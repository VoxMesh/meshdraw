"""Pure normalisation for archive records."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from fractions import Fraction
import hashlib,json,re

FIELDS = {'id','packet_id','transmission_id','observation_id','observer_id','observer_iata','observation_count','hash','timestamp',
          'received_at','receivedAt','source_time','source_epoch_s','time',
          'observed_at','rx_time','direction','region','iata','first_seen',
          'last_seen','created_at','updated_at','server_timestamp','rssi','snr'}

TIME_FIELDS = {'timestamp','received_at','receivedAt','source_time','source_epoch_s',
               'time','observed_at','rx_time','first_seen','last_seen','created_at',
               'updated_at','server_timestamp'}

ID_FIELDS = {'id','packet_id','observation_id','observer_id','hash'}

class Stop(Exception):
    pass

class Number(str):
    """A JSON fractional numeric token, preserved without float conversion."""

def canonical(value):
    return json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(',',':')).encode()

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def parse_json(data):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result: raise Stop('DUPLICATE_JSON_KEY')
            result[key]=value
        return result
    def integer(text):
        if len(text)>32: raise Stop('JSON_INTEGER_TOO_LONG')
        return int(text)
    def numeric(text):
        if len(text)>128: raise Stop('JSON_NUMBER_TOO_LONG')
        return Number(text)
    try:
        return json.loads(data,parse_int=integer,parse_float=numeric,
                          parse_constant=lambda _: (_ for _ in ()).throw(Stop('NONFINITE_JSON')),
                          object_pairs_hook=unique)
    except (ValueError,UnicodeError,RecursionError):
        raise Stop('INVALID_JSON') from None

def exact_number(value):
    if type(value) is bool or value is None: raise Stop('MISSING_OR_BAD_RF')
    if not isinstance(value,(int,str)): raise Stop('BAD_RF_TYPE')
    text=str(value)
    if len(text)>128 or re.fullmatch(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]{1,2})?',text) is None:
        raise Stop('BAD_RF_NUMBER')
    try: return Fraction(text)
    except (ValueError,ZeroDivisionError): raise Stop('BAD_RF_NUMBER') from None

def aware_us(value):
    if not isinstance(value,str) or isinstance(value,Number) or len(value)>256:
        return None
    match=re.fullmatch(r'\d{4}-\d\d-\d\d[Tt]\d\d:\d\d:\d\d(?:\.(\d+))?(Z|[+-]\d\d:\d\d)',value,re.ASCII)
    if match is None or any(c!='0' for c in (match.group(1) or '')[6:]): return None
    zone=match.group(2)
    if zone!='Z' and (int(zone[1:3])>23 or int(zone[4:6])>59):return None
    try:
        stamp=datetime.fromisoformat(value.replace('Z','+00:00'))
        delta=stamp-datetime(1970,1,1,tzinfo=timezone.utc)
        return (delta.days*86400+delta.seconds)*1000000+delta.microseconds
    except (ValueError,OverflowError): return None

def primitive(value):
    if value is None: return {'kind':'null','value':None}
    if type(value) is bool: return {'kind':'boolean','value':value}
    if type(value) is int: return {'kind':'integer','value':str(value)}
    if isinstance(value,Number): return {'kind':'number','value':str(value)}
    if type(value) is str and len(value)<=512: return {'kind':'string','value':value}
    raise Stop('UNSUPPORTED_TECHNICAL_FIELD')

def packet_key(packet):
    for field in ('id','packet_id','hash'):
        if field in packet and packet[field] is not None:
            return field+':'+json.dumps(primitive(packet[field]),sort_keys=True)
    return None

def sanitize_page(data, request_utc, page):
    if not isinstance(data,dict) or not isinstance(data.get('packets'),list):
        raise Stop('UNEXPECTED_PACKET_RESPONSE')
    if type(data.get('total')) is not int or data['total']<0:
        raise Stop('INVALID_TOTAL')
    records=[]
    for ordinal,packet in enumerate(data['packets']):
        if not isinstance(packet,dict): raise Stop('INVALID_PACKET_ROW')
        parent=packet_key(packet)
        fields={key:primitive(packet[key]) for key in FIELDS if key in packet}
        records.append({'layer':'packet','parent_key':None,'fields':fields,
                        'request_utc':request_utc,'page':page,'ordinal':ordinal})
        observations=packet.get('observations',[])
        if observations is None: observations=[]
        if not isinstance(observations,list): raise Stop('INVALID_OBSERVATIONS')
        for n,observation in enumerate(observations):
            if not isinstance(observation,dict): raise Stop('INVALID_OBSERVATION_ROW')
            clean={key:primitive(observation[key]) for key in FIELDS if key in observation}
            records.append({'layer':'observation','parent_key':parent,'fields':clean,
                            'request_utc':request_utc,'page':page,'ordinal':n})
    return records

def packet_key_from_record(record):
    for key in ('id','packet_id','hash'):
        field=record['fields'].get(key)
        if field and field['kind']!='null':return key+':'+json.dumps(field,sort_keys=True)
    return None