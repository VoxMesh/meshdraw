"""archive-input-v1: arithmetic on an explicitly supplied saved number set.

This is not a v0.2 request/replay. Physical source/receive times and retained
remain unknown. Pure v0.2 quarter/map/canonical operations are reused honestly.
"""
from collections import defaultdict
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import re
import struct

from meshdraw_core.core import canonical_bytes, quarter, to_utc_us, map_digest

PREFIX=b'MeshDraw-archive-input-v1/DEDUP_HASH\x00'
IMPLEMENTATION_VERSION='archive-profile-implementation-1.0.1'
MAX_BYTES=4*1024**2
MAX_ROWS=3000
FIELDS={'id','packet_id','transmission_id','observation_id','observer_id','observer_iata',
    'observation_count','hash','timestamp','received_at','receivedAt','source_time',
    'source_epoch_s','time','observed_at','rx_time','direction','region','iata',
    'first_seen','last_seen','created_at','updated_at','server_timestamp','rssi','snr'}

def cb(value):return canonical_bytes(value)
def digest(value):return hashlib.sha256(cb(value)).hexdigest()
def read(path):
    with Path(path).open('rb') as f:data=f.read(MAX_BYTES+1)
    if len(data)>MAX_BYTES:raise ValueError('INPUT_BYTE_LIMIT')
    def pairs(items):
        out={}
        for k,v in items:
            if k in out:raise ValueError('DUPLICATE_JSON_KEY')
            out[k]=v
        return out
    return json.loads(data,object_pairs_hook=pairs,
        parse_float=lambda _:(_ for _ in ()).throw(ValueError('UNEXPECTED_JSON_FLOAT')),
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('NONFINITE_JSON')))
def write_new(path,value):
    data=json.dumps(value,ensure_ascii=False,indent=2,sort_keys=True).encode('utf-8')
    with Path(path).open('xb') as f:f.write(data)
def safe_path(root,name):
    if type(name) is not str or not name or Path(name).is_absolute() or '..' in Path(name).parts:raise ValueError('UNSAFE_PATH')
    p=(Path(root)/name).resolve()
    if not p.is_relative_to(Path(root).resolve()):raise ValueError('PATH_ESCAPE')
    return p
def token(value):
    if type(value) is not dict or set(value)!={'kind','value'}:raise ValueError('TYPED_VALUE_REQUIRED')
    if value['kind'] not in ('string','integer','number','boolean','null'):raise ValueError('UNKNOWN_VALUE_KIND')
    v=value['value']
    if value['kind']=='null':
        if v is not None:raise ValueError('BAD_NULL')
    elif value['kind']=='boolean':
        if type(v) is not bool:raise ValueError('BAD_BOOLEAN')
    elif type(v) is not str or len(v)>512:raise ValueError('TECHNICAL_VALUE_LIMIT')
    return (value['kind'],str(v))
def value(row,key):return row['fields'].get(key,{}).get('value')
def stable_id(row):return token(row['fields']['id'])
def exact(text):
    if type(text) is not str or len(text)>128 or re.fullmatch(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]{1,2})?',text) is None:raise ValueError('BAD_RF_NUMBER')
    return Fraction(text)
def plain(number):
    n,d=number.numerator,number.denominator;scale=0
    if d==1:return str(n)
    while scale<=128:
        if (10**scale)%d==0:break
        scale+=1
    else:raise ValueError('NON_DECIMAL_FRACTION')
    if scale>128:raise ValueError('DECIMAL_SCALE_LIMIT')
    scaled=abs(n)*(10**scale)//d
    digits=str(scaled).rjust(scale+1,'0')
    text=('-' if n<0 else '')+digits[:-scale]+'.'+digits[-scale:]
    return text.rstrip('0').rstrip('.')

def validate_policy(policy):
    # Explicit immutable supported policy. No caller-supplied alternative code.
    if policy.get('profile')!='archive-input-v1' or policy.get('candidate')!='DEDUP_HASH':raise ValueError('UNSUPPORTED_PROFILE')
    fixed={'grouping':'typed-observer-id-and-parent-transmission-key',
        'representative':'earliest-archive-us-then-typed-observation-id',
        'pair_order':'archive-us-observer-parent-observation-id',
        'quantization':'quarter-half-even','rf_prefix_hex':PREFIX.hex(),
        'direction':'rx','region':'all','retained':'unknown-not-provided',
        'physical_source_time':'unknown','physical_receive_time':'unknown',
        'mapping':'v0.2-map_digest-rejection-sampling','mapping_max_words':8,
        'min_rows':8,'min_observers':2,'rf_abs_limit':'1000000'}
    for k,v in fixed.items():
        if policy.get(k)!=v:raise ValueError('UNSUPPORTED_POLICY_'+k)
    to_utc_us(policy['start'],'iso8601');to_utc_us(policy['end'],'iso8601')
    if to_utc_us(policy['start'],'iso8601')>=to_utc_us(policy['end'],'iso8601'):raise ValueError('BAD_WINDOW')
    # Pure mapper validates fixed-string tickets, uniqueness and bounds itself.
    map_digest(bytes(32),policy['tickets'],8)

def evaluate(policy,inp):
    validate_policy(policy)
    if inp.get('schema_version')!='meshdraw-archive-input-v1' or type(inp.get('rows')) is not list or len(inp['rows'])>MAX_ROWS:raise ValueError('ARCHIVE_INPUT_SHAPE')
    if inp.get('source_snapshot_sha256')!=policy['source_snapshot_sha256']:raise ValueError('DECLARED_SOURCE_HASH_MISMATCH')
    rows=inp['rows'];seen={}
    for row in rows:
        if type(row) is not dict or set(row)-{'layer','parent_key','fields','request_utc','page','ordinal'}:raise ValueError('ROW_STRUCTURE')
        if row.get('layer')!='observation' or type(row.get('parent_key')) is not str or not 1<=len(row['parent_key'])<=1024 or type(row.get('fields')) is not dict:raise ValueError('OBSERVATION_STRUCTURE')
        if set(row['fields'])-FIELDS:raise ValueError('UNSAFE_FIELD')
        for field in row['fields'].values():token(field)
        if 'id' not in row['fields'] or row['fields']['id']['kind'] not in ('string','integer'):raise ValueError('MISSING_OBSERVATION_ID')
        ident=stable_id(row)
        if ident in seen:
            if cb(seen[ident]['fields'])!=cb(row['fields']):raise ValueError('OBSERVATION_ID_CHANGED_VALUES')
            raise ValueError('DUPLICATE_OBSERVATION_ID')
        seen[ident]=row
        if any(type(row.get(k)) is not int or row[k]<0 for k in ('page','ordinal')):raise ValueError('LOCAL_INDEX_TYPE')
        if type(row.get('request_utc')) is not str:raise ValueError('DOWNLOAD_TIME_TYPE')
    accepted=[];excluded=[]
    start=to_utc_us(policy['start'],'iso8601');end=to_utc_us(policy['end'],'iso8601')
    for row in sorted(rows,key=stable_id):
        reasons=[];stamp=None
        try:stamp=to_utc_us(value(row,'timestamp'),'iso8601')
        except Exception:reasons.append('UNKNOWN_OR_UNSUPPORTED_ARCHIVE_TIME')
        if stamp is not None and not start<=stamp<end:reasons.append('OUTSIDE_ARCHIVE_WINDOW')
        if value(row,'direction')!=policy['direction']:reasons.append('DIRECTION_NOT_RX')
        observer=row['fields'].get('observer_id')
        if observer is None or observer['kind'] not in ('string','integer') or value(row,'observer_id') in ('',None):reasons.append('MISSING_OBSERVER_ID')
        if any(value(row,m) is None for m in ('rssi','snr')):reasons.append('MISSING_RF')
        if reasons:
            excluded.append({'id':list(stable_id(row)),'reasons':reasons});continue
        rf=[exact(value(row,m)) for m in ('rssi','snr')]
        if any(abs(v)>exact(policy['rf_abs_limit']) for v in rf):
            excluded.append({'id':list(stable_id(row)),'reasons':['RF_OUT_OF_PROFILE_RANGE']});continue
        strings=[plain(v) for v in rf]
        if any(len(s)>32 for s in strings):raise ValueError('RF_QUARTER_LEXICAL_LIMIT')
        accepted.append({'row':row,'stamp':stamp,'observer':token(observer),'parent':row['parent_key'],
            'id':stable_id(row),'rf':rf,'plain':strings})
    groups=defaultdict(list)
    for row in accepted:groups[(row['observer'],row['parent'])].append(row)
    selected=[min(rs,key=lambda r:(r['stamp'],r['id'])) for rs in groups.values()]
    selected.sort(key=lambda r:(r['stamp'],r['observer'],r['parent'],r['id']))
    ambiguities=defaultdict(set)
    for r in accepted:ambiguities[(r['observer'],r['parent'],r['stamp'])].add(tuple(r['rf']))
    result={'profile':'archive-input-v1','status':'ARCHIVE_NO_DRAW','reason':None,
        'plan_sha256':digest(policy),'input_document_sha256':digest(inp),
        'frozen_input_hash_match':None if policy.get('input_document_sha256_before_calculation') is None else digest(inp)==policy['input_document_sha256_before_calculation'],
        'source_snapshot_sha256_declared':policy['source_snapshot_sha256'],
        'counts':{'input_rows':len(rows),'accepted_rows':len(accepted),'selected_rows':len(selected),
            'accepted_observers':len({r['observer'] for r in accepted}),
            'selected_observers':len({r['observer'] for r in selected})},
        'excluded':excluded,'selected_ids':[list(r['id']) for r in selected],
        'ambiguity_group_count':sum(len(values)>1 for values in ambiguities.values()),
        'rf':None,'mapping':None,
        'meaning':'Math on supplied saved archive numbers; not core-v0.2 replay, source authentication, completeness, finality or entropy proof'}
    if len(selected)<policy['min_rows'] or result['counts']['selected_observers']<policy['min_observers']:
        result['reason']='INSUFFICIENT_SELECTED_ROWS_OR_OBSERVERS';return result
    pairs=[[quarter(text) for text in r['plain']] for r in selected]
    body=PREFIX+struct.pack('>I',len(pairs))+b''.join(struct.pack('>ii',*pair) for pair in pairs)
    root=hashlib.sha256(body).digest();mapping=map_digest(root,policy['tickets'],8)
    result.update(status='ARCHIVE_DRAW' if mapping['index'] is not None else 'ARCHIVE_NO_DRAW',
        reason=None if mapping['index'] is not None else 'MAPPING_EXHAUSTED',
        rf={'pairs':pairs,'bytes_hex':body.hex(),'sha256':root.hex()},mapping=mapping)
    return result
