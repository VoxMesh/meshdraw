"""Selected validation/window routines from the corrected archive client.

No new arithmetic. API completeness means the fixed bounded query only.
"""
import re
from . import math as mathcore
from . import normalization as norm

class Invalid(ValueError):
    pass

def fail(code):
    raise Invalid(code)

def exact_fields(obj,keys,code):
    if type(obj) is not dict or set(obj)!=set(keys):fail(code)

def integer(v,lo,hi):
    if type(v) is not int or not lo<=v<=hi:fail('INTEGER_BOUND')

NUM=re.compile(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]{1,2})?\Z')
INT=re.compile(r'-?(?:0|[1-9][0-9]*)\Z')

def typed(v):
    exact_fields(v,{'kind','value'},'TYPED_FIELDS');kind=v['kind'];value=v['value']
    if kind=='null':
        if value is not None:fail('TYPED_NULL')
    elif kind=='boolean':
        if type(value) is not bool:fail('TYPED_BOOLEAN')
    elif kind in ('integer','number','string'):
        if type(value) is not str or len(value)>512:fail('TYPED_STRING_BOUND')
        if kind=='integer' and (len(value)>32 or not INT.fullmatch(value)):fail('TYPED_INTEGER')
        if kind=='number' and (len(value)>128 or not NUM.fullmatch(value)):fail('TYPED_NUMBER')
    else:fail('TYPED_KIND')
def check_rows(rows,max_rows=2048):
    if type(rows) is not list or len(rows)>max_rows:fail('RECORD_LIMIT')
    seen=set();parents={};children=[]
    for r in rows:
        exact_fields(r,{'layer','parent_key','fields','request_utc','page','ordinal'},'RECORD_FIELDS')
        if r['layer'] not in ('packet','observation') or type(r['fields']) is not dict or set(r['fields'])-norm.FIELDS:fail('RECORD_STRUCTURE')
        integer(r['page'],0,3);integer(r['ordinal'],0,4096)
        if type(r['request_utc']) is not str or len(r['request_utc'])>128:fail('DOWNLOAD_METADATA')
        for k,v in r['fields'].items():
            typed(v)
            if k in ('rssi','snr') and v['kind']!='null':
                if v['kind'] not in ('integer','number','string') or len(v['value'])>128 or not NUM.fullmatch(v['value']):fail('RF_NUMBER')
        ident=r['fields'].get('id')
        if not ident or ident['kind'] not in ('integer','string') or not ident['value'] or len(ident['value'])>128:fail('RECORD_ID')
        key=(r['layer'],ident['kind'],ident['value'])
        if key in seen:fail('DUPLICATE_LOCAL_ID')
        seen.add(key)
        if r['layer']=='packet':
            if r['parent_key'] is not None:fail('TOP_PARENT_LINK')
            parent=norm.packet_key_from_record(r)
            if not parent or parent in parents:fail('DUPLICATE_PARENT_KEY')
            parents[parent]=r
        else:
            if type(r['parent_key']) is not str or len(r['parent_key'])>1024:fail('CHILD_PARENT_LINK')
            children.append(r)
    if any(r['parent_key'] not in parents for r in children):fail('ORPHAN_OBSERVATION')
    for key,parent in parents.items():
        declared=parent['fields'].get('observation_count')
        if not declared or declared['kind']!='integer' or not INT.fullmatch(declared['value']):fail('MISSING_CHILD_COUNT')
        if int(declared['value'])!=sum(r['parent_key']==key for r in children):fail('INCOMPLETE_CHILDREN')
    return parents,children
def check_snapshot(s,max_rows=2048,page_limit=50):
    exact_fields(s,{'schema_version','complete','reported_total','rows','request_offsets'},'SNAPSHOT_FIELDS')
    if s['schema_version']!='meshdraw-source-snapshot-v1' or s['complete'] is not True:fail('INCOMPLETE_SNAPSHOT')
    integer(s['reported_total'],0,200)
    if type(s['request_offsets']) is not list or not 1<=len(s['request_offsets'])<=4:fail('PAGE_METADATA')
    for x in s['request_offsets']:integer(x,0,200)
    if len(s['request_offsets'])!=len(set(s['request_offsets'])):fail('DUPLICATE_OFFSET')
    parents,children=check_rows(s['rows'],max_rows)
    if len(parents)!=s['reported_total']:fail('INCOMPLETE_PARENT_TOTAL')
    offsets=sorted(s['request_offsets']);expected=0
    for page,offset in enumerate(offsets):
        if offset!=expected:fail('PAGE_OFFSET_GAP')
        count=sum(r['page']==page for r in parents.values())
        if page_limit==100 and count!=min(100,s['reported_total']-offset):fail('SHORT_STUDY_PAGE')
        if count>page_limit or (not count and s['reported_total']>0):fail('PAGE_PARENT_COUNT')
        expected+=count
    if expected!=s['reported_total'] or any(r['page']>=len(offsets) for r in s['rows']):fail('PAGE_RECORDS_MISSING')
    if any(r['page']!=parents[r['parent_key']]['page'] for r in children):fail('CHILD_PAGE_LINK')
    return parents,children
def window_filter(plan,snapshot):
    start=mathcore.to_utc_us(plan['source']['query']['since'],'iso8601');end=mathcore.to_utc_us(plan['source']['query']['until'],'iso8601')
    parents={};excluded_parents=0;excluded_children=0;unknown_parent_times=0;unknown_child_times=0
    for r in snapshot['rows']:
        if r['layer']!='packet':continue
        raw=r['fields'].get('first_seen',{}).get('value')
        try:stamp=mathcore.to_utc_us(raw,'iso8601')
        except Exception:unknown_parent_times+=1;excluded_parents+=1;continue
        if start<=stamp<end:parents[norm.packet_key_from_record(r)]=r
        else:excluded_parents+=1
    children=[]
    for r in snapshot['rows']:
        if r['layer']!='observation':continue
        if r['parent_key'] not in parents:excluded_children+=1;continue
        try:stamp=mathcore.to_utc_us(r['fields'].get('timestamp',{}).get('value'),'iso8601')
        except Exception:unknown_child_times+=1;excluded_children+=1;continue
        if start<=stamp<end:children.append(r)
        else:excluded_children+=1
    return children,{'policy':'archive-window-study-v1','eligible_parents':len(parents),'eligible_children':len(children),'excluded_parents':excluded_parents,'excluded_children':excluded_children,'unknown_parent_times':unknown_parent_times,'unknown_child_times':unknown_child_times,'scope':'Deletes returned out-of-window records only; never recovers server omissions'}