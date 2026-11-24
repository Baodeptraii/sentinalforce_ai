"""Explicit bounded connectivity check; historical alerts never bind an execution."""
import re
from datetime import datetime,timedelta,timezone
from .wazuh_connector import Connector,ConnectorError

def parse_dashboard_record(line):
    match=re.fullmatch(r'Wazuh\s*:\s*https://[^/]+/\s*-\s*user:\s*([^/]+?)/\s*pass: (.*)',line,re.I)
    if not match:raise ValueError('Ambiguous dashboard record')
    return {'username':match[1].strip(),'password':match[2]}

def product(response):
    version=response.get('version',{})
    if version.get('distribution')=='opensearch' or response.get('tagline')=='The OpenSearch Project: https://opensearch.org/':return version
    raise ConnectorError('unsupported_indexer_version')

def check(config):
    client=Connector(config);version=product(client.request('indexer','/'))
    end=datetime.now(timezone.utc);start=end-timedelta(minutes=60)
    window={'start':start.isoformat(),'end':end.isoformat()}
    query={'size':50,'sort':[{'timestamp':'desc'}],'query':{'bool':{'filter':[
        {'terms':{'agent.ip':['192.0.2.10','192.0.2.12']}},
        {'range':{'timestamp':{'gte':window['start'],'lte':window['end']}}}]}},
        '_source':['timestamp','agent.id','agent.name','agent.ip','rule.id','rule.level','data.win.system.channel','data.win.system.eventID']}
    result=client.request('indexer','/wazuh-alerts-*/_search?scroll=1m',query)
    samples=[]
    for h in result.get('hits',{}).get('hits',[]):
        s=h.get('_source',{});samples.append({'document_id':h['_id'],'index':h['_index'],'timestamp':s.get('timestamp'),
            'agent':s.get('agent'),'rule':s.get('rule'),'system':s.get('data',{}).get('win',{}).get('system')})
    try:archives='available' if client.request('indexer','/_cat/indices/wazuh-archives-*?format=json&h=index') else 'absent'
    except ConnectorError as e:archives='access_denied' if e.status in (401,403) else 'unknown'
    return {'schema_version':'wazuh_live_diagnostic_v1','label':'LIVE CONNECTIVITY/INGEST CHECK — NOT AN EXECUTION REPORT',
        'checked_at':end.isoformat(),'endpoint':config['indexer_url'],'http_status':200,'version':version,
        'distribution':'opensearch','tls_trust':config.get('tls_mode','verified_ca'),'api_health':'credentials_missing' if not client.credentials.get('api') else 'not_checked',
        'identity':'historical_only_unverified_for_execution','mode':'alerts_only' if archives!='available' else 'alerts_and_archives',
        'archives':archives,'window':window,'sample_count':len(samples),'sample_limit':50,'samples':samples,
        'execution_correlation':False,'agent_alive':'unknown'}
