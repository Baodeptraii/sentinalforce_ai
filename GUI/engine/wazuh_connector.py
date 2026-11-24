"""Read-only Wazuh API/indexer transport. No shell, LLM or CALDERA dependency."""
import base64
import json
import hashlib
import http.client
import hmac
import re
import os
import ssl
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, ProxyHandler, HTTPRedirectHandler


class ConnectorError(Exception):
    def __init__(self, code, status=None):
        self.code,self.status=code,status
        super().__init__(code)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ConnectorError('redirect_refused')


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Explicit lab-only TOFU trust. Verify exact peer DER hash before HTTP auth is sent."""
    def __init__(self,*args,pin=None,**kwargs):
        self.pin=pin
        super().__init__(*args,**kwargs)

    def connect(self):
        super().connect()
        actual=hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest()
        if not self.pin or not hmac.compare_digest(actual,self.pin):
            self.close()
            raise ConnectorError('tls_certificate_pin_mismatch')


class PinnedHTTPSHandler(HTTPSHandler):
    def __init__(self,context,pins):
        super().__init__(context=context);self.pins=pins

    def https_open(self,req):
        pin=self.pins.get(req.host)
        return self.do_open(lambda host,**kw:PinnedHTTPSConnection(host,pin=pin,**kw),req,context=self._context,check_hostname=False)


class Connector:
    def __init__(self, config):
        self.config=config
        if not config.get('enabled'):raise ConnectorError('connector_disabled')
        for key in ('api_url','indexer_url'):
            u=urlsplit(config.get(key,''))
            if u.scheme!='https' or u.hostname not in config.get('allowed_hosts',[]) or u.username or u.password or u.path not in ('','/') or u.query or u.fragment:
                raise ConnectorError('endpoint_refused')
        secret=Path(config['credentials_file'])
        if secret.is_symlink() or not secret.is_file() or secret.stat().st_mode & 0o077 or secret.stat().st_uid!=os.getuid():
            raise ConnectorError('private_credentials_required')
        if Path(__file__).resolve().parents[1] in secret.resolve().parents:
            raise ConnectorError('credentials_must_be_outside_repo')
        try:
            self.credentials=json.loads(secret.read_text())
            if config.get('tls_mode','verified_ca')=='lab_tofu_pinned':
                pins=config.get('certificate_sha256',{})
                if any(not re.fullmatch('[a-f0-9]{64}',str(pins.get(urlsplit(config[k]).netloc,''))) for k in ('api_url','indexer_url')):
                    raise ConnectorError('explicit_certificate_pins_required')
                context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
                handler=PinnedHTTPSHandler(context,pins)
            else:
                context=ssl.create_default_context(cafile=config['ca_file'])
                handler=HTTPSHandler(context=context)
        except (OSError,ValueError,ssl.SSLError):raise ConnectorError('trusted_ca_or_credentials_unavailable') from None
        self.opener=build_opener(ProxyHandler({}),handler,NoRedirect())
        self.deadline=time.monotonic()+min(120,max(1,config.get('max_collection_seconds',45)))
        self.token=None
        self.query_count=0

    def request(self, service, path, body=None, raw=False):
        # Explicit allowlist: authenticate/read health, index metadata and search only.
        allowed = (service=='api' and path in ('/security/user/authenticate?raw=true','/agents?limit=500&select=id,name,ip,status,lastKeepAlive')) or (service=='indexer' and (
            path in ('/','/_cat/indices/wazuh-archives-*?format=json&h=index','/_search/scroll') or
            path in ('/wazuh-alerts-*/_search?scroll=1m','/wazuh-archives-*/_search?scroll=1m')))
        if not allowed:raise ConnectorError('read_endpoint_refused')
        if time.monotonic()>self.deadline:raise ConnectorError('collection_deadline')
        self.query_count=getattr(self,'query_count',0)+1
        headers={'Accept':'application/json'}
        auth=self.credentials.get(service,{})
        if service=='api' and self.token:headers['Authorization']='Bearer '+self.token
        else:
            if not auth.get('username') or not auth.get('password'):raise ConnectorError('credentials_missing')
            headers['Authorization']='Basic '+base64.b64encode((auth['username']+':'+auth['password']).encode()).decode()
        payload=None if body is None else json.dumps(body).encode()
        if payload is not None:headers['Content-Type']='application/json'
        req=Request(self.config[service+'_url'].rstrip('/')+path,data=payload,headers=headers,method='GET' if body is None else 'POST')
        try:
            with self.opener.open(req,timeout=min(self.config.get('timeout_seconds',6),max(.1,self.deadline-time.monotonic()))) as response:
                maximum=min(8_000_000,self.config.get('max_response_bytes',2_000_000))
                chunks=[];total=0
                while True:
                    if time.monotonic()>self.deadline:raise ConnectorError('collection_deadline')
                    chunk=response.read1(min(65536,maximum-total+1))
                    if not chunk:break
                    total+=len(chunk)
                    if total>maximum:raise ConnectorError('response_too_large')
                    chunks.append(chunk)
                data=b''.join(chunks)
                return data.decode().strip() if raw else json.loads(data)
        except HTTPError as error:raise ConnectorError('http_'+str(error.code),error.code) from None
        except (ssl.SSLError,URLError,TimeoutError,OSError):raise ConnectorError('transport_or_tls_failure') from None
        except (UnicodeError,ValueError):raise ConnectorError('invalid_response') from None

    def identity(self, target):
        if not self.credentials.get('api'):raise ConnectorError('identity_unverified_api_credentials_missing')
        self.token=self.request('api','/security/user/authenticate?raw=true',raw=True)
        response=self.request('api','/agents?limit=500&select=id,name,ip,status,lastKeepAlive')
        rows=response.get('data',{}).get('affected_items',[])
        if response.get('data',{}).get('total_affected_items',len(rows))>len(rows):raise ConnectorError('agent_directory_truncated')
        matches=[r for r in rows if r.get('ip')==target.get('ip')]
        if len(matches)!=1:raise ConnectorError('agent_identity_ambiguous_or_missing')
        return {k:matches[0].get(k) for k in ('id','name','ip','status','lastKeepAlive')}

    def collect(self, identity, window):
        from .wazuh_diagnostic import product
        version=product(self.request('indexer','/'))
        archive_status='unknown';indices=['wazuh-alerts-*']
        try:
            archives=self.request('indexer','/_cat/indices/wazuh-archives-*?format=json&h=index')
            if archives:indices.append('wazuh-archives-*');archive_status='available'
            else:archive_status='absent'
        except ConnectorError as error:
            if error.status==404:archive_status='absent'
            elif error.status in (401,403):archive_status='permission_denied'
            else:raise
        size=min(500,max(1,self.config.get('page_size',200)))
        max_events=min(5000,max(1,self.config.get('max_events',1000)))
        events=[];seen=set();pages=0;truncated=False
        query={'size':size,'sort':['_doc'],'query':{'bool':{'filter':[
            *([{'term':{'agent.id':identity['id']}}] if identity.get('id') else []),{'term':{'agent.ip':identity['ip']}},
            {'range':{'timestamp':{'gte':window['start'],'lte':window['end']}}}]}},
            '_source':['timestamp','@timestamp','agent','rule.id','rule.level','rule.description','data.soc',
                       'data.win.system.eventID','data.win.system.channel','data.win.system.systemTime','data.win.system.eventRecordID','data.win.system.computer',
                       'data.win.eventdata.processId','data.win.eventdata.newProcessId','data.win.eventdata.parentProcessId','data.win.eventdata.processGuid',
                       'data.win.eventdata.parentProcessGuid','data.soc_web','location','decoder.name']}
        for index in indices:
            if pages>=min(20,self.config.get('max_pages',5)):
                truncated=True;break
            result=self.request('indexer','/'+index+'/_search?scroll=1m',query)
            while True:
                pages+=1
                hits=result.get('hits',{}).get('hits',[])
                for hit in hits:
                    key=(hit.get('_index'),hit.get('_id'))
                    if key not in seen:
                        seen.add(key);events.append(hit)
                    if len(events)>=max_events:truncated=True;break
                if truncated or not hits:break
                if pages>=min(20,self.config.get('max_pages',5)):
                    truncated=True;break
                cursor=result.get('_scroll_id')
                if not cursor:raise ConnectorError('missing_scroll_cursor')
                result=self.request('indexer','/_search/scroll',{'scroll':'1m','scroll_id':cursor})
            if truncated:break
        return {'hits':events,'pages':pages,'truncated':truncated,'archive_status':archive_status,
                'mode':'alerts_and_archives' if archive_status=='available' else 'alerts_only',
                'indexer_version':version.get('number'), 'cursor_policy':'bounded_snapshot_scroll_1m; restart_requery_window_dedup'}
