"""Explicit bounded recordings of the existing redacted diagnostic stream."""
import io
import json
import time
import uuid
import zipfile
from datetime import datetime,timezone

from flower_control.control.state import ControlError


def finite_recording_checker(guard):
    """Derive a bounded read stamp from the actual consumed worker permit.

    The original action may finish normally. Its token is never reused as a
    long-lived permit and no grant is issued or refreshed by this checker.
    """
    from flower_control.control.worker_call import WorkerCallGuard
    from flower_control.control.native import process_is_alive
    from .desktop_ordinary_authority import _snapshot
    if not isinstance(guard,WorkerCallGuard):raise ControlError('diagnostic_worker_authority_required')
    guard.store.check_worker_permit(guard.action,guard.token,guard.fingerprint)
    store=guard.store
    with store.read_transaction() as db:
        row=db.execute('SELECT task,owner,resources,scope FROM actions WHERE id=?',(guard.action,)).fetchone()
        task,owner,resources,scope=row['task'],row['owner'],json.loads(row['resources']),row['scope']
    def snapshot():
        state,_=_snapshot(store,task,'capture',stable_usage=True)
        with store.read_transaction() as db:
            original=db.execute('SELECT cancel_requested FROM actions WHERE id=? AND task=?',(guard.action,task)).fetchone()
            owner_row=db.execute('SELECT process,retired,live_until FROM owners WHERE id=? AND task=?',(owner,task)).fetchone()
            if (original is None or original['cancel_requested'] or owner_row is None or owner_row['retired']
                    or owner_row['live_until']<=store.clock() or not process_is_alive(owner_row['process'])):
                raise ControlError('diagnostic_authority_changed')
            store._require_scope(db,task,scope)
            resource_state=[]
            for resource in resources:
                store._require_owned_resource(db,task,resource)
                row=db.execute('SELECT paused,quarantined,required_scope FROM resources WHERE id=?',(resource,)).fetchone()
                if row is None or row['paused'] or store._effective_quarantine(db,resource,row):raise ControlError('diagnostic_authority_changed')
                store._require_scope(db,task,row['required_scope']);resource_state.append(tuple(row))
        return state,tuple(resource_state),owner_row['process']
    stamp=snapshot()
    def check():
        if snapshot()!=stamp:raise ControlError('diagnostic_authority_changed')
        return True
    return check


class DiagnosticRecordings:
    def __init__(self,*,clock=time.monotonic):
        self.clock=clock;self.active={};self.ended={}

    def _stop(self,run,reason):
        self.active.pop(run['kind'],None)
        self.ended[run['kind']]=dict(run_id=run['run_id'],reason=reason)

    def start(self,kind,policy,*,check=lambda:True):
        if kind not in {'trace','network','events'}:raise ControlError('invalid_diagnostic_kind')
        if kind in self.active:raise ControlError('diagnostic_already_running')
        check()
        self.ended.pop(kind,None)
        run=dict(run_id=uuid.uuid4().hex,kind=kind,policy=policy,check=check,started=self.clock(),
            started_utc=datetime.now(timezone.utc).isoformat(),entries=[],bytes=0,truncated=False)
        self.active[kind]=run
        return dict(run_id=run['run_id'],kind=kind,scope='session_admitted_pages',
            format='redacted_metadata',max_entries=10000,max_seconds=900,
            raw_playwright_trace=False,content_captured=False)

    def event(self,page_id,event):
        # Copy only deterministic fields already redacted by PageDriver. Never
        # serialize unknown page-derived fields, headers, body, text or URL paths.
        kind=event.get('kind')
        if kind not in {'console','pageerror','requestfailed','response'}:return
        row=dict(page_id=page_id,kind=kind)
        for name in ('seq','status','http_error','generation','navigation_version'):
            value=event.get(name)
            if type(value) in (int,bool):row[name]=value
        for name,allowed in dict(method={'GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','CONNECT','TRACE','OTHER'},
                level={'error','warning','log','info','debug'},resource_type={'document','stylesheet','image','media','font','script',
                    'texttrack','xhr','fetch','eventsource','websocket','manifest','other'}).items():
            if event.get(name) in allowed:row[name]=event[name]
        if type(event.get('source_origin')) is str:
            from .web_discovery import source_origin
            row['source_origin']=source_origin(event['source_origin'])
        for run in list(self.active.values()):
            try:run['check']()
            except Exception:self._stop(run,'authority_changed');continue
            if run['kind']=='network' and kind not in {'response','requestfailed'}:continue
            if run['kind']=='events' and kind not in {'console','pageerror'}:continue
            item={**row,'offset_ms':round((self.clock()-run['started'])*1000,3)}
            encoded=len(json.dumps(item,ensure_ascii=True,separators=(',',':')).encode())+1
            if self.clock()-run['started']>=900 or len(run['entries'])>=10000 or run['bytes']+encoded>2_000_000:
                run['truncated']=True;continue
            run['entries'].append(item)
            run['bytes']+=encoded

    def get(self,kind,identifier,policy):
        run=self.active.get(kind)
        if run is None:
            ended=self.ended.get(kind)
            if ended is not None and ended['run_id']==identifier:
                raise ControlError('diagnostic_authority_changed')
            raise ControlError('diagnostic_run_not_found')
        if run['run_id']!=identifier:raise ControlError('diagnostic_run_not_found')
        try:run['check']()
        except Exception:
            self._stop(run,'authority_changed_discarded');raise ControlError('diagnostic_authority_changed_discarded') from None
        if run['policy']!=policy:
            self._stop(run,'policy_changed_discarded');raise ControlError('diagnostic_policy_changed_discarded')
        return run

    def payload(self,run):
        manifest=dict(format='flower-redacted-diagnostic-v1',kind=run['kind'],run_id=run['run_id'],
            scope='session_admitted_pages',started_utc=run['started_utc'],entries=run['entries'],
            truncated=run['truncated'],raw_playwright_trace=False,content_captured=False,
            coverage='responses_and_failures' if run['kind']=='network' else 'redacted_events',
            business_result_verified=False)
        if run['kind']=='network':
            entries=[]
            for row in run['entries']:
                entries.append(dict(startedDateTime=run['started_utc'],time=0,
                    request=dict(method=row.get('method','GET'),url=row.get('source_origin',''),httpVersion='',
                        headers=[],cookies=[],queryString=[],headersSize=-1,bodySize=-1),
                    response=dict(status=row.get('status',0),statusText='',httpVersion='',headers=[],cookies=[],
                        content=dict(size=0,mimeType=''),redirectURL='',headersSize=-1,bodySize=-1),
                    cache={},timings=dict(send=-1,wait=-1,receive=-1),
                    _flower=dict(page_id=row['page_id'],offset_ms=row['offset_ms'],kind=row['kind'])))
            return json.dumps(dict(log=dict(version='1.2',creator=dict(name='flower-control',version='1'),
                entries=entries,_flower=manifest)),ensure_ascii=True).encode(),'.har'
        data=json.dumps(manifest,ensure_ascii=True).encode()
        if run['kind']=='events':return data,'.json'
        output=io.BytesIO()
        with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as archive:archive.writestr('manifest.json',data)
        return output.getvalue(),'.zip'
