(function () {
  'use strict';
  const el = id => document.getElementById(id);
  const activeStates = ['confirmed','registering','creating_operation','running','stop_requested','recovery_required'];
  const labels = {ready:'Sẵn sàng để xác nhận',blocked:'Chưa đủ điều kiện thực thi',confirmed:'Đã xác nhận, đang kiểm tra lại',
    registering:'Đang đăng ký artifact riêng',creating_operation:'Đang tạo operation',running:'Đang thực thi',
    completed:'Các lệnh đã hoàn tất',failed:'Lượt thực thi có lỗi',stop_requested:'Đã yêu cầu dừng',
    stopped:'Đã dừng gửi lệnh mới',recovery_required:'Cần đối soát và phục hồi'};
  let selected = null, value = null, timer = null, busy = false, generation = 0, failures = 0;
  let expiredByServer = false;
  const node = (tag,text) => { const n=document.createElement(tag); if(text!==undefined)n.textContent=text; return n; };
  async function api(path,body) {
    const options = {};
    if (body !== undefined) {
      const meta=await (await fetch('/api/meta')).json();
      Object.assign(options,{method:'POST',headers:{'Content-Type':'application/json','X-Survey-Token':meta.token},body:JSON.stringify(body)});
    }
    const response=await fetch(path,options), result=await response.json();
    if(!response.ok)throw Error(result.error || 'Không đọc được trạng thái thực thi.');
    return result;
  }
  function previewExpiresAt() {
    const seconds = value?.preflight?.policy?.preview_ttl_seconds;
    return Number.isFinite(seconds) ? Date.parse(value.created_at) + seconds * 1000 : NaN;
  }
  function controls() {
    const expired = value?.state === 'ready' && (expiredByServer || Date.now() >= previewExpiresAt());
    const ready = value?.state === 'ready' && !expired;
    el('execution-confirm').disabled=busy || !ready || !el('execution-ack').checked || el('execution-target-confirm').value.trim()!==value.target.ip;
    el('execution-stop').hidden=!value || !activeStates.includes(value.state);
    el('execution-stop').disabled=busy || !!value?.stop_requested_at;
    el('execution-reconcile').hidden=!value || !['recovery_required','stop_requested'].includes(value.state);
    el('execution-reconcile').disabled=busy;
    el('execution-confirmation').hidden=!ready;
    el('execution-refresh-preview').hidden=!expired;
    el('execution-refresh-preview').disabled=busy;
    if (expired) {
      el('execution-status').textContent='Bản xem trước đã hết hạn';
      el('execution-message').textContent='Kiểm tra lại điều kiện để tạo bản xem trước mới.';
    }
  }
  function render(record) {
    expiredByServer=false;
    value=record;el('scenario-execution').hidden=false;
    el('execution-status').textContent=labels[record.state] || record.state;
    el('execution-identity').textContent='Mục tiêu: '+record.target.host+' · '+record.target.ip+' · paw '+(record.target.paw || 'chưa xác định')+' · execution '+record.id;
    el('execution-operation').textContent=record.operation_id ? 'Operation: '+record.operation_id : 'Chưa tạo operation';
    el('execution-caldera-link').hidden=!record.operation_url;
    if(record.operation_url && /^https?:\/\//.test(record.operation_url))el('execution-caldera-link').href=record.operation_url;
    const check=record.preflight;
    el('execution-context').textContent='Phạm vi: '+(check?.scope || []).join(', ')+' · Survey: '+(check?.survey?.survey_run_id || 'chưa có')+' · Khảo sát lúc: '+(check?.survey?.finished_at || 'chưa xác minh')+' · Plan SHA-256: '+record.plan_sha256;
    el('execution-blockers').textContent=[...(check?.blockers || []),record.error,...(check?.warnings || [])].filter(Boolean).join('\n');
    el('execution-detection').textContent='Lệnh: '+record.command_status+' · Bằng chứng hành vi: '+record.behavior_evidence+' · Detection: '+record.detection;
    el('execution-step-list').replaceChildren();
    for(const step of record.steps || []) {
      const item=node('li',step.index+'. '+step.name+' — '+step.state+(step.exit_code!==undefined?' · exit '+step.exit_code:''));
      const preview=check?.steps?.find(s=>s.index===step.index);
      const validation=record.validation?.steps?.find(s=>s.index===step.index);
      if(validation)item.append(node('p', 'Validate: '+({ready:'Sẵn sàng',needs_information:'Cần bổ sung',unsupported:'Không hỗ trợ'}[validation.status] || validation.status)),node('p',validation.next_action));
      const detail=node('details');detail.append(node('summary','Nguồn lệnh, tác động và điều kiện'));
      if(preview) {
        if (preview.runner_evidence) {
          const runner = preview.runner_evidence;
          detail.append(node('p', 'CALDERA xác nhận executor ' + runner.executor + ' trên ' + runner.paw
            + ' · Quyền quan sát: ' + (runner.observed_privilege || 'chưa xác minh')
            + ' · Quyền trong catalog: ' + (preview.catalog_privilege || 'chưa khai báo')
            + ' · Quyền theo preflight: ' + (preview.required_privilege || 'chưa xác định')));
        }
        detail.append(node('p',preview.source_ability_id+' · '+preview.executor.platform+'/'+preview.executor.name+' · catalog/CALDERA: '+preview.registration),
          node('p',preview.impacts),node('p','Đăng ký bản riêng, không ghi đè ability dùng chung. Cleanup: '+JSON.stringify(preview.cleanup)),
          node('pre',preview.command),node('p','Tham số: '+JSON.stringify(preview.parameters)),node('p',(preview.blockers || []).join('\n')));
      }
      if(step.stdout || step.stderr)detail.append(node('pre',(step.stdout || '')+'\n'+(step.stderr || '')));
      item.append(detail);el('execution-step-list').append(item);
    }
    el('execution-artifacts').replaceChildren();
    for(const name of (record.files || ['execution_request.json','execution_preflight.json','execution_result.json'])) {
      if((name==='execution_manifest.json' && !record.mapping) || (name==='operation-summary.json' && !record.operation_id))continue;
      const a=node('a',name);a.href='/api/executions/'+record.id+'/files/'+name;a.download=name;
      el('execution-artifacts').append(a,document.createTextNode(' · '));
    }
    const reportLink=node('a','Mở báo cáo trực tiếp');reportLink.href='/report.html?execution='+record.id;reportLink.target='_blank';reportLink.rel='noopener';el('execution-artifacts').append(reportLink);
    controls();
    loadTelemetry(record.id);
  }
  function schedule() {
    clearTimeout(timer);
    if(value && activeStates.includes(value.state) && value.state!=='recovery_required')timer=setTimeout(poll,2000);
    if (value?.state === 'ready') {
      const remaining = previewExpiresAt() - Date.now();
      if (remaining > 0) timer = setTimeout(controls, remaining);
    }
  }
  async function poll() {
    if(!value)return;
    const id=value.id, version=generation;
    try {
      const record=await api('/api/executions/'+id);
      if(version!==generation)return;
      failures=0;render(record);schedule();
    } catch(error) {
      if(version!==generation)return;
      el('execution-message').textContent=error.message;
      if(++failures<5)timer=setTimeout(poll,Math.min(15000,failures*3000));
    }
  }
  async function open(id, startOnClick = false) {
    if(busy)return;
    const version=++generation;clearTimeout(timer);busy=true;value=null;controls();
    el('execution-step-list').replaceChildren();el('execution-blockers').textContent='';el('execution-operation').textContent='';el('execution-identity').textContent='';
    el('scenario-execution').hidden=false;el('execution-status').textContent='Đang kiểm tra điều kiện, chưa gửi lệnh';
    el('execution-message').textContent='';el('execution-ack').checked=false;el('execution-target-confirm').value='';
    try {
      const record=await api('/api/scenarios/'+id+'/execute',startOnClick ? {start_on_click:true} : {});
      if(version!==generation)return;
      selected=id;render(record);schedule();
    } catch(error){if(version===generation)el('execution-message').textContent=error.message;}
    finally{busy=false;controls();}
  }
  async function action(name) {
    if(!value || busy)return;
    controls();
    if(name==='confirm' && el('execution-confirm').disabled)return;
    busy=true;controls();const version=generation;
    let reportTab=null;
    try { if(name==='confirm' && typeof window.open==='function')reportTab=window.open('about:blank','_blank'); } catch(_) { /* The persistent report link remains available. */ }
    if(reportTab){reportTab.opener=null;reportTab.document.title='Preparing execution report';}
    try {
      const body=name==='confirm'?{confirmed:true,target_ip:el('execution-target-confirm').value.trim(),plan_sha256:value.plan_sha256}:{};
      const record=await api('/api/executions/'+value.id+'/'+name,body);
      if(reportTab)reportTab.location.replace('/report.html?execution='+record.id);
      if(version!==generation)return;
      render(record);schedule();
    } catch(error){
      if(reportTab)reportTab.close();
      if(version===generation) {
        if (name === 'confirm' && error.message.startsWith('Preview hết hạn')) expiredByServer = true;
        el('execution-message').textContent=error.message;
      }
    }
    finally{busy=false;controls();}
  }
  async function select(job) {
    if(selected===job.id)return;
    selected=job.id;value=null;++generation;clearTimeout(timer);el('scenario-execution').hidden=true;
    if(job.execution_id){
      const version=generation;
      try{const record=await api('/api/executions/'+job.execution_id);if(version===generation){render(record);schedule();}}
      catch(error){el('execution-message').textContent=error.message;}
    }
  }
  let telemetryLoading=false, telemetryVersion=0, telemetryTimer=null;
  async function loadTelemetry(id) {
    const version=++telemetryVersion;
    try {
      const report=await api('/api/executions/'+id+'/telemetry');
      if(!value || value.id!==id || version!==telemetryVersion)return;
      const c=report.collection || {}, counts=report.counts || {};
      el('telemetry-summary').textContent='Thu thập: '+c.status+' · Hành vi: '+report.behavior_status+' · Telemetry: '+report.telemetry_status+' · Detection: '+report.detection_status;
      el('telemetry-coverage').textContent='Chế độ: '+(c.mode || 'unknown')+' · Events: '+(counts.events || 0)+' · Tương quan: '+(counts.correlated || 0)+' · '+(c.error ? c.error.code+' — kiểm tra cấu hình/quyền đọc; không cần chạy lại operation.' : (c.ingest_pending ? 'Đang chờ ingest; có thể làm mới sau '+c.window?.ingest_deadline : ''))+' '+(c.last_connector_validation?' API/indexer kiểm tra gần nhất: '+c.last_connector_validation.api_status+'/'+c.last_connector_validation.indexer_status+'. ':'')+(report.limitations || []).join(' ');
      const comp=report.expected_reality, c2=report.counts_v2;
      if(c2)el('telemetry-coverage').textContent='Chế độ: '+(c.mode || 'unknown')+' · Raw events: '+(c2.raw_event_count ?? 'unavailable')+' · Alert ứng viên: '+(c2.candidate_alert_documents ?? 'unavailable')+' · Alert tương quan: '+(c2.correlated_alert_documents ?? 'unavailable')+' · '+c2.count_quality+' · '+(report.limitations || []).join(' ');
      if(el('telemetry-metrics') && comp) {
        const rate=r=>r.denominator ? r.numerator+'/'+r.denominator+' ('+r.percent.toFixed(1)+'%)' : 'N/A (0/0)';
        el('telemetry-metrics').textContent='Lệnh hoàn tất: '+rate(comp.execution_completion)+' · Telemetry: '+rate(comp.telemetry_coverage)+' · Chưa đánh giá: '+comp.telemetry_coverage.not_evaluated+' · Alert theo execution: '+rate(comp.alert_coverage)+' · Không phải detection efficacy.';
        const table=node('table'), header=node('tr');
        for(const title of ['Bước','Lệnh','Kỳ vọng telemetry','Reality','Alert tương quan','Hành vi'])header.append(node('th',title));
        table.append(header);
        for(const row of comp.steps) {
          const tr=node('tr');
          for(const v of [row.index,row.command_status,row.expected.telemetry.criterion || 'not_defined',row.telemetry_matched?'Có bằng chứng':row.reason,row.correlated_alert_count ?? 'chưa xác minh',row.behavior_status])tr.append(node('td',String(v)));
          table.append(tr);
        }
        el('telemetry-step-comparison').replaceChildren(table);
        el('telemetry-operations').textContent=JSON.stringify({metrics:report.operations,techniques:comp.techniques,window:c.window,error:c.error,identity:c.identity_policy,expected_origin:report.expected_contract?.origin},null,2);
      }
      el('telemetry-json').href='/api/executions/'+id+'/telemetry/report.json';
      el('telemetry-markdown').href='/api/executions/'+id+'/telemetry/report.md';
      if(['queued','collecting','watching_execution','waiting_ingest'].includes(c.status)){clearTimeout(telemetryTimer);telemetryTimer=setTimeout(()=>loadTelemetry(id),5000);}
    } catch(error){if(value?.id===id)el('telemetry-summary').textContent=error.message;}
  }
  el('telemetry-refresh').onclick=async()=>{
    if(!value || telemetryLoading)return;
    const id=value.id;telemetryLoading=true;el('telemetry-refresh').disabled=true;
    try{const result=await api('/api/executions/'+id+'/telemetry/refresh',{});el('telemetry-summary').textContent=result.status==='waiting_execution_end'?'Chờ execution kết thúc; không chạy lại operation.':'Đã xếp lịch thu thập; không chạy lại operation.';clearTimeout(telemetryTimer);telemetryTimer=setTimeout(()=>loadTelemetry(id),2000);}
    catch(error){el('telemetry-summary').textContent=error.message;}
    finally{telemetryLoading=false;el('telemetry-refresh').disabled=false;}
  };
  el('execution-target-confirm').oninput=controls;el('execution-ack').onchange=controls;
  el('execution-refresh-preview').onclick=()=>{if(value?.scenario_job_id) return open(value.scenario_job_id);};
  for(const name of ['confirm','stop','reconcile'])el('execution-'+name).onclick=()=>action(name);
  api('/api/telemetry/diagnostic').then(d=>{if(d.http_status===200)el('wazuh-connectivity-status').textContent='Wazuh indexer: đã xác thực · '+d.mode+' · '+d.sample_count+' alert mẫu lúc '+d.checked_at+' · API health: '+d.api_health+' · Identity execution chưa xác minh. Đây là kiểm tra ingest, không phải báo cáo execution.';}).catch(()=>{});
  window.ScenarioExecutionUI={open,select};
})();
