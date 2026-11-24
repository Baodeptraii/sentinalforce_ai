'use strict';
const $ = id => document.getElementById(id);
let token = '', validated = '', active = null, profile = null, surveyRunId = null, timer, submitting = false, busy = false;
const labels = {running:'Đang khảo sát', completed:'Hoàn tất', completed_with_unknowns:'Hoàn tất · còn thông tin chưa xác minh', partial:'Kết quả một phần', failed:'Thất bại', interrupted:'Bị gián đoạn', cancelled:'Đã dừng theo yêu cầu'};
function notice(message) { $('notice').textContent=message; $('notice').hidden=!message; }
function scopeValue(){ return document.querySelector('input[name=scope]:checked').value; }
function payload(){ const scope=scopeValue(); return {target_ip:$('target-ip').value.trim(),survey_scope:scope==='both'?['endpoint','web']:[scope],web_checks:scope!=='endpoint'&&$('check-dvwa').checked?['dvwa']:[]}; }
async function api(path,data){
  const response=await fetch(path,{method:data?'POST':'GET',headers:data?{'Content-Type':'application/json','X-Survey-Token':token}:{},body:data?JSON.stringify(data):undefined});
  let result; try{result=await response.json();}catch(_){result={error:'HTTP '+response.status};}
  if(!response.ok){const error=Error(result.error||`HTTP ${response.status}`);error.status=response.status;throw error;} return result;
}
function badge(id,text,state){$(''+id).textContent=text;$(id).className='badge '+state;}
function element(tag,text,className){const el=document.createElement(tag);if(text!==undefined)el.textContent=text;if(className)el.className=className;return el;}
function syncDVWA(){ $('check-dvwa').disabled=busy||scopeValue()==='endpoint'; }
function lock(on){busy=on;document.querySelectorAll('#survey-form input').forEach(el=>el.disabled=on);$('check-button').disabled=on;$('new-survey').disabled=on;$('start-button').disabled=on||!validated;syncDVWA();}
function checks(result){
  $('checks').replaceChildren(); result.checks.forEach(check=>{const row=element('div',undefined,'check-row '+check.state);row.append(element('span',check.state==='pass'?'✓':check.state==='fail'?'×':'!','check-icon'));const body=element('div');body.append(element('strong',check.name),element('small',check.detail));row.append(body);$('checks').append(row);});
  badge('check-summary',result.ready?'Có thể khảo sát':'Thiếu điều kiện',result.ready?'good':'bad');const caldera=result.checks.find(c=>c.name==='CALDERA API');if(caldera)badge('connection',caldera.state==='pass'?'CALDERA đã kết nối':'CALDERA chưa sẵn sàng',caldera.state==='pass'?'good':'bad');
}
$('survey-form').addEventListener('input',()=>{validated='';$('start-button').disabled=true;syncDVWA();badge('check-summary','Cần kiểm tra lại','neutral');});
$('check-button').onclick=async()=>{
  if(busy||!$('survey-form').reportValidity())return;notice('');const request=payload();lock(true);$('check-button').textContent='Đang kiểm tra…';
  try{const result=await api('/api/preflight',request);checks(result);validated=result.ready?JSON.stringify(request):'';}catch(e){notice(e.message);validated='';}finally{lock(false);$('check-button').textContent='Kiểm tra điều kiện cần';}
};
function clearResult(){profile=null;surveyRunId=null;$('download-bundle').hidden=true;$('transfer-profile').disabled=true;$('result-empty').hidden=false;$('result-body').hidden=true;$('copy-json').disabled=true;$('download-profile').removeAttribute('href');$('download-profile').classList.add('disabled');$('download-profile').setAttribute('aria-disabled','true');}
$('survey-form').onsubmit=async event=>{
  event.preventDefault();if(submitting||active)return;const request=payload();if(JSON.stringify(request)!==validated)return;
  submitting=true;validated='';lock(true);notice('');clearResult();
  try{const result=await api('/api/jobs',request);active=result.id;poll();}
  catch(e){
    notice(e.message);try{const meta=await api('/api/meta');if(meta.active_job){active=meta.active_job;poll();}else lock(false);}
    catch(_){notice('Chưa xác định tác vụ đã được tạo hay chưa. Tải lại trang để đọc lịch sử; không gửi lại tự động.');}
  }finally{submitting=false;}
};
function fileURL(id,file){return '/api/jobs/'+id+'/files/'+file.split('/').map(encodeURIComponent).join('/');}
function statusOf(job){return job.report&&['partial','completed_with_unknowns','failed'].includes(job.report.status)?job.report.status:job.status;}
function stateLabel(value,key,request){
  if(value===true)return 'Có';if(value===false)return 'Không';
  const web=['web_runner_ready','web_reachable','application_identified','dvwa_session_ready','web_access_logs'].includes(key);
  if(web&&!request.survey_scope.includes('web'))return 'Ngoài phạm vi khảo sát';
  if(key==='dvwa_session_ready'&&Array.isArray(request.web_checks)&&!request.web_checks.includes('dvwa'))return 'Ngoài phạm vi khảo sát';
  return 'Chưa xác minh';
}
function summaryRows(id,values,request){
  $(id).replaceChildren();for(const [label,key,value] of values){const row=element('div',undefined,'observation-row');row.append(element('span',label),element('strong',stateLabel(value,key,request)));$(id).append(row);}
}
function render(job){
  const status=statusOf(job),report=job.report||{},running=status==='running';
  $('cancel-survey').hidden=!running;
  badge('run-status',labels[status]||status,status==='completed'?'good':running?'purple':['partial','completed_with_unknowns','interrupted'].includes(status)?'warn':'bad');
  $('run-message').textContent=job.message||labels[status];$('progress-number').textContent=running?'Đang chạy':'Đã dừng';$('progress-fill').className=running?'activity-indicator running':'activity-indicator';
  const events=job.events||[];$('survey-events').replaceChildren();
  for(const event of events.slice(-20)){const row=element('li');row.append(element('time',event.time?new Date(event.time).toLocaleTimeString('vi-VN'):'—'),element('span',event.text));$('survey-events').append(row);}
  if(!events.length)$('survey-events').append(element('li','Chưa có sự kiện được ghi nhận.'));
  const logs=job.logs||[];$('logs').textContent=logs.map(x=>new Date(x.time).toLocaleTimeString('vi-VN')+'  '+x.text).join('\n')||'Chưa có nhật ký.';$('log-count').textContent=logs.length+' sự kiện';
  if(running)return;
  clearResult();if(!job.profile&&!(job.files||[]).length)return;
  $('result-empty').hidden=true;$('result-body').hidden=false;
  const mode=report.mode||job.mode||'scripts',model=report.model||job.model||'';
  $('download-bundle').hidden=!(job.handoff||job.survey_output_v2);
  $('download-bundle').href='/api/jobs/'+job.id+'/bundle';
  $('result-caption').textContent=(job.finished_at?new Date(job.finished_at).toLocaleString('vi-VN')+' · ':'')+(labels[status]||status)+' · '+(mode==='ai'?'AI · '+model:'Scripts')+' · run '+job.id.slice(0,8);
  const failure=report.failure|| (job.error?{message:job.error}:null);
  $('result-error').hidden=!failure;
  $('result-error').textContent=failure?('Bước lỗi: '+(failure.stage||job.stage||'khảo sát')+(failure.turn?' · lượt '+failure.turn:'')+' — '+failure.message):'';
  $('result-warnings').replaceChildren();
  const warningMessages=[...new Set(job.warnings||[])],missing=job.missing_information||report.missing_information||[];
  for(const warning of warningMessages){
    const fields=missing.filter(m=>m&&typeof m==='object'&&m.reason===warning);
    if(fields.length>1){const details=element('details');details.append(element('summary',warning));for(const gap of fields)details.append(element('p',gap.field+' · '+gap.status));$('result-warnings').append(details);}
    else $('result-warnings').append(element('p',warning));
  }
  if(job.handoff){$('result-warnings').append(element('p','Hồ sơ phục vụ lập kế hoạch; cần kiểm tra lại trước thực thi. Khả năng phát hiện SOC chưa được đánh giá. Tải gói ZIP để giữ bằng chứng và thời điểm khảo sát.'));}
  $('result-warnings').className=warningMessages.length||job.handoff?'result-warnings':'';
  if(job.token_metrics){const t=job.token_metrics;$('result-warnings').append(element('p','LLM: '+t.requests+' request · actual đã biết '+(t.actual_total_tokens??'chưa có')+' token · '+t.unknown_usage_requests+' request chưa có usage · charge nội bộ '+t.charged_tokens+' token (gồm ước lượng).'));}
  if(report.failure?.budget_reason){$('result-warnings').append(element('p','LLM chờ giới hạn nội bộ: '+report.failure.budget_reason+(report.failure.retry_at_epoch?' · thử lại sau '+new Date(report.failure.retry_at_epoch*1000).toLocaleString('vi-VN'):'')));}
  if(job.metrics){const m=job.metrics;$('result-warnings').append(element('p','Điều phối: '+m.api_requests+' request model · '+m.model_seconds+' giây chờ model · '+m.rejected_calls+' lời gọi bị chặn. Token: '+(m.usage_complete?m.usage.reduce((n,u)=>n+(u.total_tokens||0),0):'chưa đủ số liệu provider')+'.'));}
  for(const failure of report.tool_errors||[])$('result-warnings').append(element('p','Lỗi tool '+failure.tool+' · '+failure.error));
  $('files').replaceChildren();(job.files||[]).forEach(file=>{const a=element('a','↓ '+file);a.href=fileURL(job.id,file);$('files').append(a);});
  $('result-meta').replaceChildren();profile=job.profile||null;$('profile-json').textContent=profile?JSON.stringify(profile,null,2):'Chưa có Target Profile. Bằng chứng đã thu thập được giữ trong các file của lượt này.';
  $('profile-summary').hidden=!profile;
  if(profile){
    surveyRunId=job.id;
    $('transfer-profile').disabled=false;
    for(const [name,value] of [['Mục tiêu',profile.address],['Máy',profile.os.hostname],['Hệ điều hành',profile.os.name],['Quyền admin',stateLabel(profile.capabilities.admin_ready,'admin_ready',job.request)]]){const box=element('div',undefined,'meta-item');box.append(element('small',name),element('strong',value??'Chưa xác minh'));$('result-meta').append(box);}
    const c=profile.capabilities,t=profile.telemetry;
    summaryRows('summary-capabilities',[['Sandcat online','sandcat_online',c.sandcat_online],['PowerShell','powershell_ready',c.powershell_ready],['Web có phản hồi','web_reachable',c.web_reachable],['Ứng dụng được nhận diện','application_identified',c.application_identified??(profile.services.some(s=>(s.applications||[]).length)?true:null)],['Phiên DVWA','dvwa_session_ready',c.dvwa_session_ready]],job.request);
    summaryRows('summary-telemetry',[['Sự kiện tiến trình','process_events',t.process_events],['Sự kiện mạng','network_events',t.network_events],['Log truy cập web','web_access_logs',t.web_access_logs],['Log tới Wazuh','wazuh_ingestion',t.wazuh_ingestion]],job.request);
    if($('telemetry-details')){
      $('telemetry-details').replaceChildren();
      const te=report.telemetry;
      if(te){
        $('telemetry-details').append(element('p','Kiểm tra: '+te.checked_at+' · cửa sổ '+te.window_hours+' giờ'));
        const names={process_events:'Tiến trình',network_events:'Mạng',web_access_logs:'Apache access',wazuh_ingestion:'Wazuh'};
        for(const [key,check] of Object.entries(te.checks||{})){
          const item=element('details');item.append(element('summary',names[key]+' · '+check.reason));
          for(const ev of check.evidence||[])item.append(element('p',(ev.source||'endpoint')+' · '+(ev.timestamp||ev.event_time||'')+(ev.channel?' · '+ev.channel:'')+(ev.event_id?' · ID '+ev.event_id:'')));
          $('telemetry-details').append(item);
        }
      }else $('telemetry-details').append(element('p','Lượt cũ chưa có collector telemetry. Chạy khảo sát mới để xác minh.'));
    }
    $('summary-services').replaceChildren();
    const extraServices=element('details');
    const extraSummary=element('summary','Các dịch vụ hệ thống và TCP — bấm để xem');extraServices.append(extraSummary);
    const extraList=element('ul');extraServices.append(extraList);
    for(const service of profile.services){
      const row=element('li',undefined,'service-group');
      row.append(element('strong',service.name+(service.state?' · '+service.state:'')));
      if(service.url)row.append(element('small',service.url));
      if(service.listeners)row.append(element('small','TCP: '+[...new Set(service.listeners.map(x=>x.LocalPort))].join(', ')));
      if(service.processes)row.append(element('small','Tiến trình listener: '+service.processes.slice(0,16).map(x=>x.name+' (PID '+x.pid+')').join(', ')+(service.processes.length>16?' … xem JSON':'')));
      for(const app of service.applications||[]){
        const text=app.name==='DVWA'?(app.session_ready===true?'DVWA được nhận diện — đã xác minh đăng nhập':'DVWA được nhận diện — chưa xác minh đăng nhập'):app.name+' được nhận diện — chưa xác minh phiên';
        const item=element('div',undefined,'web-application');item.append(element('span',text),element('small',app.base_url));if(app.name==='DVWA')item.append(element('small','Security level: '+(app.current_security_level??'Chưa xác minh')));row.append(item);
        if(app.modules_ref)item.append(element('small','Metadata module/form: '+app.modules_ref));
      }
      const important=service.url||(service.applications||[]).length||/wazuh|sysmon|sandcat|apache|mysql|maria/i.test((service.name||'')+' '+(service.service_name||''));
      (important?$('summary-services'):extraList).append(row);
    }
    if(extraList.children.length){extraSummary.textContent+=' ('+extraList.children.length+')';const wrapper=element('li');wrapper.append(extraServices);$('summary-services').append(wrapper);}
    if(!profile.services.length)$('summary-services').append(element('li','Chưa có dịch vụ được xác minh trong phạm vi khảo sát.'));
    const webSelected=job.request.survey_scope.includes('web'),https=(job.web_readiness||report.web_readiness||{}).https||{};
    $('https-readiness').textContent=webSelected?(https.status==='out_of_scope'?'HTTPS: Ngoài phạm vi khảo sát':'HTTPS: '+(https.verified===true?'Đã có bằng chứng xác minh TLS.':('Chưa xác minh · '+(https.reason||'Không có bằng chứng TLS.')))):'Web: Ngoài phạm vi khảo sát';
    $('https-readiness').className='https-readiness '+(webSelected&&https.status!=='out_of_scope'&&https.verified!==true?'unknown':'neutral');
    const inspection=job.web_inspection||{observations:[],request_count:0,observation_count:0};
    $('web-counts').textContent=inspection.request_count+' request · '+inspection.observation_count+' kết quả URL sau loại trùng. Banner Server là thông tin tự công bố.';
    $('web-requests').replaceChildren();
    for(const check of inspection.observations){
      const row=element('details',undefined,'web-request'),heading=element('summary',(check.http_status===null?'Lỗi probe':('HTTP '+check.http_status))+' · '+check.url);
      row.append(heading);
      if(check.error)row.append(element('p',check.error.kind+' · '+check.error.message,'probe-error'));
      if(check.server_banner)row.append(element('p','Banner tự công bố: '+check.server_banner));
      row.append(element('p','Nguồn: '+(check.sources||[]).map(x=>x.file+' ['+x.index+']').join(', ')));
      row.append(element('p','URL yêu cầu: '+((check.requested_urls||[]).join(', ')||'Bản ghi cũ không lưu URL ban đầu.')));
      const chains=check.redirect_chains||[];
      row.append(element('p',chains.length?'Chuyển hướng: '+chains.map(chain=>chain.length?chain.map(h=>h.http_status+' '+h.from+' → '+h.to+(h.blocked?' (đã chặn)':'')).join('; '):'Không có chuyển hướng').join(' | '):'Bản ghi cũ không lưu chuỗi chuyển hướng.'));
      $('web-requests').append(row);
    }
    $('missing-information').replaceChildren();
    for(const gap of job.missing_information||report.missing_information||[]){
      const row=element('p',typeof gap==='string'?gap:gap.field+' · '+({not_checked:'Chưa kiểm tra',check_failed:'Kiểm tra chưa xác minh được',credential_required:'Cần credential để xác minh',out_of_scope:'Ngoài phạm vi khảo sát'}[gap.status]||gap.status)+' · '+gap.reason,'missing-row');
      $('missing-information').append(row);
    }
    $('copy-json').disabled=false;const link=$('download-profile');link.href=fileURL(job.id,'target_profile.json');link.classList.remove('disabled');link.setAttribute('aria-disabled','false');
  }
}
async function poll(){
  clearTimeout(timer);if(!active)return;try{const job=await api('/api/jobs/'+active);render(job);if(job.status!=='running'){active=null;validated='';lock(false);await loadHistory();return;}timer=setTimeout(poll,1200);}
  catch(e){notice('Chưa cập nhật được tiến trình: '+e.message+'. Đang đọc lại trạng thái, không chạy lại operation.');timer=setTimeout(poll,3000);}
}
async function loadHistory(){
  const rows=await api('/api/jobs');$('history-count').textContent=rows.length;$('history-empty').hidden=!!rows.length;$('history-table').hidden=!rows.length;$('history').replaceChildren();
  for(const job of rows){const row=element('tr');for(const text of [job.request.target_ip,job.request.survey_scope.join(' + '),new Date(job.created_at).toLocaleString('vi-VN'),labels[job.status]||job.status])row.append(element('td',text));const td=element('td'),button=element('button','Mở →','text-button');button.onclick=async()=>{if(submitting||active&&active!==job.id){notice('Đợi lượt hiện tại hoàn thành để mở lịch sử.');return;}try{notice('');render(await api('/api/jobs/'+job.id));document.querySelector('.results-card').scrollIntoView({behavior:'smooth'});}catch(e){notice(e.message);}};td.append(button);row.append(td);$('history').append(row);}
}
$('cancel-survey').onclick=async()=>{if(!active)return;try{await api('/api/jobs/'+active+'/cancel',{});notice('Đã yêu cầu dừng; chờ tool hoàn tất cleanup. Lệnh đã gửi tới Sandcat có thể vẫn đang chạy.');}catch(e){notice(e.message);}};
$('refresh-history').onclick=()=>loadHistory().catch(e=>notice(e.message));
$('copy-json').onclick=async()=>{if(!profile)return;try{await navigator.clipboard.writeText(JSON.stringify(profile,null,2));notice('Đã sao chép Target Profile.');}catch(_){notice('Không truy cập được clipboard. Bạn có thể tải JSON.');}};
$('new-survey').onclick=()=>{if(active||submitting)return;validated='';clearResult();notice('');$('target-ip').value='';$('target-ip').focus();$('start-button').disabled=true;badge('check-summary','Chưa kiểm tra','neutral');badge('run-status','Đang chờ','neutral');$('progress-number').textContent='Chưa chạy';$('progress-fill').className='activity-indicator';$('run-message').textContent='Đợi kiểm tra điều kiện.';$('survey-events').replaceChildren();$('checks').replaceChildren(element('p','Nhập IP và kiểm tra điều kiện của mục tiêu mới.','help'));$('logs').textContent='Chưa có hoạt động.';$('log-count').textContent='0 sự kiện';};
$('nav-config').onclick=()=>$('config-dialog').showModal();$('close-config').onclick=()=>$('config-dialog').close();
$('transfer-profile').onclick=async()=>{if(!profile)return;try{await window.ScenarioUI.useProfile(profile,'Survey '+surveyRunId+' · xác minh snapshot v2 tại backend',surveyRunId);window.ScenarioUI.navigate('scenario');}catch(e){notice(e.message);}};
(async()=>{try{
  const meta=await api('/api/meta');token=meta.token;$('mode-label').textContent=meta.mode==='ai'?'AI · '+(meta.model||'Chưa cấu hình model'):'Scripts · Điều phối xác định';
  if((meta.pending_recovery||[]).length)notice('Có lượt khảo sát cần kiểm tra cleanup CALDERA. Xem SURVEY_UPGRADE.md và tools/reconcile.py trước khi chạy lại.');
  $('mode-footer').textContent=meta.mode==='ai'?'AI điều phối · Profile từ bằng chứng':'Chế độ scripts · Profile từ bằng chứng';
  $('config-url').textContent=meta.caldera_url;$('config-networks').textContent=meta.allowed_networks.join(', ');$('config-root').textContent=meta.app_root||'Chưa xác định';$('config-mode').textContent=meta.mode==='ai'?'AI · '+meta.model:'Scripts';
  await loadHistory();if(meta.active_job){active=meta.active_job;const job=await api('/api/jobs/'+active);$('target-ip').value=job.request.target_ip;$('check-dvwa').checked=(job.request.web_checks||[]).includes('dvwa');const scope=job.request.survey_scope.length===2?'both':job.request.survey_scope[0];document.querySelector(`input[name=scope][value=${scope}]`).checked=true;lock(true);poll();}
}catch(e){notice('Không tải được cấu hình: '+e.message);$('check-button').disabled=true;}})();
