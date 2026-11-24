(function () {
  'use strict';
  const el = id => document.getElementById(id);
  const core = window.ScenarioCore;
  const families = { scenario: 'SCENARIO', caldera: 'CALDERA Stockpile', dvwa: 'DVWA', nckh: 'NCKH', generated: 'Kịch bản đã sinh' };
  let data = null, targetProfile = null, sample = null, currentPreview = null;
  let selectedItem = null, family = 'all', page = 1, detailTab = 'overview';
  const pageSize = 10;
  let scenarioJob = null, scenarioTimer = null, surveyRunId = null, scenarioRetryTimer = null;
  let scenarioActionBusy = false, currentScenario = null, baseItems = [], scenarioVersion = 0, profileVersion = 0;

  async function scenarioApi(path, body) {
    const options = {};
    if (body !== undefined) {
      const meta = await (await fetch('/api/meta')).json();
      options.method = 'POST';
      options.headers = {'Content-Type': 'application/json', 'X-Survey-Token': meta.token};
      options.body = JSON.stringify(body);
    }
    const response = await fetch(path, options);
    const value = await response.json();
    if (!response.ok) throw Error(value.error || 'Không đọc được Scenario Agent.');
    return value;
  }
  function tokenSummary(metrics) {
    return 'LLM: '+metrics.requests+' request · actual đã biết '+(metrics.actual_total_tokens ?? 'chưa có')+' token · '+metrics.unknown_usage_requests+' request chưa có usage · reservation/charge nội bộ '+metrics.charged_tokens+' token (có phần ước lượng).';
  }
  async function showScenario(id, restoreInput = false) {
    const version = ++scenarioVersion, selectionVersion = profileVersion;
    clearTimeout(scenarioTimer);clearTimeout(scenarioRetryTimer);
    try {
      const job = await scenarioApi('/api/scenarios/' + id);
      if (version !== scenarioVersion) return;
      if (restoreInput && scenarioJob !== id && data) {
        const profile = await scenarioApi('/api/scenarios/' + id + '/files/target_profile.json');
        const request = await scenarioApi('/api/scenarios/' + id + '/files/request.json');
        if (version !== scenarioVersion || selectionVersion !== profileVersion) return;
        setProfile(profile, 'Scenario ' + id, job.input_source === 'survey_v2' ? job.survey?.survey_run_id : null);
        el('scenario-request').value = request.text;
        el('request-max-steps').value = request.max_steps;
        for (const scope of ['endpoint','web']) el('request-' + scope).checked = request.scope.includes(scope);
      }
      scenarioJob = id; currentScenario = job;
      if (window.ScenarioExecutionUI) window.ScenarioExecutionUI.select(job);
      const running = ['running','cancelling'].includes(job.status);
      renderScenarioActions();
      for (const name of ['scenario-request','request-max-steps','request-endpoint','request-web','profile-upload','existing-profile','remove-profile']) el(name).disabled = running;
      el('preview-sample').disabled = running;
      const labels = {cancelled:'Đã hủy sinh kịch bản', cancelling:'Đang hủy sinh kịch bản', running: 'Đang lập kế hoạch', completed: 'Đã tạo plan và kiểm tra grounding',
        needs_information: 'Cần bổ sung thông tin', waiting_quota: 'Provider giới hạn request/token (429)',
        waiting_budget:'Đang chờ ngân sách LLM nội bộ',budget_exceeded:'Context/lượt sinh vượt ngân sách',waiting_service: 'Provider tạm quá tải (503/5xx)', insufficient_coverage: 'Chưa tìm được ability bao phủ đủ yêu cầu',
        invalid_plan: 'Plan chưa vượt qua kiểm tra', invalid_request: 'Yêu cầu chưa hợp lệ',
        error: 'Lượt lập kế hoạch gặp lỗi', interrupted: 'Lượt chạy bị gián đoạn'};
      const result = job.result || {};
      el('scenario-run-status').textContent = (labels[job.status] || job.status) + ((job.phase || result.resume_phase || result.phase) ? ' · ' + (job.phase || result.resume_phase || result.phase) : '');
      el('scenario-run-details').textContent = JSON.stringify({id:job.id, status:job.status,
        source: job.input_source || 'legacy_profile', survey: job.survey, evidence: result.evidence_quality,
        readiness: result.readiness, execution_readiness: result.execution_readiness, detection_readiness: result.detection_readiness,
        result, provenance: 'Xem input_manifest, context_selection, compatibility_report và step_evidence để đối chiếu Survey'}, null, 2);
      el('scenario-feedback').textContent = [job.error, result.error,
        ...(result.grounding_diagnostics?.status === 'invalid_grounding' ? ['Bằng chứng AI đề xuất chưa vượt qua kiểm tra.', ...(result.grounding_diagnostics.errors || [])] : []),
        ...(result.analyzed_behaviors?.length ? ['Các hành vi đang đối chiếu (gồm phần bổ sung đã lưu):', ...result.analyzed_behaviors.map(b => b.description + ' — nguồn: ' + b.source_quote)] : []),
        ...(result.retry_not_before ? ['Có thể thử lại sau: '+result.retry_not_before] : []),
        ...(result.budget_reason === 'phase_input_limit'
          ? ['Context vượt giới hạn input của bước này. Hãy giảm context hoặc điều chỉnh ngân sách của bước trước khi tiếp tục.']
          : result.budget_reason ? ['Giới hạn nội bộ: '+result.budget_reason+'.' + (job.status === 'waiting_budget' ? ' Hãy thử lại khi ngân sách được cấp lại.' : '')] : []),
        ...((job.token_metrics || result.token_metrics) ? [tokenSummary(job.token_metrics || result.token_metrics)] : []),
        ...(result.questions || []),
        ...(result.validation_errors || []), ...(result.uncovered_behaviors || []), ...(result.blockers || [])].filter(Boolean).join('\n');
      el('scenario-resume').hidden = !['needs_information','waiting_service','waiting_quota','error','invalid_plan','insufficient_coverage','waiting_budget','budget_exceeded'].includes(job.status) || !result.run_id;
      const needsAnswer=['needs_information','insufficient_coverage'].includes(job.status);
      el('scenario-clarification').hidden=!needsAnswer;el('scenario-clarification-label').hidden=!needsAnswer;
      const delay=Date.parse(result.retry_not_before || '')-Date.now();
      el('scenario-resume-button').disabled=delay>0;
      if(delay>0)scenarioRetryTimer=setTimeout(()=>{if(scenarioJob===id)el('scenario-resume-button').disabled=false;},Math.min(delay,2147483647));
      el('scenario-files').replaceChildren();
      for (const file of job.files || []) {
        const link = node('a', file, 'text-button');
        link.href = '/api/scenarios/' + id + '/files/' + file;
        link.download = file;
        el('scenario-files').append(link, document.createTextNode(' · '));
      }
      if (job.status === 'completed' && job.yaml) {
        currentPreview = {yaml:job.yaml, filename:'scenario_plan_' + id + '.yml', steps:result.steps};
        el('yaml-filename').textContent = currentPreview.filename;
        el('yaml-preview').textContent = job.yaml;
        el('yaml-step-count').textContent = result.steps + ' bước · cần duyệt và kiểm tra điều kiện trước thực thi';
        el('yaml-empty').hidden = true; el('yaml-result').hidden = false;
      } else { clearPreview(); }
      if (running) scenarioTimer = setTimeout(() => showScenario(id), 2000);
      else refreshScenarioHistory();
    } catch (error) {
      if (version !== scenarioVersion) return;
      message('scenario-notice', error.message);
      el('preview-sample').disabled = false;
    }
  }
  function renderScenarioActions() {
    const job = currentScenario;
    el('scenario-actions').hidden = !job;
    el('scenario-action-hint').hidden = !job;
    if (!job) return;
    const active = ['running','cancelling'].includes(job.status);
    const complete = job.status === 'completed' && !!job.yaml;
    el('scenario-add-library').disabled = scenarioActionBusy || !complete || !!job.saved_to_library;
    el('scenario-add-library').textContent = job.saved_to_library ? 'Đã thêm vào kho' : 'Thêm vào kho kịch bản';
    el('scenario-regenerate').disabled = scenarioActionBusy || active;
    el('scenario-delete').hidden = active;
    el('scenario-delete').disabled = scenarioActionBusy || active;
    el('scenario-cancel').hidden = !active;
    el('scenario-cancel').disabled = scenarioActionBusy || job.status === 'cancelling';
    el('scenario-execute').disabled = scenarioActionBusy || !complete;
    el('scenario-action-hint').textContent = active ? 'Hủy sẽ dừng lượt đang sinh.' : 'Tạo lại dùng cùng input và phần bổ sung đã lưu. Xóa chỉ ẩn lượt khỏi lịch sử; bản trong kho vẫn được giữ.';
  }
  async function scenarioAction(name) {
    if (!scenarioJob || scenarioActionBusy) return;
    const id = scenarioJob;
    if (name === 'execute') { if (window.ScenarioExecutionUI) await window.ScenarioExecutionUI.open(id, false); return; }
    scenarioActionBusy = true; renderScenarioActions();
    try {
      const result = await scenarioApi('/api/scenarios/' + id + '/' + name, {});
      if (name === 'library') {
        if (scenarioJob === id && currentScenario) currentScenario.saved_to_library = true;
        await reloadLibrary();
        message('scenario-notice', 'Đã thêm kịch bản vào kho.');
      } else if (name === 'regenerate') {
        message('scenario-notice', 'Đã mở lượt sinh mới với cùng input đã lưu.');
        await showScenario(result.id);
      } else if (name === 'delete') {
        if (scenarioJob === id) {
          ++scenarioVersion; clearTimeout(scenarioTimer);
          scenarioJob = null; currentScenario = null; clearPreview();
          el('scenario-run-status').textContent = 'Đã xóa khỏi lịch sử';
          el('scenario-feedback').textContent = '';
          el('scenario-files').replaceChildren();
          el('scenario-run-details').textContent = '';
          el('scenario-resume').hidden = true;
        }
        await refreshScenarioHistory();
        message('scenario-notice', 'Đã ẩn lượt khỏi lịch sử. Bằng chứng và bản đã thêm vào kho được giữ lại.');
      } else if (name === 'cancel') {
        message('scenario-notice', 'Đã yêu cầu hủy. Đang chờ tiến trình sinh kịch bản dừng.');
        await showScenario(id);
      }
    } catch (error) { message('scenario-notice', error.message); }
    finally { scenarioActionBusy = false; renderScenarioActions(); }
  }
  async function reloadLibrary() {
    const saved = await scenarioApi('/api/scenario-library');
    if (!saved || !Array.isArray(saved.items)) throw Error('Không đọc được kho kịch bản đã lưu.');
    data.items = baseItems.concat(saved.items);
    renderLibrarySummary(); renderLibrary();
  }
  async function refreshScenarioHistory() {
    try {
      const jobs = await scenarioApi('/api/scenarios');
      el('scenario-history').replaceChildren();
      for (const job of jobs.sort((a,b) => b.created_at.localeCompare(a.created_at))) {
        const statusText={cancelled:'Đã hủy',cancelling:'Đang hủy',insufficient_coverage:'Chưa đủ bao phủ',completed:'Hoàn tất',waiting_service:'Chờ dịch vụ AI',running:'Đang chạy',needs_information:'Cần bổ sung',error:'Có lỗi'};
        const button = node('button', new Date(job.created_at).toLocaleString('vi-VN') + ' · ' + job.target_ip + ' · ' + (statusText[job.status] || job.status), 'text-button history-entry');
        button.type = 'button'; button.onclick = () => showScenario(job.id, true);
        el('scenario-history').append(button, node('br'));
      }
      const active = jobs.find(job => ['running','cancelling'].includes(job.status));
      if (active && !scenarioJob) showScenario(active.id, !targetProfile);
    } catch (error) { message('scenario-notice', error.message); }
  }

  function node(tag, text, className) {
    const item = document.createElement(tag);
    if (text !== undefined) item.textContent = text;
    if (className) item.className = className;
    return item;
  }
  function message(id, text) {
    el(id).textContent = text;
    el(id).hidden = !text;
  }
  function navigate(view, updateHash = true) {
    if (!['survey', 'scenario', 'library', 'abilities', 'flow'].includes(view)) view = 'survey';
    for (const name of ['survey', 'scenario', 'library', 'abilities', 'flow']) {
      el(name + '-view').hidden = name !== view;
      const nav = el('nav-' + name);
      nav.classList.toggle('selected', name === view);
      if (name === view) nav.setAttribute('aria-current', 'page');
      else nav.removeAttribute('aria-current');
    }
    el('nav-history').classList.remove('selected');
    document.body.classList.toggle('flow-mode', view === 'flow');
    el('workspace-flow').setAttribute('aria-pressed', String(view === 'flow'));
    el('workspace-flow').setAttribute('title', view === 'flow' ? 'Trở về chế độ ứng dụng' : 'Xem luồng hệ thống');
    if (view !== 'flow') document.body.classList.remove('flow-expanded');
    if (window.FlowUI) window.FlowUI.onViewChange(view);
    const title = { survey: 'Khảo sát mục tiêu', scenario: 'Sinh kế hoạch kịch bản', library: 'Kho kịch bản', abilities: 'Kho ability', flow: 'Luồng hệ thống' }[view];
    el('view-title').textContent = title;
    document.title = title + ' · SOC Lab';
    if (updateHash && location.hash !== '#' + view) location.hash = view;
    window.scrollTo({ top: 0, behavior: 'auto' });
  }
  function clearPreview() {
    currentPreview = null;
    el('yaml-result').hidden = true;
    el('yaml-empty').hidden = false;
  }
  function setProfile(value, source, runId = null) {
    const checked = core.validateProfile(value, data.profileSchema);
    ++profileVersion; surveyRunId = runId;
    targetProfile = checked;
    clearPreview();
    el('scenario-profile-state').textContent = 'Đã chọn hồ sơ';
    el('scenario-profile-state').className = 'badge good';
    el('selected-profile').hidden = false;
    el('scenario-profile-name').textContent = checked.os.hostname || checked.id;
    el('scenario-profile-source').textContent = source + (runId ? ' · xác minh bộ dữ liệu v2 khi sinh kế hoạch' : ' · Chỉ hồ sơ, chưa có bằng chứng đi kèm');
    el('scenario-profile-json').textContent = JSON.stringify(checked, null, 2);
    el('scenario-profile-summary').replaceChildren();
    for (const [label, value] of [['Địa chỉ', checked.address], ['Hệ điều hành', checked.os.name],
      ['Dịch vụ', String(checked.services.length)], ['Quyền admin', checked.capabilities.admin_ready === true ? 'Có' : checked.capabilities.admin_ready === false ? 'Không' : null]]) {
      const item = node('div', undefined, 'meta-item');
      item.append(node('small', label), node('strong', value === null || value === undefined ? 'Chưa xác minh' : value));
      el('scenario-profile-summary').append(item);
    }
    message('scenario-notice', '');
  }
  async function useProfile(value, source, runId = null) {
    await ready;
    if (!data) throw Error('Chưa đọc được dữ liệu giao diện. Tải lại trang để thử lại.');
    el('existing-profile').value = '';
    el('profile-upload').value = '';
    setProfile(value, source, runId);
  }
  async function upload(file) {
    try {
      await ready;
      if (!data) throw Error('Chưa tải được cấu trúc Target Profile. Tải lại trang để thử lại.');
      const profile = await core.readProfile(file, data.profileSchema);
      el('existing-profile').value = '';
      setProfile(profile, 'File tải lên: ' + file.name);
    } catch (error) {
      message('scenario-notice', error.message + (targetProfile ? ' Hồ sơ đã chọn trước đó được giữ lại.' : ''));
    } finally {
      el('profile-upload').value = '';
    }
  }
  function chooseSample(item) {
    sample = item;
    clearPreview();
    el('sample-selection-name').textContent = item ? item.name : 'Mẫu chuẩn trong final_template';
    el('sample-selection-source').textContent = item ? item.file : 'scenario_adversary_template.yaml';
    el('reset-sample').hidden = !item;
  }
  function download(text, filename) {
    const url = URL.createObjectURL(new Blob([text], { type: 'application/yaml;charset=utf-8' }));
    const anchor = node('a'); anchor.href = url; anchor.download = filename;
    document.body.append(anchor); anchor.click(); anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function selectTab(name) {
    detailTab = name;
    for (const tab of ['overview', 'yaml']) {
      const selected = name === tab;
      el('detail-' + tab + '-tab').setAttribute('aria-selected', String(selected));
      el('detail-' + tab + '-tab').tabIndex = selected ? 0 : -1;
    }
    el('detail-overview').hidden = name !== 'overview';
    el('detail-yaml-panel').hidden = name !== 'yaml';
  }
  function renderDetail(item) {
    selectedItem = item;
    el('library-detail-empty').hidden = !!item;
    el('library-detail').hidden = !item;
    if (!item) return;
    el('detail-family').textContent = families[item.family];
    el('detail-steps').textContent = item.abilities.length + ' bước';
    el('detail-name').textContent = item.name;
    el('detail-description').textContent = item.description;
    el('detail-id').textContent = item.id;
    el('detail-file').textContent = item.file;
    el('detail-scope').textContent = item.scope.map(s => s === 'web' ? 'Web / DVWA' : 'Endpoint').join(' + ');
    el('detail-abilities').replaceChildren(...item.abilities.map(id => node('li', id)));
    el('detail-yaml').textContent = item.yaml;
    selectTab(detailTab);
  }
  function renderLibrary() {
    if (!data) return;
    const filtered = core.filterScenarios(data.items, el('library-search').value, family, el('library-scope').value);
    const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
    page = Math.min(page, pages);
    el('library-count').textContent = filtered.length + ' kịch bản';
    el('library-empty').hidden = filtered.length > 0;
    el('library-prev').disabled = page <= 1;
    el('library-next').disabled = page >= pages;
    el('library-page').textContent = filtered.length ? `Trang ${page} / ${pages}` : '0 kết quả';
    el('library-list').replaceChildren();
    if (selectedItem && !filtered.some(item => item.id === selectedItem.id)) renderDetail(null);
    for (const item of filtered.slice((page - 1) * pageSize, page * pageSize)) {
      const button = node('button', undefined, 'scenario-row');
      button.type = 'button';
      button.classList.toggle('chosen', !!selectedItem && item.id === selectedItem.id);
      button.setAttribute('aria-pressed', String(!!selectedItem && item.id === selectedItem.id));
      const top = node('div', undefined, 'scenario-row-top');
      top.append(node('span', families[item.family], 'badge ' + (item.family === 'dvwa' ? 'good' : 'purple')),
        node('span', item.abilities.length + ' bước', 'muted-note'));
      button.append(top, node('strong', item.name), node('span', item.description, 'scenario-row-description'),
        node('small', item.scope.map(x => x === 'web' ? 'Web' : 'Endpoint').join(' + ') + '  ·  Xem chi tiết →'));
      button.onclick = () => { renderDetail(item); renderLibrary(); if (window.matchMedia('(max-width:680px)').matches) el('library-detail').scrollIntoView({ behavior: 'smooth', block: 'start' }); };
      el('library-list').append(button);
    }
    for (const button of el('library-filters').children) {
      const selected = button.dataset.family === family;
      button.classList.toggle('active', selected);
      button.setAttribute('aria-pressed', String(selected));
    }
  }
  function renderLibrarySummary() {
    el('library-stats').replaceChildren();
    el('library-filters').replaceChildren();
    el('dataset-groups').replaceChildren();
    const total = node('div', undefined, 'stat-card');
    total.append(node('span', 'Tổng kịch bản'), node('strong', String(data.items.length)), node('small', 'Dataset hiện có'));
    el('library-stats').append(total);
    for (const [key,label] of [['endpoint','Endpoint'],['web','Dịch vụ web']]) { const stat=node('div',undefined,'stat-card'); stat.append(node('span',label),node('strong',String(data.items.filter(x=>x.scope.includes(key)).length)),node('small','Kịch bản có phạm vi này')); el('library-stats').append(stat); }
    const groups = [['all', 'Tất cả'], ...Object.entries(families)];
    for (const [key, label] of groups) {
      const count = key === 'all' ? data.items.length : data.items.filter(item => item.family === key).length;
      const button = node('button', label + ' · ' + count);
      button.type = 'button'; button.dataset.family = key;
      button.onclick = () => { family = key; page = 1; renderLibrary(); };
      el('library-filters').append(button);
      if (key === 'all') continue;
      const stat = node('div', undefined, 'stat-card'); stat.append(node('span', label), node('strong', String(count)), node('small', 'kịch bản'));
      // Source filters remain below; summary cards describe target surfaces.
      const choice = node('label', undefined, 'dataset-choice');
      const checkbox = node('input'); checkbox.type = 'checkbox'; checkbox.checked = true; checkbox.value = key;
      const text = node('span'); text.append(node('strong', label), node('small', count + ' kịch bản'));
      checkbox.onchange = clearPreview; choice.append(checkbox, text); el('dataset-groups').append(choice);
    }
  }
  async function initData() {
    data.profiles = [];
    try {
      const jobs = await (await fetch('/api/jobs')).json();
      for (const job of jobs.filter(j => ['completed','completed_with_unknowns','partial'].includes(j.status)).slice(0,20)) {
        const full = await (await fetch('/api/jobs/' + job.id)).json();
        if (full.profile) data.profiles.push({name:full.profile.address + ' · ' + job.created_at,
          profile:full.profile, runId:job.id, file:'Survey ' + job.id});
      }
    } catch (_) { /* Upload and Survey transfer remain available. */ }
    el('existing-profile').replaceChildren(node('option', 'Chọn hồ sơ sẵn có…'));
    el('existing-profile').firstChild.value = '';
    data.profiles.forEach((entry, i) => {
      const option = node('option', entry.name); option.value = String(i); el('existing-profile').append(option);
    });
    renderLibrarySummary();
    el('preview-sample').disabled = false;
    el('dataset-groups').hidden = true;
    el('sample-selection').hidden = true;
    refreshScenarioHistory();
    renderLibrary();
  }

  el('preview-sample').disabled = true;
  const ready = (async () => {
    try {
      const response = await fetch('/scenario-data.json');
      if (!response.ok) throw Error('HTTP ' + response.status);
      data = JSON.parse(JSON.stringify(await response.json()));
      if (data.mode !== 'ui_preview' || !Array.isArray(data.items) || !data.template || !data.profileSchema) throw Error('Dữ liệu mẫu không đúng cấu trúc.');
      baseItems = data.items.slice();
      await initData();
      try { await reloadLibrary(); } catch (error) { message('library-notice', 'Kho kịch bản đã lưu chưa tải được. ' + error.message); }
    } catch (error) {
      data = null;
      const text = 'Chưa đọc được dữ liệu giao diện. Tải lại trang để thử lại. ' + error.message;
      message('scenario-notice', text); message('library-notice', text);
      el('existing-profile').replaceChildren(node('option', 'Chưa đọc được hồ sơ'));
    }
  })();
  window.ScenarioUI = { useProfile, navigate, getFlowContext: () => ({
    profile: targetProfile, request: el('scenario-request').value,
    sample: sample || (data ? data.template : null), datasetCount: data ? data.items.length : null,
    scope: ['endpoint', 'web'].filter(name => el('request-' + name).checked),
    maxSteps: Number(el('request-max-steps').value) || 4
  }) };

  for (const view of ['survey', 'scenario', 'library', 'abilities', 'flow']) el('nav-' + view).onclick = () => navigate(view);
  el('workspace-flow').onclick = () => navigate(el('flow-view').hidden ? 'flow' : 'survey');
  el('nav-history').onclick = () => { navigate('survey'); el('nav-survey').classList.remove('selected'); el('nav-history').classList.add('selected'); el('history-section').scrollIntoView({ behavior: 'smooth' }); };
  el('browse-dataset').onclick = () => navigate('library');
  el('back-to-scenario').onclick = () => navigate('scenario');
  window.addEventListener('hashchange', () => navigate(location.hash.slice(1), false));
  navigate(location.hash.slice(1), false);
  el('profile-upload').onchange = event => { if (event.target.files[0]) upload(event.target.files[0]); };
  for (const event of ['dragover', 'dragenter']) el('profile-drop').addEventListener(event, e => { e.preventDefault(); el('profile-drop').classList.add('drag-over'); });
  for (const event of ['dragleave', 'drop']) el('profile-drop').addEventListener(event, e => { e.preventDefault(); el('profile-drop').classList.remove('drag-over'); });
  el('profile-drop').addEventListener('drop', e => { if (e.dataTransfer.files[0]) upload(e.dataTransfer.files[0]); });
  el('existing-profile').onchange = event => {
    if (event.target.value === '' || !data) return;
    try { const entry = data.profiles[Number(event.target.value)]; setProfile(entry.profile, entry.file + ' · kèm bằng chứng khảo sát', entry.runId); }
    catch (error) { message('scenario-notice', error.message); }
  };
  el('remove-profile').onclick = () => {
    targetProfile = null; surveyRunId = null; clearPreview(); el('existing-profile').value = ''; el('profile-upload').value = '';
    el('selected-profile').hidden = true; el('scenario-profile-state').textContent = 'Chưa chọn'; el('scenario-profile-state').className = 'badge';
  };
  el('scenario-request').oninput = () => { el('request-count').textContent = el('scenario-request').value.length + ' / 4000'; clearPreview(); };
  for (const id of ['request-endpoint', 'request-web', 'request-max-steps']) el(id).addEventListener('input', clearPreview);
  el('reset-sample').onclick = () => chooseSample(null);
  el('preview-sample').onclick = async () => {
    message('scenario-notice', '');
    if (!targetProfile) { message('scenario-notice', 'Thêm Target Profile trước khi xem luồng mẫu.'); el('profile-upload').focus(); return; }
    if (!el('scenario-request').value.trim()) { message('scenario-notice', 'Nhập yêu cầu kiểm thử để hoàn thiện bản thiết kế.'); el('scenario-request').focus(); return; }
    if (!el('request-endpoint').checked && !el('request-web').checked) { message('scenario-notice', 'Chọn ít nhất một phạm vi kiểm thử.'); el('request-endpoint').focus(); return; }
    if (!el('request-max-steps').reportValidity() || !Number.isInteger(Number(el('request-max-steps').value))) return;
    try {
      el('preview-sample').disabled = true; clearPreview();
      const text = el('scenario-request').value.trim();
      const job = await scenarioApi('/api/scenarios', {...(surveyRunId ? {survey_run_id:surveyRunId,input_kind:'survey_v2'} : {profile:targetProfile,input_kind:'profile_only'}), text,
        scope:['endpoint','web'].filter(name => el('request-' + name).checked),
        max_steps:Number(el('request-max-steps').value)});
      showScenario(job.id);
    } catch (error) { message('scenario-notice', error.message); el('preview-sample').disabled = false; }
  };
  for (const [id, action] of [['scenario-add-library','library'],['scenario-regenerate','regenerate'],['scenario-cancel','cancel'],['scenario-delete','delete'],['scenario-execute','execute']]) {
    el(id).onclick = () => scenarioAction(action);
  }
  el('scenario-resume-button').onclick = async () => {
    if (!scenarioJob) return;
    try {
      await scenarioApi('/api/scenarios/' + scenarioJob + '/resume', {clarification:el('scenario-clarification').value});
      el('scenario-resume').hidden = true;
      showScenario(scenarioJob);
    } catch (error) { message('scenario-notice', error.message); }
  };
  el('copy-yaml').onclick = async () => {
    if (!currentPreview) return;
    try { await navigator.clipboard.writeText(currentPreview.yaml); message('scenario-notice', 'Đã sao chép kế hoạch YAML.'); }
    catch (_) { message('scenario-notice', 'Không truy cập được clipboard. Bạn có thể tải YAML mẫu.'); }
  };
  el('download-yaml').onclick = () => { if (currentPreview) download(currentPreview.yaml, currentPreview.filename); };
  el('library-search').oninput = el('library-scope').onchange = () => { page = 1; renderLibrary(); };
  el('library-prev').onclick = () => { page--; renderLibrary(); };
  el('library-next').onclick = () => { page++; renderLibrary(); };
  el('reset-library-filters').onclick = () => { family = 'all'; page = 1; el('library-search').value = ''; el('library-scope').value = 'all'; renderLibrary(); };
  for (const tab of ['overview', 'yaml']) {
    const button = el('detail-' + tab + '-tab'); button.onclick = () => selectTab(tab);
    button.onkeydown = event => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault(); const next = event.key === 'Home' ? 'overview' : event.key === 'End' ? 'yaml' : tab === 'overview' ? 'yaml' : 'overview';
      selectTab(next); el('detail-' + next + '-tab').focus();
    };
  }
  el('use-library-sample').onclick = () => {
    if (selectedItem) {
      if (selectedItem.family === 'generated') {
        if (selectedItem.profile) setProfile(selectedItem.profile, 'Kho kịch bản đã sinh', selectedItem.survey_run_id);
        el('scenario-request').value = selectedItem.request.text;
        el('request-max-steps').value = selectedItem.request.max_steps;
        for (const scope of ['endpoint','web']) el('request-' + scope).checked = selectedItem.scope.includes(scope);
        message('scenario-notice', 'Đã đưa yêu cầu gốc vào biểu mẫu. Dùng Tạo lại từ lịch sử để giữ đầy đủ phần bổ sung và input đã ghim.');
        clearPreview(); navigate('scenario'); return;
      }
      el('scenario-request').value = 'Lập kế hoạch dựa trên adversary ' + selectedItem.id + ' (' + selectedItem.name + '). ';
      message('scenario-notice', 'Đã đưa tham chiếu vào yêu cầu. Scenario Agent sẽ kiểm tra ID trong catalog hiện hành.');
      clearPreview(); navigate('scenario');
    }
  };
  el('download-library-yaml').onclick = () => { if (selectedItem) { const value = core.preview(selectedItem); download(value.yaml, value.filename); } };
})();
