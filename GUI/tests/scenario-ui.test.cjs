const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const core = require('../static/scenario-core.js');
const staticDir = path.join(__dirname, '../static');
const data = JSON.parse(fs.readFileSync(path.join(staticDir, 'scenario-data.json')));
const schema = data.profileSchema;

test('service inventory folds system rows and telemetry keeps observation context', async () => {
  const {context, elements:e} = boot();
  const profile = structuredClone(data.profiles[0].profile);
  profile.services = [{name:'Windows Audio',state:'Running'}, {name:'TCP listeners',listeners:[]}, {name:'Wazuh',state:'Running'}];
  context.fixtureJob={id:'compact',status:'completed_with_unknowns',profile,request:{survey_scope:['endpoint']},logs:[],warnings:[],files:[],
    report:{telemetry:{checked_at:'2026-11-16T10:00:00Z',window_hours:24,checks:{wazuh_ingestion:{reason:'Observed at manager',evidence:[{source:'alerts/alerts.json',timestamp:'2026-11-16T09:59:00Z'}]}}}}};
  vm.runInContext('render(fixtureJob)',context);
  const rows=e['summary-services'].children;
  assert.equal(rows.length,2);
  const folded=rows[1].children[0];
  assert.equal(folded.tagName,'details');
  assert.equal(folded.attributes.open,undefined);
  assert.equal(folded.children[1].children.length,2);
  assert.ok(e['telemetry-details'].children.length>0);
});

test('profile upload preserves nulls and target identity, rejects malformed input', async () => {
  const original = data.profiles[0].profile;
  const uploaded = await core.readProfile({ name: 'profile.json', size: 123, text: async () => JSON.stringify(original) }, schema);
  assert.deepEqual(uploaded, original);
  assert.notEqual(uploaded, original);
  assert.equal(uploaded.telemetry.wazuh_ingestion, null);
  await assert.rejects(core.readProfile({ name: 'profile.yaml' }, schema), /json/);
  await assert.rejects(core.readProfile({ name: 'profile.json', size: core.MAX_PROFILE_BYTES + 1 }, schema), /1 MB/);
  await assert.rejects(core.readProfile({ name: 'profile.json', text: async () => '{bad' }, schema), /JSON/);
  assert.throws(() => core.validateProfile(null, schema));
  assert.throws(() => core.validateProfile({ ...original, extra: 'outside contract' }, schema));
  assert.throws(() => core.validateProfile({ ...original, capabilities: { art_ready: null } }, schema));
  assert.throws(() => core.validateProfile({ ...original, capabilities: { sandcat_online: 'true' } }, schema));
});

test('library uses all supplied scenarios and filters by source, scope and IDs', () => {
  assert.equal(data.items.length, 113);
  assert.equal(core.filterScenarios(data.items, '', 'caldera').length, 25);
  assert.equal(core.filterScenarios(data.items, '', 'dvwa').length, 11);
  const results = core.filterScenarios(data.items, 'powershell', 'scenario', 'endpoint');
  assert.ok(results.length > 0);
  assert.ok(results.every(item => item.family === 'scenario' && item.scope.includes('endpoint')));
  const item = data.items[0];
  assert.ok(core.filterScenarios(data.items, item.abilities[0]).some(row => row.id === item.id));
  assert.equal(core.filterScenarios(data.items, 'no-match-00000000').length, 0);
  assert.ok(core.filterScenarios(data.items, 'kham pha').length > 0);
});

test('sample preview returns exact source YAML with a sample filename', () => {
  for (const item of [...data.items, data.template]) {
    const preview = core.preview(item);
    assert.equal(preview.yaml, item.yaml);
    assert.equal(preview.steps, item.abilities.length);
    assert.match(preview.filename, /^[\w-]+\.sample\.yml$/);
  }
});

// Minimal DOM fixture exercises event wiring. It is not browser/layout QA.
function boot(includeFlow = false) {
  class Element {
    constructor(tag = 'div') {
      this.tagName = tag; this.children = []; this.attributes = {}; this.dataset = {};
      this.style = {}; this.value = ''; this.checked = false; this.hidden = false;
      this.disabled = false; this._text = ''; this.listeners = {};
      this.classes = new Set();
      this.classList = { add: (...names) => names.forEach(n => this.classes.add(n)),
        remove: (...names) => names.forEach(n => this.classes.delete(n)),
        toggle: (n, on) => { const active = on === undefined ? !this.classes.has(n) : on;
          if (active) this.classes.add(n); else this.classes.delete(n); return active; } };
    }
    get textContent() { return this._text; }
    set textContent(text) { this._text = String(text); this.children = []; }
    get firstChild() { return this.children[0]; }
    append(...items) { this.children.push(...items); }
    replaceChildren(...items) { this.children = items; }
    setAttribute(k, v) { this.attributes[k] = v; }
    getAttribute(k) { return this.attributes[k]; }
    removeAttribute(k) { delete this.attributes[k]; }
    addEventListener(event, callback) { this.listeners[event] = callback; }
    querySelectorAll(selector) {
      const descendants = this.children.flatMap(child => [child, ...child.querySelectorAll('*')]);
      return selector === 'input:checked' ? descendants.filter(child => child.tagName === 'input' && child.checked) : descendants;
    }
    focus() { this.focused = true; }
    scrollIntoView() {}
    reportValidity() { return Number(this.value) >= 1 && Number(this.value) <= 50; }
    click() { if (this.onclick) return this.onclick(); }
    remove() {}
    getTotalLength() { return 100; }
    getPointAtLength(length) { return { x: length, y: 0 }; }
  }
  const elements = {};
  const html = fs.readFileSync(path.join(staticDir, 'index.html'), 'utf8');
  for (const match of html.matchAll(/<([a-z][a-z0-9]*)\b([^>]*\bid="([^"]+)"[^>]*)>/g)) {
    const element = new Element(match[1]);
    element.hidden = /\bhidden\b/.test(match[2]);
    const value = match[2].match(/\bvalue="([^"]*)"/);
    element.value = value ? value[1] : '';
    element.checked = /\bchecked\b/.test(match[2]);
    elements[match[3]] = element;
  }
  elements['library-scope'].value = 'all';
  elements['flow-mode'].value = 'normal'; elements['flow-speed'].value = '1';
  const requests = [], requestBodies = [];
  const frames = new Map(); let nextFrame = 0;
  const context = { document: { getElementById: id => {
      assert.ok(elements[id], 'Missing DOM element: ' + id); return elements[id];
    }, createElement: tag => new Element(tag), createTextNode: text => Object.assign(new Element('text'), {textContent:text}), createElementNS: (_, tag) => new Element(tag),
      addEventListener() {}, querySelectorAll: () => [], body: new Element('body') },
    location: { hash: '#scenario' }, addEventListener() {}, scrollTo() {},
    matchMedia: () => ({ matches: false }), setTimeout, clearTimeout,
    requestAnimationFrame: callback => { frames.set(++nextFrame, callback); return nextFrame; },
    cancelAnimationFrame: id => frames.delete(id),
    navigator: { clipboard: { writeText: async () => {} } }, URL, Blob,
    fetch: async (url, options) => {
      requests.push(url);
      if (options?.body) requestBodies.push(JSON.parse(options.body));
      if (url === '/api/scenario-library') return {ok:true,json:async()=>({items:[],total:0})};
      if (url === '/api/scenarios' && options?.method === 'POST') return {ok:true,json:async()=>({id:'a'.repeat(32)})};
      if (url.endsWith('/files/target_profile.json')) return {ok:true,json:async()=>data.profiles[0].profile};
      if (url.endsWith('/files/request.json')) return {ok:true,json:async()=>({text:'Test',scope:['endpoint'],max_steps:1})};
      if (url === '/api/scenarios/'+'a'.repeat(32)) return {ok:true,json:async()=>(context.scenarioFixture || {id:'a'.repeat(32),status:'completed',yaml:'id: grounded-plan',result:{steps:1},files:[]})};
      const payload = url === '/scenario-data.json' ? data : url === '/api/meta' ?
        { token: 'fixture', allowed_networks: [], caldera_url: 'fixture', active_job: null } : [];
      return { ok: true, json: async () => payload };
    } };
  context.window = context;
  vm.createContext(context);
  const scripts = ['app.js', 'scenario-core.js', 'scenario-execution.js', 'scenario.js', ...(includeFlow ? ['flow-core.js', 'flow.js'] : [])];
  for (const file of scripts) vm.runInContext(fs.readFileSync(path.join(staticDir, file), 'utf8'), context, { filename: file });
  return { context, elements, requests, requestBodies, frames };
}

test('survey profile transfers to designer; sample preview invalidates when input changes', async () => {
  const { context, elements: e, requests } = boot();
  await new Promise(resolve => setImmediate(resolve));
  const profile = structuredClone(data.profiles[0].profile);
  context.fixtureJob = { status: 'completed', stage: 'done', progress: 100, message: '',
    logs: [], warnings: [], request: { survey_scope: ['endpoint'] }, profile, files: [], id: 'test' };
  vm.runInContext('render(fixtureJob)', context);
  assert.equal(e['transfer-profile'].disabled, false);
  await e['transfer-profile'].onclick();
  assert.equal(e['scenario-view'].hidden, false);
  assert.equal(e['selected-profile'].hidden, false);
  assert.equal(JSON.parse(e['scenario-profile-json'].textContent).id, profile.id);
  e['preview-sample'].onclick();
  assert.match(e['scenario-notice'].textContent, /Nhập yêu cầu/);
  e['scenario-request'].value = 'Kiểm tra tiến trình';
  e['scenario-request'].oninput();
  await e['preview-sample'].onclick();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(e['yaml-result'].hidden, false);
  assert.equal(e['yaml-preview'].textContent, 'id: grounded-plan');
  assert.ok(requests.includes('/api/scenarios'));
  e['scenario-request'].oninput();
  assert.equal(e['yaml-result'].hidden, true);
  e['remove-profile'].onclick();
  assert.equal(e['selected-profile'].hidden, true);
  assert.ok(requests.every(url => !url.includes('preflight')));
  assert.ok(!requests.some(url => url.includes('generate')));
});

test('library filtering, pagination, empty state and sample selection are wired', async () => {
  const { context, elements: e } = boot();
  await new Promise(resolve => setImmediate(resolve));
  e['nav-library'].onclick();
  assert.equal(e['library-view'].hidden, false);
  assert.equal(e['library-list'].children.length, 10);
  e['library-next'].onclick();
  assert.match(e['library-page'].textContent, /2/);
  e['library-filters'].children.find(button => button.dataset.family === 'dvwa').onclick();
  assert.equal(e['library-count'].textContent, '11 kịch bản');
  e['library-list'].children[0].onclick();
  assert.equal(e['library-detail'].hidden, false);
  const selectedID = e['detail-id'].textContent;
  e['use-library-sample'].onclick();
  assert.equal(e['scenario-view'].hidden, false);
  await context.ScenarioUI.useProfile(data.profiles[0].profile, 'fixture');
  assert.ok(e['scenario-request'].value.includes(selectedID));
  assert.equal(e['yaml-result'].hidden, true);
  e['library-search'].value = 'no-match-00000000'; e['library-search'].oninput();
  assert.equal(e['library-empty'].hidden, false);
  e['reset-library-filters'].onclick();
  assert.equal(e['library-empty'].hidden, true);
});

test('flow view navigation, inspector, offline mode, approval and pause are wired', async () => {
  const { context, elements: e, requests, frames } = boot(true);
  await new Promise(resolve => setImmediate(resolve));
  e['workspace-flow'].onclick();
  assert.equal(e['flow-view'].hidden, false);
  assert.equal(e['scenario-view'].hidden, true);
  assert.equal(e['flow-node-layer'].children.length, 12);
  e['flow-step'].onclick();
  assert.equal(e['flow-inspector-heading'].textContent, 'Survey Agent');
  const planner = e['flow-node-layer'].children.find(node => node.attributes['data-flow-node'] === 'planner');
  planner.listeners.click();
  e['flow-step'].onclick();
  assert.equal(e['flow-inspector-heading'].textContent, 'Scenario Agent');
  e['flow-follow'].onclick();
  assert.equal(e['flow-inspector-heading'].textContent, 'Target Profile');
  e['flow-mode'].value = 'agent_offline'; e['flow-mode'].onchange();
  e['flow-play'].onclick();
  for (let now = 0; now <= 4000 && frames.size; now += 100) {
    const pending = [...frames.entries()]; frames.clear(); pending.forEach(([, frame]) => frame(now));
  }
  assert.match(e['flow-status'].textContent, /lỗi giả lập/);
  assert.equal(frames.size, 0);
  e['flow-mode'].value = 'normal'; e['flow-mode'].onchange();
  for (let steps = 0; steps < 10 && e['flow-approval-bar'].hidden; steps++) e['flow-step'].onclick();
  assert.equal(e['flow-approval-bar'].hidden, false);
  assert.equal(e['flow-play'].disabled, true);
  e['flow-approve'].onclick();
  assert.equal(e['flow-approval-bar'].hidden, true);
  assert.ok(frames.size > 0);
  e['nav-survey'].onclick();
  assert.equal(e['flow-view'].hidden, true);
  assert.equal(frames.size, 0);
  assert.ok(requests.every(url => ['/api/meta', '/api/jobs', '/scenario-data.json', '/api/scenarios','/api/scenario-library','/api/telemetry/diagnostic'].includes(url)));
  assert.equal(context.document.body.classes.has('flow-mode'), false);
});

test('partial report stays partial with a downloadable profile and evidence-based labels', async () => {
  const { context, elements: e } = boot();
  await new Promise(resolve => setImmediate(resolve));
  const profile = structuredClone(data.profiles[0].profile);
  profile.capabilities.admin_ready = false;
  context.fixtureJob = { id: 'a'.repeat(32), status: 'completed', message: 'Historical state',
    report: { status: 'partial', mode: 'ai', model: 'gemini-3.5-flash-lite',
      failure: { stage: 'model', turn: 2, message: 'LLM HTTP 400: INVALID_ARGUMENT' } },
    profile, request: { survey_scope: ['endpoint'] }, events: [{time: null, text: 'Model lỗi tại lượt 2'}], logs: [], files: ['target_profile.json'] };
  vm.runInContext('render(fixtureJob)', context);
  assert.equal(e['run-status'].textContent, 'Kết quả một phần');
  assert.equal(e['download-profile'].attributes['aria-disabled'], 'false');
  assert.match(e['result-error'].textContent, /lượt 2/);
  assert.match(e['result-caption'].textContent, /gemini-3.5-flash-lite/);
  assert.equal(vm.runInContext("stateLabel(null,'web_reachable',{survey_scope:['endpoint']})", context), 'Ngoài phạm vi khảo sát');
  assert.equal(vm.runInContext("stateLabel(null,'wazuh_ingestion',{survey_scope:['endpoint']})", context), 'Chưa xác minh');
  assert.equal(vm.runInContext("stateLabel(false,'admin_ready',{survey_scope:['endpoint']})", context), 'Không');
});

test('a second submit is blocked while the first create request is unresolved', async () => {
  const { context, elements: e } = boot();
  await new Promise(resolve => setImmediate(resolve));
  context.document.querySelector = () => ({value: 'endpoint'});
  e['target-ip'].value = '192.168.73.130';
  vm.runInContext('validated=JSON.stringify(payload()); poll=()=>{};', context);
  let posts = 0, resolveCreate;
  context.fetch = async (url, options) => {
    if (url === '/api/jobs' && options.method === 'POST') {
      posts++;
      return new Promise(resolve => { resolveCreate = resolve; });
    }
    throw Error('Unexpected request');
  };
  const first = e['survey-form'].onsubmit({preventDefault(){}});
  await e['survey-form'].onsubmit({preventDefault(){}});
  assert.equal(posts, 1);
  resolveCreate({ok:true,json:async()=>({id:'new-run'})});
  await first;
  assert.equal(posts, 1);
});

test('legacy web profiles group services for Scenario and keep raw input intact', () => {
  const file = path.join(__dirname, 'fixtures/legacy_profile.json');
  const original = JSON.parse(fs.readFileSync(file));
  const before = JSON.stringify(original);
  const normalized = core.validateProfile(original, schema);
  assert.equal(original.services.length, 9);
  assert.equal(normalized.services.length, 4);
  assert.equal(normalized.services.at(-1).url, 'http://192.168.73.130/');
  assert.deepEqual(normalized.services.at(-1).applications.map(a => a.name), ['XAMPP', 'DVWA']);
  assert.equal(normalized.services.at(-1).applications[1].session_ready, null);
  assert.equal(JSON.stringify(original), before);
});

test('web review displays grouped apps, unknown HTTPS reason and request evidence', async () => {
  const { context, elements: e, requests } = boot();
  await new Promise(resolve => setImmediate(resolve));
  const review = path.join(__dirname, 'fixtures');
  const profile = JSON.parse(fs.readFileSync(path.join(review, 'web_target_profile.json')));
  const report = JSON.parse(fs.readFileSync(path.join(review, 'web_report.json')));
  const evidence = JSON.parse(fs.readFileSync(path.join(review, 'web_web_evidence.json')));
  context.fixtureJob = { id:'f273cfc2e7604db999778e4de0873723',status:report.status,profile,report,
    request:{survey_scope:['endpoint','web'],web_checks:['dvwa']},web_readiness:report.web_readiness,
    web_inspection:{request_count:evidence.requests.length,observation_count:evidence.observations.length,observations:evidence.observations},
    files:['target_profile.json'] };
  vm.runInContext('render(fixtureJob)', context);
  assert.equal(e['summary-services'].children.length, 4);
  const http = e['summary-services'].children[3];
  assert.equal(http.children[3].children[0].textContent, 'DVWA được nhận diện — chưa xác minh đăng nhập');
  assert.match(e['https-readiness'].textContent, /Chưa xác minh.*legacy_unknown/);
  assert.match(e['https-readiness'].className, /unknown/);
  assert.match(e['web-counts'].textContent, /11 request · 9/);
  assert.equal(e['web-requests'].children.length, 9);
  assert.ok(e['missing-information'].children.some(c => /Cần credential/.test(c.textContent)));
  assert.equal(e['download-profile'].href, '/api/jobs/f273cfc2e7604db999778e4de0873723/files/target_profile.json');
  await e['transfer-profile'].onclick();
  assert.deepEqual(JSON.parse(e['scenario-profile-json'].textContent), profile);
  assert.ok(requests.every(url => ['/api/meta','/api/jobs','/scenario-data.json','/api/scenarios','/api/scenario-library','/api/telemetry/diagnostic'].includes(url)));
});

test('HTTP-only scope is neutral; duplicate telemetry warning expands to four fields', async () => {
  const { context, elements: e } = boot();
  await new Promise(resolve => setImmediate(resolve));
  const profile = structuredClone(data.profiles[0].profile), reason='Telemetry chưa được kiểm tra';
  const missing=['process_events','network_events','web_access_logs','wazuh_ingestion'].map(field=>({field:'telemetry.'+field,status:'not_checked',reason,required:false}));
  context.fixtureJob={id:'scope-fixture',status:'completed_with_unknowns',profile,request:{survey_scope:['web'],web_checks:[]},warnings:[reason,reason,reason,reason],
    missing_information:missing,web_readiness:{https:{verified:null,status:'out_of_scope',reason:'HTTPS ngoài phạm vi khảo sát.'}}};
  vm.runInContext('render(fixtureJob)',context);
  assert.equal(e['result-warnings'].children.length,1);
  assert.equal(e['result-warnings'].children[0].tagName,'details');
  assert.equal(e['result-warnings'].children[0].children.length,5);
  assert.equal(e['missing-information'].children.length,4);
  assert.equal(e['https-readiness'].textContent,'HTTPS: Ngoài phạm vi khảo sát');
  assert.match(e['https-readiness'].className,/neutral/);
});

test('handoff bundle and cancellation are available without issuing an operation', async () => {
  const {context, elements:e, requests}=boot();
  await new Promise(resolve=>setImmediate(resolve));
  context.fixtureJob={id:'a'.repeat(32),status:'running',request:{survey_scope:['endpoint'],web_checks:[]}};
  vm.runInContext('active=fixtureJob.id; render(fixtureJob)',context);
  assert.equal(e['cancel-survey'].hidden,false);
  const originalFetch=context.fetch, posts=[];
  context.fetch=async(url,options)=>{if(options?.method==='POST')posts.push(url);return originalFetch(url,options);};
  await e['cancel-survey'].onclick();
  assert.ok(requests.includes('/api/jobs/'+'a'.repeat(32)+'/cancel'));
  context.fixtureJob={...context.fixtureJob,status:'partial',profile:structuredClone(data.profiles[0].profile),handoff:{format:'survey_handoff_v1'},metrics:{api_requests:2,model_seconds:1,rejected_calls:0,usage_complete:false,usage:[null]}};
  vm.runInContext('render(fixtureJob)',context);
  assert.equal(e['cancel-survey'].hidden,true);
  assert.equal(e['download-bundle'].hidden,false);
  assert.equal(e['download-bundle'].href,'/api/jobs/'+'a'.repeat(32)+'/bundle');
  assert.ok(e['result-warnings'].children.some(c=>c.textContent.includes('chưa đủ số liệu provider')));
  assert.deepEqual(posts,['/api/jobs/'+'a'.repeat(32)+'/cancel']);
});


test('Survey transfer sends run ID and displays API evidence time, readiness and blockers', async () => {
  const {context, elements:e, requestBodies} = boot();
  await new Promise(resolve => setImmediate(resolve));
  const run = 'b'.repeat(32);
  await context.ScenarioUI.useProfile(data.profiles[0].profile, 'Survey fixture', run);
  context.scenarioFixture = {id:'a'.repeat(32), status:'completed', yaml:'id: runtime-output', files:['context_selection.json','step_evidence.json'],
    input_source:'survey_v2', survey:{survey_run_id:run,survey_finished_at:'2020-01-01T00:00:00Z'},
    result:{steps:1,readiness:'needs_information',execution_readiness:'conditional_manual_review',detection_readiness:'not_verified',
      evidence_quality:{observations:82},blockers:['Revalidate historical survey session']}};
  e['scenario-request'].value='SQL injection';
  e['request-web'].checked=true; e['request-endpoint'].checked=false;
  await e['preview-sample'].onclick();
  await new Promise(resolve => setImmediate(resolve));
  const body=requestBodies.find(b=>b.survey_run_id);
  assert.equal(body.survey_run_id,run); assert.equal(body.profile,undefined);
  assert.match(e['scenario-run-details'].textContent,/survey_v2/);
  assert.match(e['scenario-run-details'].textContent,/2020-01-01/);
  assert.match(e['scenario-run-details'].textContent,/not_verified/);
  assert.match(e['scenario-feedback'].textContent,/Revalidate historical/);
  assert.equal(e['yaml-preview'].textContent,'id: runtime-output');
});

test('choosing a legacy profile clears the previously selected Survey run ID', async () => {
  const {context, elements:e, requestBodies}=boot();
  await new Promise(resolve=>setImmediate(resolve));
  await context.ScenarioUI.useProfile(data.profiles[0].profile,'Survey','b'.repeat(32));
  await context.ScenarioUI.useProfile(data.profiles[0].profile,'Uploaded legacy profile');
  e['scenario-request'].value='Read processes';
  await e['preview-sample'].onclick();
  const body=requestBodies.find(b=>b.text==='Read processes');
  assert.ok(body.profile); assert.equal(body.survey_run_id,undefined);
});

async function completeScenario(context,e) {
  await context.ScenarioUI.useProfile(data.profiles[0].profile,'fixture');
  e['scenario-request'].value='PowerShell sinh cmd';
  await e['preview-sample'].onclick();
  await new Promise(resolve=>setImmediate(resolve));
}

test('generated plan saves into the library and updates counts without duplicate entries', async()=>{
  const {context,elements:e}=boot();await new Promise(resolve=>setImmediate(resolve));
  await completeScenario(context,e);
  assert.equal(e['scenario-actions'].hidden,false);
  assert.equal(e['scenario-add-library'].disabled,false);
  const original=context.fetch,posts=[];
  const item={id:'generated-id',name:'Generated fixture',description:'Offline',family:'generated',scope:['endpoint'],abilities:['ability'],yaml:'id: generated-id',file:'scenario_library/test.json',request:{text:'PowerShell sinh cmd',max_steps:4},profile:data.profiles[0].profile};
  context.fetch=async(url,options)=>{
    if(url.endsWith('/library')){posts.push(url);return {ok:true,json:async()=>({status:'saved',item})};}
    if(url==='/api/scenario-library')return {ok:true,json:async()=>({items:[item],total:1})};
    return original(url,options);
  };
  await e['scenario-add-library'].onclick();
  assert.equal(posts.length,1);assert.equal(e['scenario-add-library'].disabled,true);
  assert.equal(e['scenario-add-library'].textContent,'Đã thêm vào kho');
  assert.equal(e['library-count'].textContent,'114 kịch bản');
  e['library-filters'].children.find(b=>b.dataset.family==='generated').onclick();
  assert.equal(e['library-list'].children.length,1);
  e['library-list'].children[0].onclick();e['use-library-sample'].onclick();
  assert.equal(e['scenario-request'].value,'PowerShell sinh cmd');
});

test('regenerate opens a distinct job and blocks duplicate requests while pending',async()=>{
  const {context,elements:e}=boot();await new Promise(resolve=>setImmediate(resolve));await completeScenario(context,e);
  const original=context.fetch;let posts=0,resolve;
  context.fetch=async(url,options)=>{
    if(url.endsWith('/regenerate')){posts++;return new Promise(r=>{resolve=r;});}
    if(url==='/api/scenarios/'+'b'.repeat(32))return {ok:true,json:async()=>({id:'b'.repeat(32),status:'completed',yaml:'id: regenerated',result:{steps:1},files:[]})};
    return original(url,options);
  };
  const first=e['scenario-regenerate'].onclick();
  await new Promise(r=>setImmediate(r));
  await e['scenario-regenerate'].onclick();assert.equal(posts,1);
  resolve({ok:true,json:async()=>({id:'b'.repeat(32)})});await first;
  assert.equal(e['yaml-preview'].textContent,'id: regenerated');
});

test('cancel is shown during generation and hides after the cancelled response',async()=>{
  const {context,elements:e}=boot();await new Promise(resolve=>setImmediate(resolve));
  context.scenarioFixture={id:'a'.repeat(32),status:'running',result:{},files:[]};
  await completeScenario(context,e);
  assert.equal(e['scenario-cancel'].hidden,false);assert.equal(e['scenario-delete'].hidden,true);
  assert.equal(e['scenario-add-library'].disabled,true);assert.equal(e['scenario-execute'].disabled,true);
  const original=context.fetch;
  context.fetch=async(url,options)=>{
    if(url.endsWith('/cancel')){context.scenarioFixture={id:'a'.repeat(32),status:'cancelled',result:{},files:[]};return {ok:true,json:async()=>({status:'cancelling'})};}
    return original(url,options);
  };
  await e['scenario-cancel'].onclick();
  assert.equal(e['scenario-cancel'].hidden,true);assert.equal(e['scenario-delete'].hidden,false);
  assert.equal(e['scenario-run-status'].textContent,'Đã hủy sinh kịch bản');
});

test('delete removes current preview and actions from the designer',async()=>{
  const {context,elements:e}=boot();await new Promise(resolve=>setImmediate(resolve));await completeScenario(context,e);
  const original=context.fetch;
  context.fetch=async(url,options)=>url.endsWith('/delete')?{ok:true,json:async()=>({status:'deleted'})}:original(url,options);
  await e['scenario-delete'].onclick();
  assert.equal(e['yaml-result'].hidden,true);assert.equal(e['scenario-actions'].hidden,true);
  assert.equal(e['scenario-run-status'].textContent,'Đã xóa khỏi lịch sử');
});

test('execute opens blocked preflight without claiming execution',async()=>{
  const {context,elements:e,requests}=boot();await new Promise(resolve=>setImmediate(resolve));await completeScenario(context,e);
  const original=context.fetch,posts=[];
  const record=executionFixture('blocked');record.preflight.blockers=['Agent stale'];
  context.fetch=async(url,options)=>{
    if(url.endsWith('/execute')){posts.push(url);return {ok:true,json:async()=>record};}
    return original(url,options);
  };
  await e['scenario-execute'].onclick();
  assert.equal(posts.length,1);assert.match(e['execution-blockers'].textContent,/Agent stale/);
  assert.equal(e['execution-confirm'].disabled,true);
  assert.equal(e['scenario-run-status'].textContent,'Đã tạo plan và kiểm tra grounding');
  assert.ok(!requests.some(x=>x.includes('/operations')));
});

function executionFixture(state='ready') {
  return {id:'e'.repeat(32),scenario_job_id:'a'.repeat(32),state,created_at:'2026-11-21T00:00:00Z',
    target:{host:'PTIT',ip:'192.168.1.150',paw:'datnptit'},plan_sha256:'plan-hash',operation_id:null,
    command_status:'not_run',behavior_evidence:'not_evaluated',detection:'unknown',
    preflight:{blockers:[],warnings:[],steps:[{index:1,source_ability_id:'source',executor:{name:'psh',platform:'windows'},command:'Get-Process',cleanup:[],parameters:{},registration:'matched',blockers:[]}]},
    steps:[{index:1,name:'Process discovery',state:'not_run'}]};
}

test('validate button requests preview only and waits for confirmation',async()=>{
  const {context,elements:e}=boot();
  await new Promise(resolve=>setImmediate(resolve));
  await completeScenario(context,e);
  const original=context.fetch, posts=[];
  context.setTimeout=()=>123;context.clearTimeout=()=>{};
  context.fetch=async(url,options)=>{
    if(options?.method==='POST')posts.push({url,body:JSON.parse(options.body)});
    if(url.endsWith('/execute'))return {ok:true,json:async()=>executionFixture('ready')};
    return original(url,options);
  };
  await e['scenario-execute'].onclick();
  assert.equal(posts.length,1);
  assert.ok(posts[0].url.endsWith('/execute'));
  assert.deepEqual(posts[0].body,{});
  assert.equal(e['execution-confirmation'].hidden,false);
  assert.match(e['execution-status'].textContent,/Sẵn sàng/);
});

test('execution requires explicit IP and acknowledgement; confirm polls the same execution',async()=>{
  const {context,elements:e}=boot();await new Promise(resolve=>setImmediate(resolve));await completeScenario(context,e);
  const original=context.fetch,posts=[];let poll;
  let reportUrl=null;
  context.window.open=()=>({document:{},location:{replace:url=>{reportUrl=url;}},close(){}});
  context.setTimeout=(fn)=>{poll=fn;return 999999;};context.clearTimeout=()=>{};
  context.fetch=async(url,options)=>{
    if(url.endsWith('/execute'))return {ok:true,json:async()=>executionFixture()};
    if(url.endsWith('/confirm')){posts.push(JSON.parse(options.body));return {ok:true,json:async()=>({...executionFixture('running'),operation_id:'op-fixture'})};}
    if(url==='/api/executions/'+'e'.repeat(32))return {ok:true,json:async()=>({...executionFixture('completed'),operation_id:'op-fixture',command_status:'success'})};
    return original(url,options);
  };
  await e['scenario-execute'].onclick();
  assert.equal(e['execution-confirm'].disabled,true);
  e['execution-target-confirm'].value='wrong';e['execution-ack'].checked=true;e['execution-ack'].onchange();
  assert.equal(e['execution-confirm'].disabled,true);
  e['execution-target-confirm'].value='192.168.1.150';e['execution-target-confirm'].oninput();
  assert.equal(e['execution-confirm'].disabled,false);
  await e['execution-confirm'].onclick();assert.equal(posts.length,1);
  assert.equal(reportUrl,'/report.html?execution='+'e'.repeat(32));
  assert.equal(posts[0].plan_sha256,'plan-hash');assert.equal(posts[0].confirmed,true);
  await poll();assert.equal(e['execution-status'].textContent,'Các lệnh đã hoàn tất');
  assert.match(e['execution-detection'].textContent,/Detection: unknown/);
});

test('expired preview can be replaced without confirming either preview',async()=>{
  const {context,elements:e}=boot();
  const original=context.fetch, posts=[];
  context.setTimeout=()=>123;context.clearTimeout=()=>{};
  context.fetch=async(url,options)=>{
    if(options?.method==='POST')posts.push(url);
    if(url.endsWith('/execute')){
      const record=executionFixture();
      record.preflight.policy={preview_ttl_seconds:300};
      if(posts.length===2){record.id='f'.repeat(32);record.created_at=new Date().toISOString();}
      return {ok:true,json:async()=>record};
    }
    return original(url,options);
  };
  await context.ScenarioExecutionUI.open('a'.repeat(32));
  assert.equal(e['execution-status'].textContent,'Bản xem trước đã hết hạn');
  assert.equal(e['execution-confirmation'].hidden,true);
  assert.equal(e['execution-refresh-preview'].hidden,false);
  await e['execution-confirm'].onclick();
  await e['execution-refresh-preview'].onclick();
  assert.equal(e['execution-status'].textContent,'Sẵn sàng để xác nhận');
  assert.equal(e['execution-refresh-preview'].hidden,true);
  assert.equal(e['execution-confirm'].disabled,true);
  assert.deepEqual(posts,Array(2).fill('/api/scenarios/'+'a'.repeat(32)+'/execute'));
});

test('reload restores execution with GET and never confirms automatically',async()=>{
  const {context,elements:e}=boot();await new Promise(resolve=>setImmediate(resolve));const original=context.fetch,posts=[];
  context.scenarioFixture={id:'a'.repeat(32),status:'completed',yaml:'id: fixture',result:{steps:1},files:[],execution_id:'e'.repeat(32)};
  context.fetch=async(url,options)=>{
    if(options?.method==='POST')posts.push(url);
    if(url==='/api/executions/'+'e'.repeat(32))return {ok:true,json:async()=>executionFixture('recovery_required')};
    return original(url,options);
  };
  await completeScenario(context,e);await new Promise(resolve=>setImmediate(resolve));
  assert.equal(e['execution-status'].textContent,'Cần đối soát và phục hồi');
  assert.equal(e['execution-reconcile'].hidden,false);
  assert.ok(!posts.some(x=>x.endsWith('/confirm') || x.endsWith('/execute')));
});

test('late history/result fetch cannot downgrade a newly selected Survey v2 profile',async()=>{
  const {context,elements:e,requestBodies}=boot();await new Promise(resolve=>setImmediate(resolve));
  await context.ScenarioUI.useProfile(data.profiles[0].profile,'legacy');
  const original=context.fetch;let resolve;
  context.fetch=async(url,options)=>{
    if(url==='/api/scenarios/'+'a'.repeat(32))return new Promise(r=>{resolve=r;});
    return original(url,options);
  };
  e['scenario-request'].value='Process discovery';await e['preview-sample'].onclick();
  await new Promise(r=>setImmediate(r));
  const survey='b'.repeat(32);await context.ScenarioUI.useProfile(data.profiles[0].profile,'Survey',survey);
  resolve({ok:true,json:async()=>({id:'a'.repeat(32),status:'completed',input_source:'legacy_profile',yaml:'id: old',result:{steps:1},files:[]})});
  await new Promise(r=>setImmediate(r));
  context.fetch=original;
  await e['preview-sample'].onclick();await new Promise(r=>setImmediate(r));
  assert.equal(requestBodies.at(-1).survey_run_id,survey);
  assert.equal(requestBodies.at(-1).input_kind,'survey_v2');
  assert.equal(requestBodies.at(-1).profile,undefined);
});

test('budget and provider waits display tokens and do not ask for missing user facts',async()=>{
  const {context,elements:e}=boot();await new Promise(resolve=>setImmediate(resolve));
  context.scenarioFixture={id:'a'.repeat(32),status:'waiting_budget',files:[],result:{run_id:'run',resume_phase:'build_plan',
    retry_not_before:'2000-01-01T00:00:00Z',budget_reason:'shared_window_limit',
    token_metrics:{requests:2,actual_total_tokens:null,unknown_usage_requests:2,charged_tokens:10000}}};
  await completeScenario(context,e);
  assert.match(e['scenario-run-status'].textContent,/ngân sách.*build_plan/);
  assert.match(e['scenario-feedback'].textContent,/ước lượng/);
  assert.equal(e['scenario-clarification'].hidden,true);
  assert.equal(e['scenario-resume-button'].disabled,false);
  assert.equal(e['scenario-resume'].hidden,false);
});

test('telemetry reload, refresh and exports use only telemetry endpoints and escape text',async()=>{
  const {context,elements:e}=boot();await new Promise(resolve=>setImmediate(resolve));
  const original=context.fetch,posts=[];
  context.setTimeout=()=>123;context.clearTimeout=()=>{};
  context.fetch=async(url,options)=>{
    if(options?.method==='POST')posts.push(url);
    if(url.endsWith('/telemetry/refresh'))return {ok:true,json:async()=>({status:'queued'})};
    if(url.endsWith('/telemetry'))return {ok:true,json:async()=>({collection:{status:'degraded',mode:'alerts_only',error:{code:'trusted_ca_or_credentials_unavailable'}},counts:{events:0},behavior_status:'unknown',telemetry_status:'unavailable',detection_status:'not_evaluable',limitations:['<script>untrusted</script>']})};
    if(url==='/api/executions/'+'e'.repeat(32))return {ok:true,json:async()=>executionFixture('completed')};
    return original(url,options);
  };
  await context.ScenarioExecutionUI.select({id:'telemetry-job',execution_id:'e'.repeat(32)});
  await new Promise(resolve=>setImmediate(resolve));
  assert.match(e['telemetry-summary'].textContent,/not_evaluable/);
  assert.match(e['telemetry-coverage'].textContent,/alerts_only/);
  assert.equal(e['telemetry-coverage'].children.length,0);
  assert.ok(e['telemetry-markdown'].href.endsWith('/telemetry/report.md'));
  await e['telemetry-refresh'].onclick();
  assert.deepEqual(posts,['/api/executions/'+'e'.repeat(32)+'/telemetry/refresh']);
});

test('expected reality shows N/A and unavailable without treating missing identity as zero',async()=>{
  const {context,elements:e}=boot();await new Promise(resolve=>setImmediate(resolve));
  const original=context.fetch,posts=[];
  context.fetch=async(url,options)=>{
    if(options?.method==='POST')posts.push(url);
    if(url.endsWith('/telemetry'))return {ok:true,json:async()=>({
      collection:{status:'complete',mode:'alerts_only'},behavior_status:'unknown',telemetry_status:'unknown',detection_status:'unknown',
      counts_v2:{raw_event_count:null,candidate_alert_documents:31,correlated_alert_documents:null,count_quality:'exact_within_query'},
      expected_reality:{execution_completion:{numerator:3,denominator:3,percent:100},telemetry_coverage:{numerator:0,denominator:0,percent:null,not_evaluated:3},alert_coverage:{numerator:0,denominator:0,percent:null},steps:[],techniques:{}},
      operations:{api_health:'credentials_missing'},limitations:[]})};
    if(url==='/api/executions/'+'e'.repeat(32))return {ok:true,json:async()=>executionFixture('completed')};
    return original(url,options);
  };
  await context.ScenarioExecutionUI.select({id:'comparison-job',execution_id:'e'.repeat(32)});
  await new Promise(resolve=>setImmediate(resolve));
  assert.match(e['telemetry-coverage'].textContent,/Raw events: unavailable/);
  assert.match(e['telemetry-coverage'].textContent,/Alert tương quan: unavailable/);
  assert.match(e['telemetry-metrics'].textContent,/N\/A/);
  assert.match(e['telemetry-metrics'].textContent,/3\/3/);
  assert.deepEqual(posts,[]);
});
