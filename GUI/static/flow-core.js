/* A deterministic, browser-only demonstration. Never executes tools or agents. */
(function (root) {
  'use strict';
  const nodes = [
    { id: 'target', title: 'Mục tiêu khảo sát', tool: 'input.target', kind: 'input', x: 55, y: 80, duration: 800 },
    { id: 'survey', title: 'Survey Agent', tool: 'tools.get_endpoint_info', kind: 'tool', x: 335, y: 80, duration: 1800 },
    { id: 'profile', title: 'Target Profile', tool: 'profile.build', kind: 'data', x: 615, y: 80, duration: 900 },
    { id: 'dataset', title: 'Kho dataset', tool: 'dataset.retrieve', kind: 'data', x: 895, y: 80, duration: 1000 },
    { id: 'request', title: 'Yêu cầu người dùng', tool: 'input.user_request', kind: 'input', x: 335, y: 310, duration: 700 },
    { id: 'planner', title: 'Scenario Agent', tool: 'llm.plan · rag.retrieve', kind: 'agent', x: 615, y: 310, duration: 2000 },
    { id: 'validate', title: 'Kiểm tra kịch bản', tool: 'schema.validate', kind: 'tool', x: 895, y: 310, duration: 1100 },
    { id: 'yaml', title: 'Kịch bản YAML', tool: 'artifact.adversary.yml', kind: 'data', x: 895, y: 540, duration: 800 },
    { id: 'approval', title: 'Phê duyệt', tool: 'human.review', kind: 'input', x: 615, y: 540, duration: 0 },
    { id: 'caldera', title: 'CALDERA / Sandcat', tool: 'operation.dispatch', kind: 'tool', x: 335, y: 540, duration: 1700 },
    { id: 'telemetry', title: 'Thu thập telemetry', tool: 'wazuh.query · log.collect', kind: 'tool', x: 55, y: 540, duration: 1500 },
    { id: 'report', title: 'Đối chiếu & báo cáo', tool: 'evidence.correlate', kind: 'agent', x: 55, y: 310, duration: 1100 }
  ];
  const order = ['target', 'survey', 'profile', 'request', 'dataset', 'planner', 'validate', 'yaml', 'approval', 'caldera', 'telemetry', 'report'];
  const edges = [
    { from: 'target', to: 'survey', path: 'M235 122 C280 122 290 122 335 122', label: 'survey_request' },
    { from: 'survey', to: 'profile', path: 'M515 122 C560 122 570 122 615 122', label: 'raw evidence' },
    { from: 'profile', to: 'planner', path: 'M705 164 C705 220 705 254 705 310', label: 'target_profile.json' },
    { from: 'request', to: 'planner', path: 'M515 352 C560 352 570 352 615 352', label: 'user_request' },
    { from: 'dataset', to: 'planner', path: 'M985 164 C985 242 750 232 750 310', label: 'retrieved tests' },
    { from: 'planner', to: 'validate', path: 'M795 352 C840 352 850 352 895 352', label: 'plan.json' },
    { from: 'validate', to: 'yaml', path: 'M985 394 C985 450 985 484 985 540', label: 'validated plan' },
    { from: 'yaml', to: 'approval', path: 'M895 582 C850 582 840 582 795 582', label: 'adversary.yml' },
    { from: 'approval', to: 'caldera', path: 'M615 582 C570 582 560 582 515 582', label: 'approved plan' },
    { from: 'caldera', to: 'telemetry', path: 'M335 582 C290 582 280 582 235 582', label: 'execution evidence' },
    { from: 'telemetry', to: 'report', path: 'M145 540 C145 484 145 450 145 394', label: 'events + alerts' }
  ];
  const clone = value => JSON.parse(JSON.stringify(value));
  function fixtures(context = {}, mode = 'normal') {
    const profile = context.profile || { id: 'demo-windows', os: { name: 'Windows 10', status: 'simulated' }, address: '192.0.2.10', services: [], capabilities: { sandcat_online: null, powershell_ready: null }, telemetry: { wazuh_ingestion: null } };
    const abilities = (context.sample && context.sample.abilities || ['demo-discovery-ability']).slice(0, context.maxSteps || 4);
    const common = { simulation: true, run_id: 'DEMO-RUN' };
    const request = { text: context.request || 'Kiểm thử khả năng ghi nhận hành vi khám phá hệ thống.', scope: context.scope && context.scope.length ? context.scope : ['endpoint'], mode: 'plan_only' };
    const plan = { target_id: profile.id, ability_ids: abilities, source: 'demo_fixture' };
    return {
      target: { input: { target_ip: profile.address, scope: request.scope }, output: { ...common, tool_request: 'get_endpoint_info', target_ip: profile.address } },
      survey: { input: { ...common, tool: 'get_endpoint_info', transport: 'CALDERA / Sandcat' }, output: mode === 'agent_offline' ? { ...common, status: 'error', error: 'agent_offline', evidence_collected: false } : { ...common, status: 'ok', hostname: profile.os.hostname || 'DEMO-WINDOWS', os: profile.os.name, evidence_ref: 'demo/endpoint-info.json' } },
      profile: { input: { ...common, evidence_ref: 'demo/endpoint-info.json' }, output: { ...common, profile: clone(profile), note: 'Hồ sơ chỉ được sao chép để minh họa, không cập nhật kết quả khảo sát.' } },
      request: { input: { ...common, text: request.text }, output: { ...common, user_request: request } },
      dataset: { input: { ...common, platform: profile.os.name, sources: ['CALDERA', 'ART', 'custom'] }, output: { ...common, dataset_items_available: context.datasetCount || null, selected_ability_ids: abilities, retrieval: 'simulated' } },
      planner: { input: { ...common, target_profile_id: profile.id, user_request: request, retrieved_ability_ids: abilities }, output: { ...common, plan, model_call_performed: false } },
      validate: { input: { ...common, plan }, output: { ...common, schema_check: 'simulated_pass', scope_check: 'simulated_pass', lab_dependencies_verified: false } },
      yaml: { input: { ...common, plan }, output: { ...common, artifact: context.sample ? context.sample.file : 'demo/adversary.sample.yml', format: 'CALDERA adversary YAML', artifact_written: false } },
      approval: { input: { ...common, artifact: 'adversary.sample.yml' }, output: { ...common, approval: 'demo_only', authorizes_lab_execution: false } },
      caldera: { input: { ...common, dispatch: 'simulated_operation', ability_ids: abilities }, output: { ...common, execution: 'simulated', api_call_performed: false, evidence_ref: 'demo/operation-result.json' } },
      telemetry: { input: { ...common, execution_ref: 'demo/operation-result.json', sources: ['Sysmon', 'Apache', 'Wazuh'] }, output: { ...common, events: mode === 'telemetry_gap' ? null : ['demo-event-001'], alerts: mode === 'telemetry_gap' ? null : ['demo-alert-001'], observation: mode === 'telemetry_gap' ? 'insufficient_evidence' : 'simulated_evidence' } },
      report: { input: { ...common, execution_ref: 'demo/operation-result.json', telemetry_ref: 'demo/events.json' }, output: { ...common, detection_result: mode === 'telemetry_gap' ? 'not_evaluable' : 'simulated_detected', reason: mode === 'telemetry_gap' ? 'Thiếu dữ liệu quan sát; không kết luận SOC bỏ sót.' : 'Kết quả minh họa, không phải đánh giá SOC trên lab.', lab_verified: false } }
    };
  }
  class Simulation {
    constructor(context = {}, mode = 'normal') { this.reset(context, mode); }
    reset(context = this.context, mode = this.mode) {
      if (!['normal', 'agent_offline', 'telemetry_gap'].includes(mode)) throw Error('Unknown simulation mode');
      this.context = clone(context); this.mode = mode; this.data = fixtures(this.context, mode);
      this.states = Object.fromEntries(nodes.map(node => [node.id, 'idle']));
      this.index = -1; this.elapsed = 0; this.stepElapsed = 0; this.running = false;
      this.waiting = false; this.finished = false; this.failed = false; this.logs = [];
    }
    get current() { return this.index >= 0 ? order[this.index] : null; }
    get completed() { return Object.values(this.states).filter(status => ['done', 'warning'].includes(status)).length; }
    log(type, message, node = this.current) { this.logs.push({ time: this.elapsed, type, node, message }); }
    enter() {
      this.index++; this.stepElapsed = 0;
      if (this.index >= order.length) { this.index = order.length - 1; this.finished = true; this.running = false; this.log('done', 'Hoàn tất mô phỏng. Không có thao tác trên lab.'); return; }
      this.states[this.current] = this.current === 'approval' ? 'waiting' : 'active';
      this.log('start', nodes.find(node => node.id === this.current).tool + ' · mô phỏng');
      if (this.current === 'approval') { this.waiting = true; this.running = false; this.log('waiting', 'Chờ phê duyệt trong mô phỏng; không cấp quyền thực thi lab.'); }
    }
    play() {
      if (this.finished || this.failed || this.waiting) return;
      if (this.index < 0) this.enter();
      this.running = true;
    }
    pause() { this.running = false; }
    complete() {
      if (this.current === 'survey' && this.mode === 'agent_offline') {
        this.states.survey = 'error'; this.failed = true; this.running = false;
        this.log('error', 'Sandcat offline (giả lập). Dừng luồng, không tạo profile thành công giả.'); return;
      }
      const warning = this.mode === 'telemetry_gap' && ['telemetry', 'report'].includes(this.current);
      this.states[this.current] = warning ? 'warning' : 'done';
      this.log(warning ? 'warning' : 'done', warning ? 'Thiếu bằng chứng quan sát (giả lập).' : 'Chuyển dữ liệu mẫu sang bước tiếp theo.');
      this.enter();
    }
    advance(delta) {
      let left = Math.max(0, Math.min(Number(delta) || 0, 60000));
      while (left > 0 && this.running) {
        const duration = nodes.find(node => node.id === this.current).duration;
        const used = Math.min(left, duration - this.stepElapsed);
        this.stepElapsed += used; this.elapsed += used; left -= used;
        if (this.stepElapsed >= duration) this.complete();
      }
    }
    step() {
      if (this.finished || this.failed || this.waiting) return;
      if (this.index < 0) this.enter();
      const duration = nodes.find(node => node.id === this.current).duration;
      this.elapsed += Math.max(0, duration - this.stepElapsed); this.complete(); this.pause();
    }
    approve() {
      if (!this.waiting) return;
      this.waiting = false; this.states.approval = 'done'; this.log('done', 'Đã phê duyệt mô phỏng; không gọi CALDERA.'); this.enter();
    }
  }
  const exported = { nodes, edges, order, Simulation };
  if (typeof module !== 'undefined' && module.exports) module.exports = exported;
  else root.FlowCore = exported;
})(typeof globalThis !== 'undefined' ? globalThis : this);
