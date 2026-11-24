(function () {
  'use strict';
  const el = id => document.getElementById(id);
  const { nodes, edges, Simulation } = window.FlowCore;
  const colors = { input: '#e4ad4d', tool: '#22c8b1', agent: '#a37af5', data: '#719aff' };
  const statuses = { idle: 'Chưa chạy', active: 'Đang xử lý', done: 'Hoàn tất mô phỏng', waiting: 'Chờ duyệt', warning: 'Thiếu bằng chứng', error: 'Lỗi giả lập' };
  const kinds = { input: 'INPUT', tool: 'TOOL', agent: 'AGENT', data: 'DATA' };
  const svg = el('flow-map');
  let engine = new Simulation(), selected = 'target', follow = true, visible = !el('flow-view').hidden;
  let frameId = null, lastFrame = null, lastClock = 0, signature = '', logCount = -1;
  let zoom = 1, panX = 0, panY = 0, drag = null;
  const nodeElements = {}, edgeElements = [];
  const motionReduced = window.matchMedia('(prefers-reduced-motion: reduce)');

  function svgNode(tag, attrs = {}, text) {
    const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value));
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function drawGraph() {
    for (const edge of edges) {
      const color = colors[nodes.find(node => node.id === edge.to).kind];
      const group = svgNode('g', { class: 'flow-edge', 'data-state': 'idle' });
      const path = svgNode('path', { d: edge.path, stroke: color });
      group.append(svgNode('title', {}, edge.label), svgNode('path', { d: edge.path, class: 'flow-edge-track' }), path);
      el('flow-edge-layer').append(group);
      const packets = [0, 1].map(() => {
        const packet = svgNode('circle', { r: 4.1, fill: color, class: 'flow-packet', visibility: 'hidden' });
        el('flow-packet-layer').append(packet); return packet;
      });
      edgeElements.push({ ...edge, group, path, packets });
    }
    for (const node of nodes) {
      const group = svgNode('g', { transform: `translate(${node.x} ${node.y})`, class: 'flow-node',
        role: 'button', tabindex: '0', 'data-flow-node': node.id, 'data-kind': node.kind,
        'aria-label': node.title + ' — chọn xem dữ liệu' });
      group.append(svgNode('title', {}, node.title + ' · ' + node.tool),
        svgNode('rect', { x: 0, y: 0, width: 180, height: 84, rx: 10, class: 'flow-node-face' }),
        svgNode('path', { d: 'M10 1 H170', stroke: colors[node.kind], class: 'flow-node-accent' }),
        svgNode('rect', { x: 13, y: 17, width: 23, height: 23, rx: 6, fill: colors[node.kind], class: 'flow-node-icon-bg' }),
        svgNode('text', { x: 24.5, y: 33, fill: colors[node.kind], class: 'flow-node-icon' }, { input: '↳', tool: '⌘', data: '{}', agent: '✦' }[node.kind]),
        svgNode('text', { x: 45, y: 32, class: 'flow-node-title' }, node.title),
        svgNode('text', { x: 14, y: 53, class: 'flow-node-subtitle' }, node.tool),
        svgNode('circle', { cx: 16, cy: 69, r: 2.5, class: 'flow-state-dot' }));
      const state = svgNode('text', { x: 25, y: 72, class: 'flow-node-state' }, statuses.idle);
      group.append(state);
      for (const [cx, cy] of [[0, 42], [180, 42], [90, 0], [90, 84]]) group.append(svgNode('circle', { cx, cy, r: 3.5, class: 'flow-port' }));
      const select = () => { selected = node.id; follow = false; sync(true); };
      group.addEventListener('click', select);
      group.addEventListener('keydown', event => { if (['Enter', ' '].includes(event.key)) { event.preventDefault(); select(); } });
      el('flow-node-layer').append(group); nodeElements[node.id] = { group, state };
    }
  }
  function context() {
    return window.ScenarioUI && window.ScenarioUI.getFlowContext ? window.ScenarioUI.getFlowContext() : {};
  }
  function reset() {
    stopFrames(); engine.reset(context(), el('flow-mode').value); selected = 'target'; follow = true;
    signature = ''; logCount = -1; sync(true); updatePackets();
    el('flow-context-label').textContent = engine.context.profile ? 'Minh họa với hồ sơ đang chọn · không tác động dữ liệu gốc' : 'Sử dụng dữ liệu minh họa';
  }
  function renderInspector() {
    const node = nodes.find(node => node.id === selected), state = engine.states[selected];
    el('flow-inspector-heading').textContent = node.title;
    el('flow-inspector-tool').textContent = node.tool;
    el('flow-node-kind').textContent = kinds[node.kind];
    el('flow-node-kind').setAttribute('data-kind', node.kind);
    el('flow-node-status').textContent = statuses[state];
    el('flow-node-status').setAttribute('data-state', state);
    el('flow-follow').textContent = follow ? 'Đang theo dõi luồng' : 'Theo dõi luồng →';
    el('flow-follow').setAttribute('aria-pressed', String(follow));
    el('flow-inspector-note').textContent = state === 'idle' ? 'Bước chưa chạy. Input/output bên dưới là dữ liệu mẫu dự kiến.' :
      state === 'waiting' ? 'Luồng dừng để bạn duyệt. Phê duyệt tại đây chỉ có hiệu lực trong mô phỏng.' :
      state === 'error' ? 'Mô phỏng lỗi agent. Các bước sau giữ nguyên trạng thái chưa chạy.' :
      state === 'warning' ? 'Thiếu telemetry trong mô phỏng; không đủ cơ sở kết luận SOC bỏ sót.' :
      'Dữ liệu minh họa được truyền giữa các thành phần; không có tool hoặc model thực được gọi.';
    el('flow-input').textContent = JSON.stringify(engine.data[selected].input, null, 2);
    el('flow-output').textContent = JSON.stringify(engine.data[selected].output, null, 2);
    el('flow-output-label').textContent = ['done', 'warning', 'error'].includes(state) ? 'Kết quả mô phỏng' : 'Mẫu dự kiến';
  }
  function renderLogs() {
    if (logCount === engine.logs.length) return;
    logCount = engine.logs.length;
    el('flow-log-count').textContent = logCount + ' sự kiện';
    if (!logCount) {
      const text = document.createElement('p'); text.textContent = 'Chờ bắt đầu. Mỗi lần chuyển dữ liệu sẽ xuất hiện tại đây.';
      el('flow-log').replaceChildren(text); return;
    }
    const entries = engine.logs.map(entry => {
      const row = document.createElement('div'); row.className = 'flow-log-row'; row.setAttribute('data-type', entry.type);
      const time = document.createElement('time'); time.textContent = (entry.time / 1000).toFixed(2).padStart(6, '0') + 's';
      const source = document.createElement('span'); source.textContent = entry.node;
      const message = document.createElement('span'); message.textContent = entry.message;
      row.append(time, source, message); return row;
    });
    el('flow-log').replaceChildren(...entries); el('flow-log').scrollTop = el('flow-log').scrollHeight;
  }
  function sync(force = false) {
    const next = JSON.stringify([engine.states, engine.running, engine.current, selected, follow, engine.logs.length]);
    if (!force && next === signature) return;
    signature = next;
    if (follow && engine.current) selected = engine.current;
    for (const node of nodes) {
      const { group, state } = nodeElements[node.id];
      group.setAttribute('data-state', engine.states[node.id]);
      group.setAttribute('aria-pressed', String(selected === node.id));
      group.setAttribute('aria-label', node.title + ' — ' + statuses[engine.states[node.id]]);
      state.textContent = statuses[engine.states[node.id]];
    }
    for (const edge of edgeElements) {
      const state = engine.states[edge.to], source = engine.states[edge.from];
      edge.group.setAttribute('data-state', state === 'error' ? 'error' :
        ['active', 'waiting'].includes(state) && ['done', 'warning'].includes(source) ? 'active' :
        ['done', 'warning'].includes(state) && ['done', 'warning'].includes(source) ? 'done' : 'idle');
    }
    el('flow-view').setAttribute('data-running', String(engine.running));
    el('flow-play').textContent = engine.running ? 'Ⅱ Tạm dừng' : engine.waiting ? 'Chờ duyệt mô phỏng' :
      engine.finished || engine.failed ? '↺ Chạy lại' : engine.index >= 0 ? '▶ Tiếp tục' : '▶ Chạy mô phỏng';
    el('flow-play').disabled = engine.waiting;
    el('flow-step').disabled = engine.running || engine.waiting || engine.finished || engine.failed;
    el('flow-approval-bar').hidden = !engine.waiting;
    el('flow-completed').textContent = engine.completed + ' / ' + nodes.length;
    el('flow-packets').textContent = edges.filter(edge => ['done', 'warning'].includes(engine.states[edge.from]) && engine.states[edge.to] !== 'idle').length;
    el('flow-status').textContent = engine.failed ? 'Đã dừng · lỗi giả lập' : engine.finished ? 'Hoàn tất mô phỏng' :
      engine.waiting ? 'Chờ phê duyệt mô phỏng' : engine.running ? 'Đang mô phỏng · ' + nodes.find(node => node.id === engine.current).title :
      engine.index >= 0 ? 'Đã tạm dừng' : 'Sẵn sàng mô phỏng';
    el('flow-status').setAttribute('data-state', engine.failed ? 'error' : engine.waiting ? 'waiting' : engine.running ? 'active' : 'idle');
    el('flow-time').textContent = (engine.elapsed / 1000).toFixed(1) + 's';
    renderInspector(); renderLogs();
  }
  function updatePackets() {
    for (const edge of edgeElements) {
      const active = edge.group.getAttribute('data-state') === 'active';
      for (let i = 0; i < edge.packets.length; i++) {
        const packet = edge.packets[i]; packet.setAttribute('visibility', active && !motionReduced.matches ? 'visible' : 'hidden');
        if (active && !motionReduced.matches) {
          const progress = ((engine.elapsed / 1450) + i / 2) % 1;
          const point = edge.path.getPointAtLength(edge.path.getTotalLength() * progress);
          packet.setAttribute('cx', point.x); packet.setAttribute('cy', point.y);
        }
      }
    }
  }
  function stopFrames() {
    if (frameId !== null) window.cancelAnimationFrame(frameId);
    frameId = null; lastFrame = null;
  }
  function frame(now) {
    frameId = null;
    if (!visible || !engine.running) return;
    const delta = lastFrame === null ? 0 : Math.min(100, Math.max(0, now - lastFrame));
    lastFrame = now; engine.advance(delta * Number(el('flow-speed').value)); sync(); updatePackets();
    if (now - lastClock > 100) { el('flow-time').textContent = (engine.elapsed / 1000).toFixed(1) + 's'; lastClock = now; }
    if (engine.running) frameId = window.requestAnimationFrame(frame); else lastFrame = null;
  }
  function startFrames() { if (visible && frameId === null && engine.running) { lastFrame = null; frameId = window.requestAnimationFrame(frame); } }
  function onViewChange(view) {
    visible = view === 'flow';
    if (!visible) {
      engine.pause(); stopFrames();
      el('flow-expand').textContent = 'Mở rộng ↗'; el('flow-expand').setAttribute('aria-pressed', 'false');
    }
    sync(true);
  }
  function updateViewBox() {
    svg.setAttribute('viewBox', `${panX} ${panY} ${1140 / zoom} ${680 / zoom}`);
    el('flow-zoom-label').textContent = Math.round(zoom * 100) + '%';
  }
  function changeZoom(delta) {
    const next = Math.min(1.8, Math.max(.65, Math.round((zoom + delta) * 100) / 100));
    panX += (1140 / zoom - 1140 / next) / 2; panY += (680 / zoom - 680 / next) / 2; zoom = next; updateViewBox();
  }
  drawGraph(); sync(true);
  el('flow-play').onclick = () => {
    if (engine.running) { engine.pause(); stopFrames(); }
    else { if (engine.finished || engine.failed || engine.index < 0) reset(); engine.play(); startFrames(); }
    sync(true);
  };
  el('flow-step').onclick = () => { if (engine.index < 0) reset(); engine.step(); sync(true); updatePackets(); };
  el('flow-reset').onclick = reset;
  el('flow-mode').onchange = reset;
  el('flow-approve').onclick = () => { engine.approve(); engine.play(); sync(true); updatePackets(); startFrames(); };
  el('flow-follow').onclick = () => { follow = !follow; sync(true); };
  el('flow-zoom-in').onclick = () => changeZoom(.15);
  el('flow-zoom-out').onclick = () => changeZoom(-.15);
  el('flow-fit').onclick = () => { zoom = 1; panX = 0; panY = 0; updateViewBox(); };
  el('flow-expand').onclick = () => {
    const expanded = document.body.classList.toggle('flow-expanded');
    el('flow-expand').textContent = expanded ? 'Thu gọn ↙' : 'Mở rộng ↗';
    el('flow-expand').setAttribute('aria-pressed', String(expanded));
  };
  svg.addEventListener('pointerdown', event => {
    if (event.button !== 0 || event.target.closest('[data-flow-node]')) return;
    const rect = svg.getBoundingClientRect();
    drag = { x: event.clientX, y: event.clientY, startX: panX, startY: panY, width: rect.width, height: rect.height };
    svg.setPointerCapture(event.pointerId); svg.classList.add('dragging');
  });
  svg.addEventListener('pointermove', event => {
    if (!drag) return;
    panX = drag.startX - (event.clientX - drag.x) * (1140 / zoom) / drag.width;
    panY = drag.startY - (event.clientY - drag.y) * (680 / zoom) / drag.height; updateViewBox();
  });
  for (const name of ['pointerup', 'pointercancel', 'lostpointercapture']) svg.addEventListener(name, () => { drag = null; svg.classList.remove('dragging'); });
  svg.addEventListener('wheel', event => { if (event.ctrlKey) { event.preventDefault(); changeZoom(event.deltaY < 0 ? .1 : -.1); } }, { passive: false });
  document.addEventListener('visibilitychange', () => { if (document.hidden) { engine.pause(); stopFrames(); sync(true); } });
  window.addEventListener('pagehide', () => { engine.pause(); stopFrames(); });
  window.FlowUI = { onViewChange };
})();
