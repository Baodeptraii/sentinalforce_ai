const test = require('node:test');
const assert = require('node:assert/strict');
const { Simulation, nodes, edges, order } = require('../static/flow-core.js');

test('simulation stops at approval and never calls external APIs', () => {
  const simulation = new Simulation();
  simulation.play(); simulation.advance(60000);
  assert.equal(simulation.current, 'approval');
  assert.equal(simulation.waiting, true);
  assert.equal(simulation.running, false);
  assert.equal(simulation.states.caldera, 'idle');
  simulation.play(); simulation.advance(60000);
  assert.equal(simulation.states.caldera, 'idle');
  simulation.approve(); simulation.play(); simulation.advance(60000);
  assert.equal(simulation.finished, true);
  assert.equal(simulation.completed, 12);
  assert.equal(simulation.data.caldera.output.api_call_performed, false);
  assert.equal(simulation.data.planner.output.model_call_performed, false);
  assert.equal(simulation.data.report.output.lab_verified, false);
  assert.equal(simulation.data.report.output.detection_result, 'simulated_detected');
});

test('offline agent halts before a profile is marked complete', () => {
  const simulation = new Simulation({}, 'agent_offline');
  simulation.play(); simulation.advance(60000);
  assert.equal(simulation.failed, true);
  assert.equal(simulation.states.survey, 'error');
  assert.equal(simulation.states.profile, 'idle');
  assert.equal(simulation.states.caldera, 'idle');
  simulation.step(); simulation.play(); simulation.advance(60000);
  assert.equal(simulation.states.profile, 'idle');
});

test('telemetry gap produces insufficient evidence, never a missed detection claim', () => {
  const simulation = new Simulation({}, 'telemetry_gap');
  simulation.play(); simulation.advance(60000); simulation.approve(); simulation.play(); simulation.advance(60000);
  assert.equal(simulation.finished, true);
  assert.equal(simulation.states.telemetry, 'warning');
  assert.equal(simulation.data.telemetry.output.events, null);
  assert.equal(simulation.data.report.output.detection_result, 'not_evaluable');
});

test('pause freezes progress and stepping honors the approval gate', () => {
  const simulation = new Simulation();
  simulation.play(); simulation.advance(250); simulation.pause();
  simulation.advance(10000);
  assert.equal(simulation.elapsed, 250);
  simulation.step();
  assert.equal(simulation.states.target, 'done');
  assert.equal(simulation.current, 'survey');
  while (!simulation.waiting) simulation.step();
  simulation.step();
  assert.equal(simulation.current, 'approval');
  assert.equal(simulation.states.caldera, 'idle');
  simulation.reset();
  assert.equal(simulation.index, -1);
  assert.equal(simulation.logs.length, 0);
  assert.equal(simulation.elapsed, 0);
});

test('context is snapshotted and originals stay unchanged', () => {
  const context = { profile: { id: 'chosen-target', address: null, os: { name: 'Windows', status: 'unknown' } },
    request: 'Test discovery', scope: ['web'], maxSteps: 1,
    sample: { file: 'example.yml', abilities: ['ability-a', 'ability-b'] } };
  const simulation = new Simulation(context);
  context.profile.id = 'changed-after-start';
  assert.equal(simulation.data.profile.output.profile.id, 'chosen-target');
  assert.equal(simulation.data.target.input.target_ip, null);
  assert.deepEqual(simulation.data.planner.output.plan.ability_ids, ['ability-a']);
  assert.deepEqual(context.sample.abilities, ['ability-a', 'ability-b']);
  assert.equal(simulation.data.approval.output.authorizes_lab_execution, false);
});

test('graph and execution order agree; all edges connect existing nodes', () => {
  assert.equal(nodes.length, 12);
  assert.equal(new Set(order).size, nodes.length);
  assert.deepEqual([...order].sort(), nodes.map(node => node.id).sort());
  for (const edge of edges) {
    assert.ok(order.includes(edge.from) && order.includes(edge.to));
    assert.ok(order.indexOf(edge.from) < order.indexOf(edge.to));
  }
});
