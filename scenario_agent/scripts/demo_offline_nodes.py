"""Exercise the six real node functions with an explicitly simulated LLM.

This diagnostic does not use LangGraph and does not call Gemini or E5.
"""
import copy
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scenario_agent.config import Config, ROOT
from scenario_agent.catalog import ability, connect
from scenario_agent.workflow import Workflow, new_state
from tests.test_scenario_agent import ABILITY, fixture_plan, fixture_request

def main():
    config = Config()
    config.runs = ROOT / 'outputs/offline_fixture'
    state = new_state(config, 'Windows endpoint T1033 user discovery, 1 test. ' + ABILITY,
                      ROOT / 'input/target_profile.json', 'keyword')
    with connect(config.catalog) as db:
        record = ability(db, ABILITY)
    class FixtureLLM:
        def generate(self, instruction, data, schema):
            return fixture_request(state) if 'request' not in data else fixture_plan(state, record)
    flow = Workflow(config, FixtureLLM())
    print('OFFLINE FIXTURE: simulated LLM + keyword retrieval; node functions only.')
    print('NO Gemini call; NO E5/FAISS; NO LangGraph execution; NO CALDERA execution.')
    for _ in range(16):
        node = state['next']
        if node == 'END':
            break
        state = flow.step(node, state)
        print(f"{node} -> {state['next']} | status={state['status']}")
    print('output=' + str(state.get('output')))
    print('plan_readiness=' + str(state.get('plan', {}).get('metadata', {}).get('readiness')))
    return 0 if state['status'] == 'completed' else 1

if __name__ == '__main__':
    raise SystemExit(main())
