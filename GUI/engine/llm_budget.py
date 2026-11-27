"""Load the shared stdlib ledger, without importing Scenario model/provider code."""
import importlib.util
import sys
from pathlib import Path


def module(config):
    path=Path(config.get('scenario_root') or '/home/soc/build_scenario_agent')/'scenario_agent/token_budget.py'
    name='_soc_shared_llm_budget'
    if name not in sys.modules:
        spec=importlib.util.spec_from_file_location(name,path)
        if spec is None or spec.loader is None:raise ValueError('Shared LLM budget module unavailable.')
        value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);sys.modules[name]=value
    return sys.modules[name]
