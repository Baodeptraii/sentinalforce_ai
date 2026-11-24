"""GUI Survey/Scenario coordination with mock wire IO only."""
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock,patch
from engine.llm import ChatClient,LLMError
from engine.llm_budget import module


class SharedBudgetTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        env=patch.dict('os.environ',{'SOC_LLM_BUDGET_DB':str(self.root/'budget.sqlite'),'SURVEY_LLM_MODEL':'shared-model',
            'SURVEY_LLM_BASE_URL':'http://127.0.0.1/v1','SURVEY_LLM_API_KEY':'fake-fixture-secret'})
        env.start();self.addCleanup(env.stop)
        self.config={'llm':{'base_url':'http://127.0.0.1/v1','model':'shared-model'}}
    def test_scenario_inflight_prevents_survey_call_in_same_window(self):
        with patch.dict('os.environ',{'SOC_LLM_WINDOW_REQUESTS':'1'}):
            module(self.config).Ledger().reserve('shared-model','scenario:other','parse','source',100,20)
            client=ChatClient(self.config);client.opener=Mock();client.bind_budget('survey-test',self.root/'token_metrics.json')
            with self.assertRaises(LLMError) as error:client.choose([{'role':'user','content':'test'}],[])
            self.assertEqual(error.exception.budget_reason,'shared_window_limit');client.opener.open.assert_not_called()
    def test_actual_usage_and_cached_reasoning_are_kept_without_prompt_or_key(self):
        client=ChatClient(self.config);client.bind_budget('test',self.root/'token_metrics.json')
        response={'choices':[{'message':{'role':'assistant','tool_calls':[]},'finish_reason':'stop'}],
            'usage':{'prompt_tokens':100,'completion_tokens':20,'total_tokens':120,'prompt_tokens_details':{'cached_tokens':30},'completion_tokens_details':{'reasoning_tokens':5}}}
        client.opener=Mock();client.opener.open.return_value=io.BytesIO(json.dumps(response).encode())
        secret='sensitive-input-do-not-log'
        self.assertIsNone(client.choose([{'role':'user','content':secret}],[]))
        raw=(self.root/'token_metrics.json').read_text();self.assertNotIn(secret,raw);self.assertNotIn('fake-fixture-secret',raw)
        metrics=json.loads(raw);usage=metrics['calls'][0]['usage']
        self.assertEqual(metrics['actual_total_tokens'],120);self.assertEqual(usage['cached_tokens'],30);self.assertEqual(usage['thinking_tokens'],5)
    def test_duplicate_same_survey_message_does_not_send_again(self):
        client=ChatClient(self.config)
        response={'choices':[{'message':{'role':'assistant','tool_calls':[]},'finish_reason':'stop'}]}
        client.opener=Mock();client.opener.open.return_value=io.BytesIO(json.dumps(response).encode())
        client.choose([{'role':'user','content':'test'}],[])
        with self.assertRaises(LLMError):client.choose([{'role':'user','content':'test'}],[])
        self.assertEqual(client.opener.open.call_count,1)

if __name__=='__main__':unittest.main()
