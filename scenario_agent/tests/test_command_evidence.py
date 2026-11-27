"""PowerShell continuation evidence; these checks never execute commands."""
import unittest
from scenario_agent.command_evidence import command_fragment_evidence
from scenario_agent.catalog import connect,ability
from scenario_agent.config import Config
from scenario_agent.behaviors import validate_analysis,validate_grounding

IDENTIFIER='a1b2c3d4-dvwa-0003-cmdi-000000000003'
QUOTE='curl.exe -s -b "$CookieFile" -b "security=low" -d "ip=127.0.0.1%26%26whoami&Submit=Submit" "$DvwaUrl/vulnerabilities/exec/" | Out-Null'

class CommandEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config=Config()
        with connect(config.catalog) as db:cls.record=ability(db,IDENTIFIER)
        cls.command=next(e['command'] for e in cls.record['ability']['executors'] if e['name']=='psh' and e['platform']=='windows')

    def test_real_dvwa_one_line_quote_matches_original_multiline_source(self):
        evidence=command_fragment_evidence(self.command,QUOTE,'psh')
        self.assertEqual(evidence['method'],'powershell_explicit_continuation')
        self.assertIn('`\n',evidence['source_fragment'])
        self.assertIn(evidence['source_fragment'],self.command)

    def test_windows_line_endings_and_pwsh_are_supported(self):
        evidence=command_fragment_evidence(self.command.replace('\n','\r\n'),QUOTE,'pwsh')
        self.assertEqual(evidence['method'],'powershell_explicit_continuation')
        self.assertIn('`\r\n',evidence['source_fragment'])

    def test_literal_fragment_for_any_executor_stays_unchanged(self):
        self.assertEqual(command_fragment_evidence(self.command,'curl.exe -s','psh'),
                         {'method':'literal','source_fragment':'curl.exe -s'})

    def test_modified_payload_target_or_variable_is_rejected(self):
        for quote in (QUOTE.replace('whoami','hostname'),QUOTE.replace('security=low','security=high'),
                      QUOTE.replace('$CookieFile','$OtherCookie'),QUOTE.replace('/exec/','/sqli/'),
                      QUOTE.replace('Out-Null','Invoke-Expression')):
            with self.subTest(quote=quote):self.assertIsNone(command_fragment_evidence(self.command,quote,'psh'))

    def test_ordinary_newlines_are_not_command_continuations(self):
        self.assertIsNone(command_fragment_evidence('Get-Clipboard\nGet-Printer','Get-Clipboard Get-Printer','psh'))
        self.assertIsNone(command_fragment_evidence('curl a `\n b\nGet-Printer','curl a b Get-Printer','psh'))

    def test_quoted_spaces_and_quoted_backticks_are_not_normalized(self):
        self.assertIsNone(command_fragment_evidence('curl "a  b" `\n -s','curl "a b" -s','psh'))
        self.assertIsNone(command_fragment_evidence('curl "a `\n b"','curl "a b"','psh'))
        self.assertIsNone(command_fragment_evidence("curl 'a `\n b'","curl 'a b'",'psh'))

    def test_trailing_space_after_backtick_and_escaped_backtick_do_not_join(self):
        self.assertIsNone(command_fragment_evidence('curl -s ` \n -d data','curl -s -d data','psh'))
        self.assertIsNone(command_fragment_evidence('curl -s ``\n -d data','curl -s -d data','psh'))

    def test_comments_and_unsupported_constructs_fail_closed(self):
        self.assertIsNone(command_fragment_evidence('# curl -s `\n-d data','# curl -s -d data','psh'))
        self.assertIsNone(command_fragment_evidence("$x=@'\ntext\n'@\ncurl -s `\n -d data",'curl -s -d data','psh'))
        self.assertIsNone(command_fragment_evidence('curl --% -s `\n -d data','curl --% -s -d data','psh'))

    def test_non_powershell_executor_never_uses_the_fallback(self):
        for executor in ('cmd','sh','bash','python'):
            with self.subTest(executor=executor):self.assertIsNone(command_fragment_evidence(self.command,QUOTE,executor))

    def test_grounding_accepts_saved_dvwa_format_with_source_audit(self):
        import json
        config=Config();target=json.loads((config.root/'input/target_profile.json').read_text())
        text='Thử command injection trên DVWA.'
        analysis=validate_analysis({'ordered':False,'behaviors':[{'description':text,'source_quote':text,
            'query_en':'DVWA command injection','keywords':['injection','DVWA']}]},text)
        retrieval={'abilities':[{'record':self.record}],'adversaries':[],'behavior_candidates':{'B1':[IDENTIFIER]}}
        response={'unmodeled_requirements':[],'coverage':[{'behavior_id':'B1','reason':'Catalog HTTP probe',
            'matches':[{'ability_id':IDENTIFIER,'platform':'windows','executor':'psh','command_quote':QUOTE}]}]}
        coverage=validate_grounding(response,analysis,retrieval,target)
        self.assertEqual(coverage['coverage'][0]['matches'][0]['command_quote'],QUOTE)
        evidence=coverage['coverage'][0]['matches'][0]['evidence_match']
        self.assertEqual(evidence['method'],'powershell_explicit_continuation')
        self.assertIn(evidence['source_fragment'],self.command)

    def test_plan_contract_excludes_unreviewed_setup_and_full_reuse(self):
        import json
        from scenario_agent.behaviors import planning_view
        from scenario_agent.models import read_schema,plan_generation_schema
        config=Config()
        retrieval={'abilities':[{'record':self.record}],'adversaries':[{'record':{
            'id':'profile','ordering':['unreviewed-session-init',IDENTIFIER],'abilities':[self.record],
            'provenance':{'kind':'caldera_adversary','id':'profile','location':'test','revision':None},'reuse_eligible':True}}],
            'behavior_coverage':{'analysis':{'ordered':False,'behaviors':[{'id':'B1','description':'DVWA command injection'}]},
                'coverage':[{'behavior_id':'B1','matches':[{'ability_id':IDENTIFIER,'platform':'windows','executor':'psh'}]}]}}
        view=planning_view(retrieval)
        self.assertFalse(view['adversaries'][0]['record']['reuse_eligible'])
        self.assertTrue(view['adversaries'][0]['record']['adaptation_required'])
        bound=plan_generation_schema(read_schema(config.root,'plan'),{'id':'plan','request_id':'request','target_id':'target'},view)
        self.assertEqual(bound['properties']['atomic_ordering']['items']['enum'],[IDENTIFIER])
        self.assertNotIn('reuse_adversary',bound['properties']['metadata']['properties']['selection']['properties']['strategy']['enum'])
