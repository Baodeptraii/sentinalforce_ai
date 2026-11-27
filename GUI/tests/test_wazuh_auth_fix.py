import unittest
from unittest.mock import Mock
from engine.wazuh_diagnostic import parse_dashboard_record,product
from engine.wazuh_connector import Connector,ConnectorError
class AuthFixTests(unittest.TestCase):
 def test_delimiter_and_password_preserved(self):
  p=' fake / spaced !@:#  '
  r=parse_dashboard_record('Wazuh : https://192.168.100.112/ - user: admin/ pass: '+p)
  self.assertEqual('admin',r['username']);self.assertEqual(p,r['password'])
 def test_ssh_record_refused(self):
  with self.assertRaises(ValueError):parse_dashboard_record('SSH : user/password')
 def test_compatibility_version(self):
  self.assertEqual('7.10.2',product({'version':{'number':'7.10.2'},'tagline':'The OpenSearch Project: https://opensearch.org/'})['number'])
  with self.assertRaises(ConnectorError):product({'version':{'number':'7.10.2'}})
 def test_api_missing_no_network(self):
  c=object.__new__(Connector);c.credentials={'api':{},'indexer':{'username':'a','password':'b'}};c.request=Mock()
  with self.assertRaisesRegex(ConnectorError,'identity_unverified'):c.identity({'ip':'192.168.1.150'})
  c.request.assert_not_called()
