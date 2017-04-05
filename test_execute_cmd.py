from unittest import TestCase

from scanutil import execute_cmd


class TestExecute_cmd(TestCase):
    def test_execute_cmd(self):
        title, evidence = execute_cmd('Testing',
                                      'ssh root@kali openssl s_client -tls1 -connect target:443')
        if 'RENEGOTIATING' not in evidence:
            self.fail()
        if 'error:num=19:self signed certificate in certificate chain' not in evidence:
            self.failt()
