from unittest import TestCase

from sslscanutil import execute_cmd


class TestCmdExec(TestCase):
    def test_execute_cmd(self):
        result = execute_cmd('curl -m 10 -ksv http://localhost')

        request = 'Request:\n'
        response = 'Response:\n'

        if 'Operation timed out' in result:
            return

        if '< HTTP/1.1' not in result and '< HTTP/1.0' not in result:
            return

        idx_begin_request = result.find('GET /')
        if idx_begin_request < 0:
            return

        rows = result[idx_begin_request:].split('\r\n')
        request_evidence = "Request:\n\n"
        response_evidence = "Response:\n\n"

        for row in rows:
            if len(row) == 0:
                continue

            if row[0] == '>':
                request_evidence += row[2:] + '\n'
                continue

            if row[0] == '<':
                response_evidence += row[2:] + '\n'
                continue

            if row.find('GET') == 0:
                request_evidence += row + '\n'

        evidence = request_evidence + response_evidence
        print evidence
