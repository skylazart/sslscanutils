from unittest import TestCase

from scanutil import Report


class TestReport(TestCase):
    def test_generate_report(self):
        report = Report(host="test.com", port=443)
        report.add_finding('TLS One Enabled', 'Evidence TLS One is enabled on target host port:', 'EVIDENCE IN TXT')
        report.generate_report("output.html")
