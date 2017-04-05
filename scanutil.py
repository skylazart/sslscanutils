#!/usr/bin/env python


from optparse import OptionParser
import sys
from subprocess import Popen, PIPE
import string
from StringIO import StringIO
import gzip
import base64
import uuid

SSL_SCAN_COMMAND = "sslscan {host}:{port}"


class Finding:
    def __init__(self, short_desc, desc, evidence_content):
        """
        :type short_desc str
        :type desc str
        :type evidence_content str

        :param short_desc: Short description
        :param desc: Long description
        :param evidence_content:  Evidence content (going to be saved in a temp file)
        """
        self.id = uuid.uuid1()
        self.short_desc = short_desc
        self.desc = desc
        self.evidence_content = evidence_content


class Report:
    # Variable containing the HTML report layout compressed and encoded in base64
    HTML_REPORT = 'H4sIAKcc5FgAA5VWW5OaShB+91dwfElSlRNZXbNrolYJroAXXK8IL6kZIDA6XCKDiqn899MDi7onlZMcX5Dp6Z6vv/66mfZf/' \
                  'am8NJ+fBJ8FtFtp84dAUeh1qm5Y5QsucroVAX7twGVIsH20T1zWqa6Wg78fqy8mRhh1uwsbhcLeTVLKknatWCvslIQ7sNBONW' \
                  'EZdRPfdVlVYFnsdqrMPbGanSTVfGvx8/fu107VQQx9Ks2fMUrcj/fvR0R6MIPW/Xijx25AU+scefCeWco6GxvDg6uKI3jfuQv' \
                  'pwQpaqSPfBaZxF2N191GTh4ZGjh42Wilu6EfT0Ok0kwJcb4pFvNVHrf+U2ar38HUWjcZZ5K0a8yZWVp6j+FRT575Jet/Gx3iH' \
                  'NmbqKAOiqclIk3ueplgJrg/EKZESy7DE6THy+HqJbUp6J4jr2fVWgoyZp9X1rXkufYe+WWehHbTucDBjJuzBDQ3w6sHEME/W9' \
                  'ulBJrBPlhrImIuoH3mTbY+WZ2CDpuONE1vqPIJzsom8KvdHlkFDpM54Xsd8PRRHMnn8pg100TVOPKfIWkjE2cxF4OGsKTS163' \
                  'QHayLK84Yc5eggB/PYIU3RNDTPDNeio7TSa+7z2G5IibkBjpUh8KDvr/kPtqjuZLixTi35bovrp4O9jTxkNCNrM4ydfhlDP2C' \
                  'lBTxJBCvgU3KjSr4F8XFg5zlwDidL6+iWfuol79Okf+XkyruUQl5XrhprEUOO1jLyMOjDWpZx5tRVgXvjFFv1e8jjRK1wVvK4' \
                  'dTbDc14TVToAdtHaaKVNtIMB50xEoCvAcRxv9XN53osGz2gTU45RV6X76TFuyV50AC33kTJIrfrqXzxJBU9EOljktjbAueIfn' \
                  'GCd/aom0+DFrv5WWztLmV318KRnljEQoe4+JpJvNiB2sDqYjXVmB2vIoUdyLSjDO0edHzCBM+sn325MvBF5HFkKrY9D3h8l3v' \
                  'sU+ktEG4v+AZatWZ/8SptFfnXgUclxQP9Fee9d16SyFgFoyHegP7CyDi7aeqUh6ejKoJWQ1+F/9OhVZ43f9xfPe54A9iuu1zO' \
                  'mzmcM7O3wIVsrpmwbR04Gj8Tek5gJyd6+nYFbdECFpRyFVrhOeZmAapC1RPFOjx11B21liWOQEEBoLoMBsxY7z31J1QkGmabs' \
                  'knyUBdBy4ZzicPbyfgKK2EW6rynutaDNuRyYBfIfBw51ntYw6u7Af36ehbQPbXu2xaaPjVWkha/ik9HyMiZB1r0ILSBev/cAW' \
                  'LxnmZd4uOUUFbFPFAcOjLnEQ4tkP7rQ2PsZ14DFm0Xz7KgU6G7CWNaPgKOp9UVPC5oHHKxImQ+M9Is/HwEIpPu8kHYwru6wwX' \
                  'NshtZmPgDp5Dna4rA5yyWuT+ETQkfykOMEaTT3dqbFNy0O7ejH/MxJjrn3eMvnn+RT4NExWoupeXMmj/lf9nE4pLZygrYCzq9' \
                  'tS8bQrhrZlfJrvTx/mSvUb2jJ/q1mUrv49KXQ2md+hstrJg8BS2uLssv4o044Sy9jYjD3ba4Nubm90YM3OkM9bvAVI7DTqVS7' \
                  '7Voh626l0o4F4sCVgF8dqq/uEwLyEAkTJrRx97sfJexHu4bBNYZ+cchBsClKEvBEuLyT4JSxKLwx8EtIUhWi0KbE3nWqUeyGM' \
                  'mHZW/fghuy98GaJ9p7L3ryr5iAc9yuCk6cxvwgVJjgyD1qc8F1aLZdT/cviSV5qU33xAxoZoPA0OCIeo3Cr3oCwo5DBaSVIv3' \
                  'EJDX+LtbirQn6fhDLN+LL+HO35egyPV+s9xyGMRCGiAgm/RvsA8TfYiS6GL9xQOJUov/e19Q34cu50K7WaoLhMYL4ruNQNAK5' \
                  'wJMz/iRUBhY6QkwmkCoRVnMhO+fYPkNBT4SllmvP2lde7D7nL23efK7eVr70Mv1p+E/0Hk8W+hpkKAAA='

    BUTTON_FORMAT = """<button class="tablinks" onclick="openCity(event, '{id}')">{short_desc}</button>"""
    DIV_FORMAT = """<div id="{id}" class="tabcontent"><h3>{short_desc}</h3><p>{desc}</p><p>{evidence}</p></div>"""

    def __init__(self, host, port):
        self._host = host
        self._port = port
        self._finding_list = []

    def add_finding(self, short_desc, desc, evidence_content):
        finding = Finding(short_desc, desc, evidence_content.replace('\n', '<br>\n'))
        self._finding_list.append(finding)

    def generate_report(self, filename):
        html_report = gzip.GzipFile(fileobj=StringIO(base64.decodestring(self.HTML_REPORT))).read()

        buttons = ''
        divs = ''

        for finding in self._finding_list:
            buttons += self.BUTTON_FORMAT.format(id=finding.id, short_desc=finding.short_desc) + "\n"
            divs += self.DIV_FORMAT.format(id=finding.id, short_desc=finding.short_desc, desc=finding.desc,
                                           evidence=finding.evidence_content) + "\n"

        report = html_report.format(host=self._host, port=self._port, additional_info='Port 80 found',
                                    BUTTON_SECTIONS=buttons, DIV_SECTIONS=divs)
        f = open(filename, 'w')
        f.write(report)
        f.close()


def execute_cmd(title, cmd, renegotiate='R\n'):
    # type: (str, str, str) -> tuple
    print "####-> %s" % title
    print "sending command %s" % cmd

    f = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    result = f.communicate('R\n')
    return title, cmd + "\n" + ''.join(result).replace("Kali GNU/Linux 1.0.9\n", '')


class SSLEvidenceExecutor:
    def __init__(self, params, options, result, verified):
        """
        :type params dict
        :type result list
        :type verified dict

        :param params: Dictionary containing the key/value pairs to compose the sslscan command
        :param options: Command line arguments
        :param result: Output result of sslscan
        :param verified: Dictionary containing the vulnerabilities found
        """

        self._params = params
        self._options = options
        self._result = result
        self._check = verified
        self._report = Report(host=self._params['host'], port=self._params['port'])
        self._report.add_finding('SSLScan output', 'SSLScan output', '\n'.join(result))

    def verify(self):
        self._verify()

    def _verify(self):
        if self._check['tls10']:
            self._test_tls1()

        if self._check['tls10weakcipher']:
            self._test_weak_cipher("tls1", self._check['tls10weakcipher_list'])

        if self._check['tls11weakcipher']:
            self._test_weak_cipher("tls1_1", self._check['tls11weakcipher_list'])

        if self._check['tls12weakcipher']:
            self._test_weak_cipher("tls1_2", self._check['tls12weakcipher_list'])

        self._test_renegotiation_self_signed()

        self._report.generate_report('output.html')

    def _test_tls1(self):
        cmd_template = self._create_cmd("openssl s_client -tls1 -connect {host}:{port}")
        title, evidence = execute_cmd("Evidence TLS1.0 is enabled on {host} port {port}:".format(**self._params),
                                      cmd_template)

        self._report.add_finding("TLS One Enabled", title, evidence)

    def _test_weak_cipher(self, tls, ciphers):
        """
        :type tls str
        :type ciphers set
        :param tls: TLS version
        :param ciphers: set containing the list of weak ciphers
        :return: None
        """

        for cipher in ciphers:
            cmd_template = self._create_cmd("openssl s_client -%s -cipher '%s' -connect {host}:{port}" % (tls, cipher))
            title = "Evidence using weak cipher %s (%s) on {host} port {port}:" % (tls, cipher)
            title, evidence = execute_cmd(title.format(**self._params),
                                          cmd_template)
            self._report.add_finding("Weak Cipher %s %s" % (tls, cipher), title, evidence)

    def _create_cmd(self, cmd):
        """
        :type cmd str
        :param cmd: OpenSSL command
        :return: Command string including the ssh command when necessary
        """

        if self._options.ssh is not None:
            cmd = "%s %s" % (self._options.ssh, cmd)

        return cmd.format(**self._params)

    def _test_renegotiation_self_signed(self):
        cmd_template = self._create_cmd("openssl s_client -connect {host}:{port}")
        title = "Testing if secure renegotiation is supported on {host} port {port}:"

        title, result = execute_cmd(title.format(**self._params), cmd_template)

        idx = result.find('RENEGOTIATING')
        if idx > 0 and result.find('handshake failure', idx, len(result)) < 0 and result.find('verify return:0', idx,
                                                                                              len(result)) > 0:
            self._report.add_finding("Secure Renegotiation Supported",
                                     "Evidence showing the secure renegotiation supported on {host} port {port}:"
                                     .format(**self._params), result)

            if 'Verify return code: 19 (self signed certificate in certificate chain)' in result:
                self._report.add_finding("Self Signed Certificate",
                                         "Evidence demonstrating a self signed certificate on {host} port {port}:".
                                         format(**self._params), result)


def run_ssl_scan(params, options):
    """
    :type params dict
    :param params: Dictionary containing the key/value pairs to compose the sslscan command
    :param options: Command line arguments
    :return: output string
    """

    if options.ssh is not None:
        cmd_template = "%s %s" % (options.ssh, SSL_SCAN_COMMAND)
    else:
        cmd_template = SSL_SCAN_COMMAND

    cmd = cmd_template.format(**params)

    f = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE, stdin=PIPE)
    result = f.stdout.readlines()

    return result


def filter_result(result):
    """
    :type result list
    :param result: List containing the output lines of sslscan
    :return: filtered result (for nonprintable characters and color formatting strings
    """

    result = map(lambda s: filter(lambda x: x in string.printable,
                                  s.replace('[32m128[0m', '')
                                  .replace('[1;34m', '')
                                  .replace('[32m', '')
                                  .replace('[33m', '')
                                  .replace('[0m', '')
                                  .strip()), result)
    return result


def generate_evidences(params, options, result, verified):
    """
    :type params dict
    :type result list
    :type verified dict

    :param params: Dictionary containing the key/value pairs to compose the sslscan command
    :param options: Command line arguments
    :param result: Output result of sslscan
    :param verified: Dictionary containing the vulnerabilities found
    :return: None
    """

    f = SSLEvidenceExecutor(params=params, options=options, result=result, verified=verified)
    f.verify()


def parse_result(params, options, result):
    """
    :type params dict
    :type result list
    :param params: Dictionary containing the key/value pairs to compose the sslscan command
    :param options: Command line arguments
    :param result: Output result of sslscan
    :return: Dictionary containing the vulnerabilities
    """

    verified = dict(tls10=False,
                    sslv3=False,
                    tls10weakcipher=False,
                    tls11weakcipher=False,
                    tls12weakcipher=False,
                    tls10heartbleed=False,
                    tls11heartbleed=False,
                    tls12heartbleed=False,
                    tls10weakcipher_list=set(),
                    tls11weakcipher_list=set(),
                    tls12weakcipher_list=set())

    for l in result:
        l = ' '.join(l.split())

        if 'Accepted' in l:
            # Line format: Accepted TLSv1.0 128 bits ECDHE-RSA-AES128-SHA
            splited = l.split()

            if splited[3] == 'bits' and int(splited[2]) < 128:
                if 'TLSv1.0' in splited[1]:
                    verified['tls10weakcipher'] = True
                    # Saving the cipher name
                    verified['tls10weakcipher_list'].add(splited[4])

                if 'TLSv1.1' in splited[1]:
                    verified['tls11weakcipher'] = True
                    # Saving the cipher name
                    verified['tls11weakcipher_list'].add(splited[4])

                if 'TLSv1.2' in splited[1]:
                    verified['tls12weakcipher'] = True
                    # Saving the cipher name
                    verified['tls12weakcipher_list'].add(splited[4])

            if 'TLSv1.0' in l:
                verified['tls10'] = True

        if 'heartbleed' in l:
            if 'not' not in l and 'vulnerable' in l:
                if 'TLS 1.0' in l:
                    verified['tls10heartbleed'] = True
                if 'TLS 1.1' in l:
                    verified['tls11heartbleed'] = True
                if 'TLS 1.2' in l:
                    verified['tls12heartbleed'] = True

    print 'SSL Findings so far:'
    for k in verified.keys():
        v = verified[k]
        if type(v) == bool:
            print 'K: %s V: %s' % (k, verified[k])
        elif type(v) == set:
            print "K: %s V: %s" % (k, ', '.join(cipher for cipher in v))

    return verified


def main(argv):
    parser = OptionParser()
    parser.add_option("-H", "--host", dest="host",
                      help="Format: hostname or IP address")

    parser.add_option("-P", "--port", dest="port",
                      help="Format: destination port address")

    parser.add_option("-S", "--ssh", dest="ssh",
                      help="Format: 'ssh user@host'")

    (options, args) = parser.parse_args()

    if options.host is None or options.port is None:
        print "%s -h for help" % argv[0]
        return

    params = dict(host=options.host, port=options.port)

    print "Starting sslscan against %s:%s" % (options.host, options.port)
    result = run_ssl_scan(params, options)
    for l in result:
        print l,

    print "Parsing results..."
    result = filter_result(result)
    verified = parse_result(params, options, result)
    generate_evidences(params=params, options=options, result=result, verified=verified)


if __name__ == '__main__':
    main(sys.argv)
