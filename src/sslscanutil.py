#!/usr/bin/env python

import base64
import gzip
import sys
import uuid
from StringIO import StringIO
from optparse import OptionParser
from subprocess import Popen, PIPE

"""sslscanutil.py: Utility to help generating evidences for basic SSL stuff"""
__author__ = 'Felipe Cerqueira - FSantos@trustwave.com'


class TestingCommands:
    def __init__(self, ssh_cmd, openssl_path, sslscan_path, curl_path, nmap_path):
        if ssh_cmd is None:
            ssh_cmd = ''
        else:
            ssh_cmd += ' '

        self._openssl_path = ssh_cmd + openssl_path
        self._sslscan_path = ssh_cmd + sslscan_path
        self._curl_path = ssh_cmd + curl_path
        self._nmap_path = ssh_cmd + nmap_path

    def sslscan_command(self):
        return '%s --no-color {host}:{port}' % self._sslscan_path

    def test_sslv2(self):
        return '%s s_client -connect {host}:{port} -ssl2' % self._openssl_path

    def test_sslv3(self):
        return '%s s_client -connect {host}:{port} -ssl3' % self._openssl_path

    def test_tls1(self):
        return '%s s_client -tls1 -connect {host}:{port}' % self._openssl_path

    def test_weak_cipher(self):
        return '%s s_client -{tls} -cipher \'{cipher}\' -connect {host}:{port}' % self._openssl_path

    def recon(self):
        return '%s -T4 -sV --top-ports 25 {host}' % self._nmap_path

    def test_hsts(self):
        return '%s -ksv https://{host}:{port}' % self._curl_path

    def test_http_redirect(self):
        return '%s -m 10 -ksv http://{host}' % self._curl_path

    def test_self_signed_renegotiation(self):
        return '%s s_client -connect {host}:{port}' % self._openssl_path


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
    HTML_REPORT = 'H4sIABY75VgAA41WW2/aShB+z6/w4aWt1FMMxGlpSSQwwZhrMBdjv1R7cXzBN+E1YKr+9zNrx+C0TXWQ' \
                  'kPHOzuw3M983bOef/lxeGU+PgsMC/+Gmwx+Cj0L7vmaFNb5gIfpwI8CnE1gMCcRB+8Ri97X1avDvl9qL' \
                  'ibnMtx6WBIXC3kpSnyWderFW2H033IHFv68lLPOtxLEsVhNYFlv3NWadWJ0kSS3fWnycvfV8X6OIoa+l' \
                  '+RtGiXV3+3Hs9j7LbtdW5Z6LWzYjTf8O6VI4d/n7aGduVWYE7Vs5FMdyMDqYw51tHSPY37XNoJ1SuREY' \
                  'eiPGw92dKo901T3aWG+nuDU7GvrMn7/ee0bb2J+73dM07N3Oj3FbtuMd2hopVQauOkzGfK+qmAluDkTA' \
                  'kJi6KZYxAEdmKpuM+5OhbZNmO0H6wlabM884l74jx2iykATtBg4WzIA9uKUCtlkw1Y2T6T2W+baQromo' \
                  'H9lTr3vBiXU/nWxpbA61CM7JpvK63B+Zuh+i4eJO7T8e8/W8JlpMXUk0dNU2wo1IlXZ6zUOLSauXGFuo' \
                  'jTKCnGb7ay4DDzVphlub1JQbHm6eDsSLbKh9ZG5HMe2XMWYHrLSzvB8K+JR5DnuOCfFxQHI8vB7TlXm0' \
                  'Sr/hJYfTtH/N71rDXoqb0jXv1kbEip+aq8jG0CtzVcbRfGsIddRPsdm8hTxOvhkuypp4dDs65/Ud9g6A' \
                  'XQS+lDaRBIMU+CQi4APgOE682fktPsyGf+CDMmrQoXbAXhzhlumTCleBW3uzNTpQXdpN9LJGXQ9qsnsz' \
                  'jis5Rgv6FawvHH6rDyWnnhfReBJqjhHAGaHm43BR4f/pYGwXv9YEeK/tuIYmW+1AOL/y3Aofogx2Jq9z' \
                  '1ii4zftTsVc4znv6G1fnlV4iZQM9ccRrj3nekUcVH3q5/lWn11pftBdBf5wDCTXQ+cy78Db/9gLghwha' \
                  '8JFOIwpnA7bE7P9pzyy2gjXnYSPHzHXhSn+Jedl/ruw/kmATwMxhxlYTTX3xJv5idhQ22nRiqqwZ6Ax0' \
                  'v+Y8zDh3nxf393zg1ouJ28ERzeCRkL0bMyHZk+o89NABFZZyLJrhJuVUwc1bkEbPxzsTpJbLDeRpihOg' \
                  'Ptpq0ioYMHN5HYk0GGSqsktANlXKvLyfwJ9dJMCpCeMJKLqB9LptGBcHo7VhJshoElCfPm6AIg3w186L' \
                  '0O+D/M9ElBysryP1NSXd8eoyOg/E7UZoCfH63c+AxX4CKRr6yOOlL2KffBxQoFNio2WyHy9LWXV/xzVg' \
                  '8XYpnenQT8ylBJKaHQGHpPZFWw2kAw7WbpkPSOXiz0cJak3tp2VvB2OvgXWeoxSaW22AlSJHIo6kRfPk' \
                  'kNZsDn8h/lgecZww0qU9ydS4MioyVXZifuY0x9z9Uq3n/8mnwDPDaCOmRuVMHvNv9kk48oly4tSKVLdX' \
                  'jg93Indd1d2V8my/PN/MFfo3MmWnypmUtDQJZJrCODjzMyzeM3kEWNoeyi5j1KfhAri4yUAe0A/NIZwb' \
                  'suRV+GCPz9CPCr5C3lwCnXrB7Iebm04suBRuCPwmUXt1vRCQjdwwYUIHP/xwooT97NQxuMYgGeoeBOKj' \
                  'JAFPhMsrCk4Zi8KKgd9JkpoQhcR3ye6+FsVWOHBD6ob2e+tgheyj8G6F9rbF3n2o5Tio9Yzg8HnMr0aF' \
                  'CU7N4xaH/OitV6v57PvyUV6p89nyJ8gZ0PBMOCgeo3CrVXCQKGRwWonTaV1Cw89iLX4YQopfhTLT+LL+' \
                  'FO35egyPV+tdSl3mRiHyBTd8jvYB4m+wE10M37mhcCpR/uirmwr4cvo83NTrgmIxgTmWYPlWAHCFo8uc' \
                  '36oioJAKeT2hroLLbmhEUr79EyT0WHj2MpW+f+X14VPu8v7Dt5tq8+svI7Ce303/A0O2XaarCgAA'

    BUTTON_FORMAT = """<button class="tablinks" onclick="openFinding(event, '{id}')">{short_desc}</button>"""
    DIV_FORMAT = """<div id="{id}" class="tabcontent"><p class="shortdesc">{short_desc}</p><p class="desc">{desc}</p>
    <p class="preformatted">{evidence}</p></div> """

    def __init__(self, host, port):
        self._host = host
        self._port = port
        self._finding_list = []
        self._additional_info = ''

    def add_finding(self, short_desc, desc, evidence_content):
        # finding = Finding(short_desc, desc, evidence_content.replace('\n', '<br>\n'))
        finding = Finding(short_desc, desc, evidence_content)
        self._finding_list.append(finding)

    def set_additional_info(self, additional_info):
        self._additional_info = additional_info

    def generate_report(self, filename):
        html_report = gzip.GzipFile(fileobj=StringIO(base64.decodestring(self.HTML_REPORT))).read()

        buttons = ''
        divs = ''

        for finding in self._finding_list:
            buttons += self.BUTTON_FORMAT.format(id=finding.id, short_desc=finding.short_desc) + "\n"
            divs += self.DIV_FORMAT.format(id=finding.id, short_desc=finding.short_desc, desc=finding.desc,
                                           evidence=finding.evidence_content) + "\n"

        report = html_report.format(host=self._host, port=self._port, additional_info=self._additional_info,
                                    BUTTON_SECTIONS=buttons, DIV_SECTIONS=divs)
        f = open(filename, 'w')
        f.write(report)
        f.close()


def execute_cmd(cmd, second_cmd=None):
    # type: (str, str) -> str
    f = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    if second_cmd is None:
        result = f.communicate()
    else:
        result = f.communicate(second_cmd)

    """TODO: Implement a more generic replacement"""
    result = ''.join(result).replace("Kali GNU/Linux 1.0.9\n", '')
    return cmd + "\n" + result


class SslEvidenceGenerator:
    def __init__(self, params, options, result, verified):
        """
        Generate the evidences and check for some findings

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
        self._commands = TestingCommands(ssh_cmd=options.ssh, openssl_path=options.openssl_path,
                                         sslscan_path=options.sslscan_path, curl_path=options.curl_path,
                                         nmap_path=options.nmap_path)

        self._report.add_finding('SSLScan output', 'SSLScan output', '\n'.join(result))

    def verify(self):
        if self._options.enable_recon:
            self._recon()

        self._verify()

    def _verify(self):
        if self._check['sslv2']:
            self._test_sslv2()

        if self._check['sslv3']:
            self._test_sslv3()

        if self._check['tls10']:
            self._test_tls1()

        if self._check['tls10weakcipher']:
            self._test_weak_cipher("tls1", self._check['tls10weakcipher_list'])

        if self._check['tls11weakcipher']:
            self._test_weak_cipher("tls1_1", self._check['tls11weakcipher_list'])

        if self._check['tls12weakcipher']:
            self._test_weak_cipher("tls1_2", self._check['tls12weakcipher_list'])

        if self._check['sslv3weakcipher']:
            self._test_weak_cipher("ssl3", self._check['sslv3weakcipher_list'])

        self._test_renegotiation_self_signed_wildcard()
        self._test_http_redirect()
        self._test_hsts()

        self._report.generate_report(self._options.output)

    def _recon(self):
        title = 'Nmap recon on {host}:'.format(**self._params)
        cmd = self._commands.recon().format(**self._params)

        print '## %s' % title
        print '-> %s' % cmd

        result = execute_cmd(cmd)
        self._report.add_finding('Nmap recon', title, result)

    def _test_sslv2(self):
        title = 'Evidence SSLv2 is enabled on {host} port {port}:'.format(**self._params)
        cmd = self._commands.test_sslv2().format(**self._params)

        print '## %s' % title
        print '-> %s' % cmd

        result = execute_cmd(cmd)
        self._report.add_finding('SSLv2 Enabled', title, result)

    def _test_sslv3(self):
        title = 'Evidence SSLv3 is enabled on {host} port {port}:'.format(**self._params)
        cmd = self._commands.test_sslv3().format(**self._params)

        print '## %s' % title
        print '-> %s' % cmd

        result = execute_cmd(cmd)
        self._report.add_finding('SSLv3 Enabled', title, result)

    def _test_tls1(self):
        title = 'Evidence TLS1.0 is enabled on {host} port {port}:'.format(**self._params)
        cmd = self._commands.test_tls1().format(**self._params)

        print '## %s' % title
        print '-> %s' % cmd

        result = execute_cmd(cmd)
        self._report.add_finding('TLS One Enabled', title, result)

    def _test_weak_cipher(self, tls, ciphers):
        # type: (str, list) -> None

        for cipher in ciphers:
            params_tls_cipher = dict(self._params, tls=tls, cipher=cipher)
            title = 'Evidence using weak cipher {tls} ({cipher}) on {host} port {port}:'.format(**params_tls_cipher)
            cmd = self._commands.test_weak_cipher().format(**params_tls_cipher)

            print '## %s' % title
            print '-> %s' % cmd

            result = execute_cmd(cmd)
            self._report.add_finding("Weak Cipher %s %s" % (tls, cipher), title, result)

    def _test_renegotiation_self_signed_wildcard(self):
        title = 'Testing if secure renegotiation is supported on {host} port {port}:'.format(**self._params)
        cmd = self._commands.test_self_signed_renegotiation().format(**self._params)

        print '## %s' % title
        print '-> %s' % cmd

        result = execute_cmd(cmd, 'R\n')

        if result.find('CN=*.') > 0:
            self._report.add_finding("Wildcard SSL Certificate in Use",
                                     "Evidence demonstrating using CN wildcard in the SSL certificate on {host} port "
                                     "{port}: ".format(**self._params), result)

        if result.find('verify error:num=19:self signed certificate in certificate chain'):
            self._report.add_finding("Self Signed Certificate",
                                     "Evidence demonstrating a self signed certificate on {host} port {port}:".
                                     format(**self._params), result)

        idx = result.find('RENEGOTIATING')
        if idx > 0 and result.find('handshake failure', idx, len(result)) < 0 and result.find('verify return:0', idx,
                                                                                              len(result)) > 0:
            self._report.add_finding("Secure Renegotiation Supported",
                                     "Evidence showing the secure renegotiation supported on {host} port {port}:"
                                     .format(**self._params), result)

    def _test_http_redirect(self):
        title = 'Testing if HTTP is responding on {host} port 80:'.format(**self._params)
        cmd = self._commands.test_http_redirect().format(**self._params)

        print '## %s' % title
        print '-> %s' % cmd

        result = execute_cmd(cmd)

        redirect = False

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

        evidence = '<pre>' + request_evidence + response_evidence + '</pre>'

        if 'HTTP/1.1 302' in evidence and 'Location' in evidence:
            redirect = True

        self._report.set_additional_info('HTTP port 80 is accepting connections')

        if redirect:
            self._report.add_finding("HTTP Supported With Immediate Redirection",
                                     "Evidence with immediate HTTP redirection when receive requests on {host} port 80:"
                                     .format(**self._params), evidence)
        else:
            self._report.add_finding("Insecure HTTP Connection Available",
                                     "Evidence showing server accepting insecure connection on {host} port 80:"
                                     .format(**self._params), evidence)

    def _test_hsts(self):
        title = 'Testing if HSTS header is in place {host} port {port}:'.format(**self._params)
        cmd = self._commands.test_hsts().format(**self._params)

        print '## %s' % title
        print '-> %s' % cmd

        result = execute_cmd(cmd)
        request = 'Request:\n'
        response = 'Response:\n'

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

        evidence = '<pre>' + request_evidence + response_evidence + '</pre>'

        if 'Strict-Transport-Security' not in response_evidence:
            self._report.add_finding("Strict Transport Security (HSTS) Not Enforced",
                                     "Evidence showing no HSTS header in place on {host} port {port}:"
                                     .format(**self._params), evidence)


def generate_evidences(params, options, result, verified):
    """
    Generate evidences using the sslscan output and do some more checks

    :type params dict
    :type result list
    :type verified dict

    :param params: Dictionary containing the key/value pairs to compose the sslscan command
    :param options: Command line arguments
    :param result: Output result of sslscan
    :param verified: Dictionary containing the vulnerabilities found
    :return: None
    """

    f = SslEvidenceGenerator(params=params, options=options, result=result, verified=verified)
    f.verify()


def parse_result(result):
    """
    Parse the sslscan output and fill a dict for each finding found

    :type result list
    :param result: Output result of sslscan
    :return: Dictionary containing the vulnerabilities
    """

    verified = dict(tls10=False,
                    sslv2=False,
                    sslv3=False,
                    tls10weakcipher=False,
                    tls11weakcipher=False,
                    tls12weakcipher=False,
                    tls10heartbleed=False,
                    tls11heartbleed=False,
                    tls12heartbleed=False,
                    sslv3weakcipher=False,
                    tls10weakcipher_list=set(),
                    tls11weakcipher_list=set(),
                    tls12weakcipher_list=set(),
                    sslv3weakcipher_list=set())

    for l in result:
        l = ' '.join(l.split())

        if 'Accepted' in l or 'Preferred' in l:
            # Line format: Accepted TLSv1.0 128 bits ECDHE-RSA-AES128-SHA
            splited = l.split()

            if len(splited) <= 3:
                continue

            if splited[3] == 'bits' and (int(splited[2]) < 128 or 'RC4' in splited[4]):
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

                if 'SSLv3' in splited[1]:
                    verified['sslv3weakcipher'] = True
                    # Saving the cipher name
                    verified['sslv3weakcipher_list'].add(splited[4])

            if 'SSLv3' in l:
                verified['sslv3'] = True

            if 'SSLv2' in l:
                verified['sslv2'] = True

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

    print '-> SSL findings identified so far:'
    for k in verified.keys():
        v = verified[k]
        if type(v) == bool:
            print 'K: %s V: %s' % (k, verified[k])
        elif type(v) == set:
            print "K: %s V: %s" % (k, ', '.join(cipher for cipher in v))

    print ''
    return verified


def main(argv):
    parser = OptionParser()
    parser.add_option("-H", "--host", dest="host",
                      help="Format: hostname or IP address")

    parser.add_option("-P", "--port", dest="port",
                      help="Format: destination port address")

    parser.add_option("-S", "--ssh", dest="ssh",
                      help="Format: 'ssh user@host'")

    parser.add_option("-O", "--output", dest="output", default="output.html",
                      help="Format: report.html")

    parser.add_option("-I", "--input", dest="input",
                      help="Format: file containing lines host:port:path_to_report.html")

    parser.add_option("--openssl", dest="openssl_path", default="openssl",
                      help="Custom path to openssl")

    parser.add_option("--sslscan", dest="sslscan_path", default="sslscan",
                      help="Custom path to sslscan")

    parser.add_option("--curl", dest="curl_path", default="curl",
                      help="Custom path to curl")

    parser.add_option("--nmap", dest="nmap_path", default="nmap",
                      help="Custom path to nmap")

    parser.add_option("--enable-recon", dest="enable_recon", action="store_true", default=False,
                      help="Enable Nmap recon - default is disabled")

    (options, args) = parser.parse_args()

    commands = TestingCommands(ssh_cmd=options.ssh, openssl_path=options.openssl_path,
                               sslscan_path=options.sslscan_path, curl_path=options.curl_path,
                               nmap_path=options.nmap_path)

    if options.input is None:
        if options.host is None or options.port is None:
            print "%s -h for help" % argv[0]
            return

    if options.host is not None and options.port is not None:
        start_scan(options, commands)
        return

    saved_output_files = []

    assert isinstance(options.input, str)
    input_file = open(options.input, mode='r')
    for line in input_file.readlines():
        host, port, output = line.strip().split(':')
        options.host = host
        options.port = port
        options.output = output

        start_scan(options, commands)
        saved_output_files.append(output)

    print '#### Batch test concluded'
    for output in saved_output_files:
        print '-> Output: %s' % output


def start_scan(options, commands):
    params = dict(host=options.host, port=options.port)

    print '#### Starting sslscan against %s:%s -> output: %s' % (options.host, options.port, options.output)

    cmd = commands.sslscan_command().format(**params)
    result = execute_cmd(cmd)
    print '-> SSLScan output:'
    print result

    result = result.split('\n')
    verified = parse_result(result)
    generate_evidences(params=params, options=options, result=result, verified=verified)
    print '-> Check out the report output: %s' % options.output


if __name__ == '__main__':
    main(sys.argv)
