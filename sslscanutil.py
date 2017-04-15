#!/usr/bin/env python

from optparse import OptionParser
import sys
from subprocess import Popen, PIPE
import string
from StringIO import StringIO
import gzip
import base64
import uuid

"""sslscanutil.py: Utility to help generating evidences for basic SSL stuff"""
__author__ = 'Felipe Cerqueira - FSantos@trustwave.com'


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
    DIV_FORMAT = """<div id="{id}" class="tabcontent"><p class="shortdesc">{short_desc}</p><p class="desc">{desc}</p><p class="preformatted">{evidence}</p></div> """

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


def execute_cmd(title, cmd, renegotiate='R\n'):
    # type: (str, str, str) -> tuple
    print "####-> %s" % title
    print "sending command %s" % cmd

    f = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    result = f.communicate('R\n')
    result = ''.join(result).replace("Kali GNU/Linux 1.0.9\n", '')
    return title, cmd + "\n" + result


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

    def _test_sslv3(self):
        cmd_template = self._create_cmd("openssl s_client -connect {host}:{port} -ssl3")
        title, evidence = execute_cmd("Evidence SSLv3 is enabled on {host} port {port}:".format(**self._params),
                                      cmd_template)
        self._report.add_finding("SSLv3 Enabled", title, evidence)

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

    def _test_renegotiation_self_signed_wildcard(self):
        cmd_template = self._create_cmd("openssl s_client -connect {host}:{port}")
        title = "Testing if secure renegotiation is supported on {host} port {port}:"

        title, result = execute_cmd(title.format(**self._params), cmd_template)

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
        cmd_template = self._create_cmd("curl -Ivs http://{host}")
        title = "Testing if HTTP is available {host} port 80:"

        title, result = execute_cmd(title.format(**self._params), cmd_template)
        redirect = False
        rows = result.split('\n')
        request_evidence = "Request:\n\n"
        response_evidence = "Response:\n\n"

        if "* Connected to" not in result:
            return

        self._report.set_additional_info("HTTP port 80 is accepting connections")

        for row in rows:
            if len(row) == 0:
                continue

            if row[0] == '>':
                request_evidence += row[2:] + '\n'
            if row[0] == '<':
                response_evidence += row[2:] + '\n'
                if 'HTTP/1.1 302' in row or 'HTTP/1.0 302' in row:
                    redirect = True

        evidence = request_evidence + response_evidence
        if redirect:
            self._report.add_finding("HTTP Supported With Immediate Redirection",
                                     "Evidence with immediate HTTP redirection when receive requests on {host} port 80:"
                                     .format(**self._params), evidence)
        else:
            self._report.add_finding("Insecure HTTP Connection Available",
                                     "Evidence showing server accepting insecure connection on {host} port 80:"
                                     .format(**self._params), evidence)

    def _test_hsts(self):
        cmd_template = self._create_cmd("curl -Iksv https://{host}:{port}")
        title = "Testing if HSTS header is in place {host} port {port}:"

        title, result = execute_cmd(title.format(**self._params), cmd_template)
        rows = result.split('\n')
        request_evidence = "Request:\n\n"
        response_evidence = "Response:\n\n"

        for row in rows:
            if len(row) == 0:
                continue
            if row[0] == '>':
                request_evidence += row[2:] + '\n'
            if row[0] == '<':
                response_evidence += row[2:] + '\n'

        evidence = request_evidence + response_evidence

        if 'Strict-Transport-Security' not in response_evidence:
            self._report.add_finding("Strict Transport Security (HSTS) Not Enforced",
                                     "Evidence showing no HSTS header in place on {host} port {port}:"
                                     .format(**self._params), evidence)


# SSLScan syntax formatter
SSL_SCAN_COMMAND = "sslscan {host}:{port}"


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
                                  .replace('[31m', '')
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

    parser.add_option("-O", "--output", dest="output",
                      help="Format: report.html")

    parser.add_option("-I", "--input", dest="input",
                      help="Format: file containing lines host:port:path_to_report.html")

    parser.set_defaults(output='output.html')
    (options, args) = parser.parse_args()

    if options.input is None:
        if options.host is None or options.port is None:
            print "%s -h for help" % argv[0]
            return

    if options.host is not None and options.port is not None:
        start_scan(options)
        return

    saved_output_files = []

    assert isinstance(options.input, str)
    input_file = open(options.input, mode='r')
    for line in input_file.readlines():
        host, port, output = line.strip().split(':')
        options.host = host
        options.port = port
        options.output = output

        start_scan(options=options)

        saved_output_files.append(output)

    print "--> Batch test concluded"
    for output in saved_output_files:
        print "-> Output: %s" % output


def start_scan(options):
    params = dict(host=options.host, port=options.port)
    print "--> Starting sslscan against %s:%s" % (options.host, options.port)
    print "-> Output result: %s" % options.output
    result = run_ssl_scan(params, options)
    for l in result:
        print l,

    print "Parsing results..."
    result = filter_result(result)
    verified = parse_result(params, options, result)
    generate_evidences(params=params, options=options, result=result, verified=verified)
    print "-> Check out the report output: %s" % options.output


if __name__ == '__main__':
    main(sys.argv)
