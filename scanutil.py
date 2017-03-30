#!/usr/bin/env python


from optparse import OptionParser
import sys
from subprocess import Popen, PIPE
import string

SSL_SCAN_COMMAND = "sslscan {host}:{port}"


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

    def _test_tls1(self):
        cmd_template = self._create_cmd("openssl s_client -tls1 -connect {host}:{port}")
        self._execute_cmd("Evidence TLS1.0 is enabled on {host} port {port}:".format(**self._params),
                          cmd_template)

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
            self._execute_cmd(title.format(**self._params),
                              cmd_template)

    def _create_cmd(self, cmd):
        """
        :type cmd str
        :param cmd: OpenSSL command
        :return: Command string including the ssh command when necessary
        """

        if self._options.ssh is not None:
            cmd = "%s %s" % (self._options.ssh, cmd)

        return cmd.format(**self._params)

    def _execute_cmd(self, title, cmd, renegotiate='R\n'):
        print "####-> %s" % title
        print "sending command %s" % cmd

        f = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        result = f.communicate(renegotiate)

        for l in result:
            if 'Kali' in l and 'Linux' in l:
                continue

            print l.strip()


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

    print 'Findings:'
    for k in verified.keys():
        v = verified[k]
        if type(v) == bool:
            print 'K: %s V: %s' % (k, verified[k])
        elif type(v) == set:
            print "K: %s V: %s" % (k, ', '.join(cipher for cipher in v))

    return verified


def check_try_again(result):
    """
    :type result list
    :param result: Output result of sslscan
    :return: True or False
    """

    if result is not None:
        for l in result:
            print l,

    ans = raw_input("Try again? ")
    if ans in ['y', 'Y', 'Yes', 'YES', 'yes']:
        return True

    return False


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

    while True:
        print "Starting sslscan against %s:%s" % (options.host, options.port)

        result = run_ssl_scan(params, options)
        if not check_try_again(result):
            break

    print "Parsing results..."

    result = filter_result(result)
    verified = parse_result(params, options, result)
    generate_evidences(params=params, options=options, result=result, verified=verified)


if __name__ == '__main__':
    main(sys.argv)
