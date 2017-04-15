from unittest import TestCase

from sslscanutil import TestingCommands


class Options:
    def __init__(self):
        pass


class TestTestingCommands(TestCase):
    def test_commands(self):
        options = Options()
        options.host = 'host'
        options.port = '443'
        options.ssh = 'ssh root@kali'
        options.output = 'temp.html'

        params = dict(host=options.host, port=options.port)

        testing_default = TestingCommands(None, openssl_path='openssl', sslscan_path='sslscan', curl_path='curl',
                                          nmap_path='nmap')

        testing_custom_path = TestingCommands(ssh_cmd=options.ssh, openssl_path='/tmp/openssl',
                                              sslscan_path='/tmp/sslscan',
                                              curl_path='/tmp/curl', nmap_path='/tmp/nmap')

        """ Testing commands using default path """
        default_ssl_scan_cmd = testing_default.sslscan_command()
        default_sslv2_cmd = testing_default.test_sslv2()
        default_sslv3_cmd = testing_default.test_sslv3()
        default_tls1_cmd = testing_default.test_tls1()
        default_weak_cipher_cmd = testing_default.test_weak_cipher()

        if default_ssl_scan_cmd.format(**params) != 'sslscan --no-color host:443':
            self.fail()

        if default_sslv2_cmd.format(**params) != 'openssl s_client -connect host:443 -ssl2':
            self.fail()

        if default_sslv3_cmd.format(**params) != 'openssl s_client -connect host:443 -ssl3':
            self.fail()

        if default_tls1_cmd.format(**params) != 'openssl s_client -tls1 -connect host:443':
            self.fail()

        if default_weak_cipher_cmd.format(
                **dict(params, tls='tls1', cipher='RC4')) != 'openssl s_client -tls1 -connect -cipher \'RC4\' host:443':
            self.fail()

        """ Testing commands using custom path """
        custom_ssl_scan_cmd = testing_custom_path.sslscan_command()
        custom_sslv2_cmd = testing_custom_path.test_sslv2()
        custom_sslv3_cmd = testing_custom_path.test_sslv3()
        custom_tls1_cmd = testing_custom_path.test_tls1()
        custom_weak_cipher_customcmd = testing_custom_path.test_weak_cipher()

        if custom_ssl_scan_cmd.format(**params) != 'ssh root@kali /tmp/sslscan --no-color host:443':
            self.fail()

        if custom_sslv2_cmd.format(**params) != 'ssh root@kali /tmp/openssl s_client -connect host:443 -ssl2':
            self.fail()

        if custom_sslv3_cmd.format(**params) != 'ssh root@kali /tmp/openssl s_client -connect host:443 -ssl3':
            self.fail()

        if custom_tls1_cmd.format(**params) != 'ssh root@kali /tmp/openssl s_client -tls1 -connect host:443':
            self.fail()

        if custom_weak_cipher_customcmd.format(
                **dict(params, tls='tls1',
                       cipher='RC4')) != 'ssh root@kali /tmp/openssl s_client -tls1 -connect -cipher \'RC4\' host:443':
            self.fail()
