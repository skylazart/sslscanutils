from unittest import TestCase

from scanutil import SSLEvidenceExecutor


class Options:
    pass


class TestSSLEvidenceExecutor(TestCase):
    def test_verify(self):
        verified = dict(tls10=False,
                        sslv3=False,
                        tls10weakcipher=False,
                        tls11weakcipher=False,
                        tls12weakcipher=False,
                        tls10heartbleed=False,
                        tls11heartbleed=False,
                        tls12heartbleed=False)

        options = Options()
        options.host = 'host'
        options.port = '443'
        options.ssh = 'ssh root@kali'
        options.output = 'temp.html'

        params = dict(host=options.host, port=options.port)

        result = []

        executor = SSLEvidenceExecutor(verified=verified, options=options, params=params, result=result)
        executor.verify()

