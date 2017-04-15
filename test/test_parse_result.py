from unittest import TestCase

from sslscanutil import parse_result

result = """
OpenSSL 1.0.1m-dev xx XXX xxxx

Testing SSL server yyy.net-xxx.corp on port 443

  TLS renegotiation:
Secure session renegotiation supported

  TLS Compression:
Compression disabled

  Heartbleed:
TLS 1.0 not vulnerable to heartbleed
TLS 1.1 not vulnerable to heartbleed
TLS 1.2 not vulnerable to heartbleed

  Supported Server Cipher(s):
Accepted  TLSv1.0  128 bits  ECDHE-RSA-AES128-SHA
Accepted  TLSv1.0  128 bits  DHE-RSA-AES128-SHA
Accepted  TLSv1.0  128 bits  AES128-SHA
Accepted  TLSv1.0  112 bits  ECDHE-RSA-DES-CBC3-SHA
Accepted  TLSv1.0  112 bits  EDH-RSA-DES-CBC3-SHA
Accepted  TLSv1.0  112 bits  DES-CBC3-SHA
Accepted  TLSv1.1  128 bits  ECDHE-RSA-AES128-SHA
Accepted  TLSv1.1  128 bits  DHE-RSA-AES128-SHA
Accepted  TLSv1.1  128 bits  AES128-SHA
Accepted  TLSv1.1  112 bits  ECDHE-RSA-DES-CBC3-SHA
Accepted  TLSv1.1  112 bits  EDH-RSA-DES-CBC3-SHA
Accepted  TLSv1.1  112 bits  DES-CBC3-SHA
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-GCM-SHA256
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-SHA256
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-SHA
Accepted  TLSv1.2  128 bits  DHE-RSA-AES128-GCM-SHA256
Accepted  TLSv1.2  128 bits  DHE-RSA-AES128-SHA256
Accepted  TLSv1.2  128 bits  DHE-RSA-AES128-SHA
Accepted  TLSv1.2  128 bits  AES128-GCM-SHA256
Accepted  TLSv1.2  128 bits  AES128-SHA256
Accepted  TLSv1.2  128 bits  AES128-SHA
Accepted  TLSv1.2  112 bits  ECDHE-RSA-DES-CBC3-SHA
Accepted  TLSv1.2  112 bits  EDH-RSA-DES-CBC3-SHA
Accepted  TLSv1.2  112 bits  DES-CBC3-SHA

  Preferred Server Cipher(s):
TLSv1.0  128 bits  ECDHE-RSA-AES128-SHA
TLSv1.1  128 bits  ECDHE-RSA-AES128-SHA
TLSv1.2  128 bits  ECDHE-RSA-AES128-GCM-SHA256

  SSL Certificate:
Signature Algorithm: sha256WithRSAEncryption
RSA Key Strength:    2048

Subject:  yyy.net-xxx.corp
Issuer:   FooBar xxx Certification Authority 2016
"""


class Options:
    pass


class TestParseResult(TestCase):
    def test_parse_result(self):
        verified = parse_result(params=dict(), options=Options(), result=result.split('\n'))

        for k in verified.keys():
            v = verified[k]

            if type(v) == bool:
                if v and k not in ['tls10', 'tls10weakcipher', 'tls11weakcipher', 'tls12weakcipher']:
                    self.fail()

