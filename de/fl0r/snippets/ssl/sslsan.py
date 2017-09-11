"""
Extract all subjectAltName or CN entries from a TLS Certificate
usage: `python sslsan.py [-h] [--port PORT] host`

used packages: pyOpenSSL, asn1crypto
Tested using Python 3.6.2

Author: Florian Ammon (@riesenwildschaf)
---
MIT License

Copyright (c) 2017 Florian Ammon

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import argparse
from OpenSSL.crypto import X509, load_certificate, FILETYPE_PEM
from ssl import get_server_certificate

from utils.x509utils import get_san


def get_san_from_host(host: str, port: int) -> list:
    san = list()
    try:
        pem_cert = get_server_certificate((host, port))
        cert: X509 = load_certificate(FILETYPE_PEM, pem_cert)
        san = get_san(cert)

    except ConnectionRefusedError as e:
        print(e.strerror)
        exit(1)

    except:
        exit(1)

    return san


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('host', type=str, help='hostname or ip')
    parser.add_argument('--port', type=int, default=443)
    args = parser.parse_args()

    san = get_san_from_host(args.host, args.port)
    print(*san, sep='\n')

    exit(0)
