"""
Extract all subjectAltName or CN entries from a TLS Certificate (SMTP(S)-Server)
usage: `python sslsansmtp.py [-h] [--smtpport SMTPPORT] [--smtpsport SMTPSPORT] [--MX] host`

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
import dns.resolver
from typing import Generator

from utils.sslutils import get_cert_from_smtps, get_cert_from_smtp
from utils.x509utils import get_san


def dns_query(host: str, entry: str) -> Generator:
    try:
        answers = dns.resolver.query(host, entry)
        for data in answers:
            yield (data.exchange)
    except dns.resolver.NoAnswer as e:
        pass


def add_hosts(hosts, cert):
    if cert:
        for san in get_san(cert):
            hosts.add(san)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('host', type=str, help='hostname or ip')
    parser.add_argument('--smtpport', type=int, default=25)
    parser.add_argument('--smtpsport', type=int, default=465)
    parser.add_argument('--MX', help='search MX entries of host', action="store_true")
    args = parser.parse_args()

    san = set()
    hosts = list()

    if args.MX:
        for host in dns_query(args.host, 'MX'):
            hosts.append(str(host))

    else:
        hosts.append(args.host)

    for host in hosts:
        cert = get_cert_from_smtp(host, args.smtpport)
        add_hosts(san, cert)

        cert = get_cert_from_smtps(host, args.smtpsport)
        add_hosts(san, cert)

    print(*[f'HOST: {host}' for host in san], sep='\n')

    exit(0)
