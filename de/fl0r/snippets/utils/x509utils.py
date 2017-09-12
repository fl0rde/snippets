"""
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

from OpenSSL.crypto import X509
from asn1crypto.core import Asn1Value
from asn1crypto.x509 import GeneralNames


def get_san(cert: X509) -> list:
    san = get_subject_alt_name(cert)
    if not san:
        san = list(get_subject_cn(cert))

    return san


def get_subject_alt_name(cert: X509) -> list:
    san = list()
    for i in range(cert.get_extension_count()):
        if cert.get_extension(i).get_short_name() == b'subjectAltName':
            general_names = GeneralNames.load(cert.get_extension(i).get_data())
            for general_name in general_names:
                value = Asn1Value.load(general_name.contents)
                san.append(value.contents.decode())
            break
    return san


def get_subject_cn(cert: X509) -> str:
    for comp in cert.get_subject().get_components():
        if comp[0] == b'CN':
            return comp[1].decode()
    return ""
