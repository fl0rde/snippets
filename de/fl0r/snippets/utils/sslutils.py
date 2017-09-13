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

from OpenSSL.crypto import FILETYPE_ASN1, FILETYPE_PEM, load_certificate, X509
from smtplib import SMTP_SSL, SMTP, SMTPConnectError
from ssl import get_server_certificate


def get_cert_from_https(host: str, port: int = 443) -> X509:
    cert = None

    try:
        pem_cert = get_server_certificate((host, port))
        cert = load_certificate(FILETYPE_PEM, pem_cert)

    except ConnectionRefusedError as e:
        print(f'HTTPS: {e.strerror}')
        pass

    except Exception:
        print('HTTPS: unknown error')
        pass

    return cert


def get_cert_from_smtp(host: str) -> X509:
    cert = None

    try:
        with SMTP(host=host) as smtp:
            smtp.starttls()
            der_cert = smtp.sock.getpeercert(True)
            cert = load_certificate(FILETYPE_ASN1, der_cert)

    except (SMTPConnectError, TimeoutError) as e:
        print(f'STARTTLS: {e.strerror}')
        pass

    except Exception:
        print('STARTTLS: unknown error')
        pass

    return cert


def get_cert_from_smtps(host: str) -> X509:
    cert = None

    try:
        with SMTP_SSL(host=host) as smtp:
            der_cert = smtp.sock.getpeercert(True)
            cert = load_certificate(FILETYPE_ASN1, der_cert)

    except (SMTPConnectError, TimeoutError) as e:
        print(f'SMTPS: {e.strerror}')
        pass

    except Exception:
        print('SMTPS: unknown error')
        pass

    return cert
