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

import json
import urllib.request
from OpenSSL.crypto import load_certificate, FILETYPE_ASN1, X509
from base64 import b64decode
from struct import unpack

from .x509utils import get_san


def extract_certificate_from_leaf(leaf_input: bytes) -> X509:
    cert = None
    der_cert = None

    entry_type = unpack('>H', leaf_input[10:12])[0]
    if entry_type == 0:
        length = unpack('>I', b'\x00' + leaf_input[12:15])[0]
        der_cert = leaf_input[15:15 + length]

    if der_cert:
        cert = load_certificate(FILETYPE_ASN1, der_cert)

    return cert


def get_tree_size(host: str) -> int:
    json_decoder = json.JSONDecoder()

    request = urllib.request.urlopen(host + f'/ct/v1/get-sth')
    latest_str = request.read().decode()
    size = int(json_decoder.decode(latest_str)['tree_size'])
    return size


def get_san_from_ct(host: str, start: int, end: int) -> list:
    json_decoder = json.JSONDecoder()

    if end < 0:
        end = start + 1000

    request = urllib.request.urlopen(host + f'/ct/v1/get-entries?start={start}&end={end}')
    entries_str = request.read().decode()
    entries = json_decoder.decode(entries_str)['entries']

    san = list()
    for entry in entries:
        cert = extract_certificate_from_leaf(b64decode(entry['leaf_input']))
        if cert:
            san.extend(get_san(cert))

    return san
