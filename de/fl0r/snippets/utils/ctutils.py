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
from pathlib import Path
from struct import unpack
from typing import Generator

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


def download_entries(host: str, start: int, end: int, filename: str):
    if not Path(filename).is_file():
        urllib.request.urlretrieve(host + f'/ct/v1/get-entries?start={start}&end={end}', filename=filename)


def read_entries(host: str, start: int, end: int, buffer: int) -> Generator[str, None, None]:
    data = ''
    filename = f'{start}-{end}'
    download_entries(host, start, end, filename)

    with open(filename, 'r') as tmp:
        begin = 0
        chunk = tmp.read(buffer)
        while chunk:
            data = data[begin:] + chunk
            chunk = tmp.read(buffer)

            for border in extract_leafs(data):
                begin = end
                yield (data[border[0]:border[1]])


def extract_leafs(data: str) -> Generator[tuple, None, None]:
    begin = 0
    end = 0

    while True:
        begin += end
        tmp = data[begin:]

        leaf = tmp.find('"leaf_input"')
        if leaf < 0:
            break
        else:
            leaf += 12

        start = tmp[leaf:].find('"')
        if start < 0:
            break
        else:
            start += 1 + leaf

        end = tmp[start:].find('"')
        if end < 0:
            break
        else:
            end += start

        yield((begin + start, begin + end))


def get_san_from_ct(host: str, start: int, end: int) -> Generator[str, None, None]:
    for s in range(start, end, 500):
        for entry in read_entries(host, s, min(s+500, end), 1000000):
            cert = extract_certificate_from_leaf(b64decode(entry))
            if cert:
                for san in get_san(cert):
                    yield san
