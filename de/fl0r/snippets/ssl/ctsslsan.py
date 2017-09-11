import argparse
import json
import urllib.request
from OpenSSL.crypto import load_certificate, FILETYPE_ASN1, X509
from base64 import b64decode
from struct import unpack

from utils.x509utils import get_san


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
        end = start+1000

    request = urllib.request.urlopen(host + f'/ct/v1/get-entries?start={start}&end={end}')
    entries_str = request.read().decode()
    entries = json_decoder.decode(entries_str)['entries']

    san = list()
    for entry in entries:
        cert = extract_certificate_from_leaf(b64decode(entry['leaf_input']))
        if cert:
            san.extend(get_san(cert))

    return san


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--size', help='get tree size', action='store_true')
    parser.add_argument('--host', type=str, default='https://ct.googleapis.com/icarus', help='ct server')
    parser.add_argument('--start', type=int, default='0')
    parser.add_argument('--end', type=int, default='-1')
    args = parser.parse_args()

    if args.size:
        print(get_tree_size(args.host))
        exit(0)

    san = get_san_from_ct(args.host, args.start, args.end)
    print(*san, sep='\n')

    exit(0)
