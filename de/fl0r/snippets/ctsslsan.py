"""
Extract all subjectAltName or CN entries from Certificate Transparency entries
usage: `usage: ctsslsan.py [-h] [--treesize] [--host HOST] [--start START] [--end END]`

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

from utils.ctutils import get_san_from_ct, get_tree_size

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--treesize', help='get tree size', action='store_true')
    parser.add_argument('--host', type=str, default='https://ct.googleapis.com/icarus', help='ct server')
    parser.add_argument('--start', type=int, default='100000', help='entry to start')
    parser.add_argument('--end', type=int, help='start + 500 if missing')
    args = parser.parse_args()

    if args.treesize:
        print(get_tree_size(args.host))
        exit(0)

    if not args.end:
        args.end = args.start + 500

    san = get_san_from_ct(args.host, args.start, args.end)
    print(*san, sep='\n')

    exit(0)
