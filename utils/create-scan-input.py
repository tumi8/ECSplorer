#!/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import json
import fileinput
import argparse


def main():
    parser = argparse.ArgumentParser(description='Get nameserver for a list of domains')
    parser.add_argument('--cnames', '-c', action="store_true",
                        help='create cname scanning list. Otherwise only a list of the final name in the '
                             'cname with the according nameserver IP address is created')
    parser.add_argument('--ipv6', '-6', action="store_true",
                        help='Extract IPv6 nameserver IP addresses')
    parser.add_argument('inFile', type=str,
                        help='Input file containing a list of domains')
    parser.add_argument('outFile', type=str,
                        help='Output file containing a list of domains,nameserver pairs')

    args = parser.parse_args()

    if args.inFile == args.outFile:
        print("inFile and outFile match, aborting")
        exit(0)

    if args.outFile != '-':
        outf = open(args.outFile, "w")
    else:
        outf = None

    if args.inFile == '-':
        in_file = fileinput.input()
    else:
        in_file = open(args.inFile, "r")

    for line in in_file:
        domain_info = json.loads(line)
        if 'error' in domain_info:
            continue
        domain = domain_info['domain']
        if not args.cnames and domain_info['cname_chain']:
            domain = domain_info['cname_chain'][-1]
        for ip in domain_info['ns_mappings'][domain]["v4_ns" if not args.ipv6 else 'v6_ns']:
            print(f'{domain},{ip}', file=outf)
        if args.cnames:
            for name in domain_info['cname_chain']:
                domain = name
                for ip in domain_info['ns_mappings'][domain]["v4_ns" if not args.ipv6 else 'v6_ns']:
                    print(f'{domain},{ip}', file=outf)
    if outf:
        outf.close()


if __name__ == '__main__':
    main()
