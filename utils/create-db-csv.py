#!/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import json
import fileinput
import argparse
import csv
import sys


def main():
    parser = argparse.ArgumentParser(description='Get nameserver for a list of domains')
    parser.add_argument('--ipv6', '-6', action="store_true",
                        help='Extract IPv6 nameserver IP addresses')
    parser.add_argument('inFile', type=str,
                        help='Input file containing a list of domains')
    parser.add_argument('outFile', type=str,
                        help='Output file containing a list of basedomain,cname_chain,nameserver_names,'
                             'nameserver_ips,error')

    args = parser.parse_args()

    if args.inFile == args.outFile:
        print("inFile and outFile match, aborting")
        exit(0)

    if args.outFile != '-':
        outf = open(args.outFile, "w")
    else:
        outf = sys.stdout

    if args.inFile == '-':
        in_file = fileinput.input()
    else:
        in_file = open(args.inFile, "r")

    csvwriter = csv.writer(outf)
    for line in in_file:
        domain_info = json.loads(line)
        domain = domain_info['domain']
        basedomain = domain
        if domain_info['cname_chain']:
            domain = domain_info['cname_chain'][-1]
        nsnames = []
        ns_ips = []
        if domain in domain_info['ns_mappings']:
            nsnames = domain_info["ns_mappings"][domain]["names"]
            ns_ips = domain_info["ns_mappings"][domain]["v4_ns" if not args.ipv6 else "v6_ns"]
        csvwriter.writerow([basedomain, domain, nsnames, ns_ips])

    outf.flush()
    outf.close()


if __name__ == '__main__':
    main()
