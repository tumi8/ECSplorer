#!/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import json
import multiprocessing.pool
import sys
import threading
import time

import dns.rdatatype
import dns.resolver
import dns.name
import publicsuffixlist
import traceback
import fileinput

import argparse

parser = argparse.ArgumentParser(description='Get nameserver for a list of domains')
parser.add_argument('-a', action="store_true",
                    help='Whether to return one or all namesververs for any domain')
parser.add_argument('inFile', type=str,
                    help='Input file containing a list of domains')
parser.add_argument('--outFile', type=str,
                    help='Output file containing a list of domains,nameserver pairs')
parser.add_argument('--errorFile', type=str,
                    help='Error file')

args = parser.parse_args()

write_lock = threading.Lock()

psl = publicsuffixlist.PublicSuffixList(only_icann=True)

if args.inFile == args.outFile:
    print("inFile and outFile match, aborting")
    exit(0)

if args.inFile != '-':
    outf = open(args.outFile, "w")
    errorsf = open(args.errorFile, "w")
else:
    outf = None
    errorsf = None

nameservers = ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844", "9.9.9.9", "149.112.112.112",
               "2620:fe::fe", "2620:fe::9", "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"]
pub_resolver = dns.resolver.Resolver()
pub_resolver.nameservers = nameservers


class NSFindException(Exception):
    def __init__(self, domain, msg):
        self.domain = domain
        self.msg = msg
        super(NSFindException, self).__init__(msg)


def write_output(domainInfo, stdsys=True):
    with write_lock:
        print(f"{json.dumps(domainInfo)}", file=outf if not stdsys else sys.stdout, flush=True)


def write_error(domain, ex_str, stdsys=True):
    with write_lock:
        print(f'{domain}:\n{ex_str}', file=errorsf if not stdsys else sys.stderr, flush=True)


def get_ns_ip(target, resolver, record) -> [str]:
    ips = []
    try:
        ns_ip = resolver.resolve(target, record)
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        return "NXDomain in nameserver lookup"
    except dns.resolver.Timeout:
        pass
    except dns.resolver.NoNameservers:
        return "No Nameserver could resolve this target"
    else:
        for rr in ns_ip.response.answer:
            if rr.rdtype == record:
                for res in rr:
                    ips.append(str(res.address))
    return ips


def get_auth_ns(domain, resolver: dns.resolver.Resolver, tries=5):
    if tries == 0:
        raise NSFindException(domain, f'timeout for {resolver.nameservers} at {domain}')
    if not domain:
        raise NSFindException(domain, 'no suitable auth ns - domain None')
    if not psl.privatesuffix(domain):
        raise NSFindException(domain, 'no suitable auth ns for any parent')
    if not psl.publicsuffix(domain):
        raise NSFindException(domain, 'no suitable auth ns - invalid tld')
    try:
        resp = resolver.resolve(domain, "NS", raise_on_no_answer= False)
    except dns.resolver.Timeout:
        return get_auth_ns(domain, resolver, tries - 1)
    except dns.resolver.NoNameservers:
        error = [domain, "No Nameserver could resolve this domain"]
    except dns.resolver.NXDOMAIN:
        error = [domain, "Query returned NXDOMAIN"]
        # possibility of qname min error...
        return get_auth_ns('.'.join(domain.split('.')[1:]), resolver, tries)
    else:
        ns_rrs = None
        for rr in resp.response.answer:
            if rr.rdtype == dns.rdatatype.NS and str(rr.name).strip('.') == domain:
                ns_rrs = rr
                break
        if ns_rrs:
            ip4s = set()
            ip6s = set()
            nsnames = set()
            for rr in ns_rrs:
                nsnames.add(str(rr.target).strip('.'))
                ips = get_ns_ip(rr.target, resolver, dns.rdatatype.A)
                if isinstance(ips, list):
                    ip4s = ip4s.union(ips)
                ips = get_ns_ip(rr.target, resolver, dns.rdatatype.AAAA)
                if isinstance(ips, list):
                    ip6s = ip6s.union(ips)
            return list(ip4s), list(ip6s), list(nsnames)

        return get_auth_ns(str(resp.qname.parent()).strip('.'), resolver, tries)
    raise NSFindException(*error)


def get_cname(domain, resolver, tries=5):
    if tries == 0:
        raise NSFindException(domain, f'timeout for {resolver.nameservers}')
    try:
        resp = resolver.resolve(domain, "A", raise_on_no_answer=False)
    except dns.resolver.Timeout:
        time.sleep(0.1)
        return get_cname(domain, resolver, tries - 1)
    except dns.resolver.NoNameservers:
        error = [domain, "No Nameserver could resolve this domain"]
    except dns.resolver.NXDOMAIN:
        error = [domain, "Query returned NXDOMAIN"]
    else:
        cname = None
        reached = False
        for rr in resp.response.answer:
            if rr.rdtype == dns.rdatatype.CNAME and str(rr.name).strip('.') == domain:
                cname = str(rr.pop().target).strip('.')
                break
            if rr.rdtype == dns.rdatatype.A and str(rr.name).strip('.') == domain:
                reached = True
                break

        return cname, reached
    raise NSFindException(*error)


def handle_domain(domain):
    domain = domain.strip().lower()
    domain_info = {
        'domain': domain,
        'ns_mappings': {},
        'cname_chain': []
    }
    try:
        while True:
            auth_ns, auth_ns6, auth_nsnames = get_auth_ns(domain, pub_resolver)
            domain_info['ns_mappings'][domain] = {
                'v4_ns': auth_ns,
                'v6_ns': auth_ns6,
                'names': auth_nsnames
            }
            auth_res = dns.resolver.Resolver()
            auth_res.nameservers = auth_ns if auth_ns else auth_ns6
            cname, reached = get_cname(domain, auth_res)
            if reached:
                break
            if cname:
                domain_info['cname_chain'].append(cname)
            else:
                domain_info['error'] = 'no record'
                break
            domain = cname
    except NSFindException as e:
        domain_info['error'] = f'{e.domain}: {e.msg}'
    except Exception:
        write_error(domain, traceback.format_exc())

    write_output(domain_info)


def main():
    if args.inFile == '-':
        inf = fileinput.input()
    else:
        inf = open(args.inFile, "r")
    pool = multiprocessing.pool.ThreadPool(processes=100)
    result = pool.map_async(handle_domain, inf, chunksize=1)
    try:
        while result.wait():
            pass
    except StopIteration:
        print('finished', file=sys.stderr)
    pool.close()


if __name__ == "__main__":
    main()
    # r = process_map(functools.partial(handle_domain), inf.readlines(), initializer=init, max_workers=16, chunksize=1)
