// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

func parseFlags() {
	flag.IntVar(&prefixLengthToScanWith, "pl", 24, "PREFIX LENGTH = Prefix length we will use for the 'Source' field in the ECS in all our scans")
	flag.StringVar(&inputFile, "if", "", "INPUT FILE = The file in which the list of Domains we want to scan is stored.")
	flag.StringVar(&storeDir, "out", "", "output Directory to write results")
	flag.IntVar(&capacityForChannelsFlag, "cc", 100, "CAPACITY of CHANNELS = Number of Domains we can scan concurrently")
	flag.IntVar(&numberOfIPGenerators, "ni", 20, "NUMBER of IPGENERATORS = Number of concurrently called IPGenerators")
	flag.IntVar(&loggingLevel, "ll", 2, " LOGGING LEVEL = Level of how much we log. 0 (no logging) 1(only errors), 2 (informational), 3 (debugging)")
	flag.StringVar(&fileToLogTo, "lf", "", "LOGGING FILE = File we want to log into")
	flag.StringVar(&queryListFile, "query-list", "", "List of query parameters to use instead of normal trie based approach")
	flag.BoolVar(&printFinalResult, "pr", false, "PRINT RESULT = Indicates if final result shall be printed")
	flag.StringVar(&cpuProfileFile, "cp", "", "CPU PROFILE = File to which cpuProfile shall be written")
	flag.StringVar(&memProfileFile, "mp", "", "MEMORY PROFILE = File to which memProfile shall be written")
	flag.StringVar(&bgpPrefixFile, "pf", "", "PREFIX FILE = File where the bgp prefixes are stored")
	flag.StringVar(&specialPrefixesFile, "sf", "", "SPECIAL PREFIX FILE = File where the bgp prefixes are stored")
	flag.IntVar(&maximumTempErrors, "te", 3, "TEMPORARY ERRORS = maximum number of temporary errors we accept for one domain-name server pair before stop scanning it")
	flag.IntVar(&queryRate, "query-rate", 100, "query rate per second,                                                    <= 0 for unlimited.")
	flag.IntVar(&retries, "retries", 3, "number of retries on error")
	flag.IntVar(&domainOutstanding, "domain-outstanding", 100, "maximum number of domains which are scanned at once,                      == 0 to disable.")
	flag.StringVar(&ip4flag, "ip4source", "", "ipv4 source address to use during the scan")
	flag.StringVar(&ip6flag, "ip6source", "", "ipv6 source address to use during the scan")
	flag.IntVar(&maxNumScopeZeros, "scope-zero-allowed", 10000, "Number of scope zeros to accepts,                                                    <= 0 for unlimited.")
	flag.BoolVar(&nostore, "disable-store", false, "disable all storage")
	flag.BoolVar(&versionf, "version", false, "show version string")
	flag.BoolVar(&ipv6Scan, "6", false, "Perfom IPv6 scan using BGPANNOUNCED prefixes as seed")
	flag.IntVar(&randomizeDepth, "randomize-depth", 32, "Randomize scan prefix selection after a given depth")
	flag.BoolVar(&scanAllBGP, "scanAllBGP", false, "Force scan all BGP announced prefixes from the prefix list")
	flag.StringVar(&resolver, "resolver", "", "Set this to use a public resolver instead of the authoritative name server")
	flag.StringVar(&configFile, "config-file", "", "Config file path")
	timeoutDial = flag.Duration("timeout-dial", 2*time.Second, "Dial timeout")
	timeoutRead = flag.Duration("timeout-read", 2*time.Second, "Read timeout")
	timeoutWrite = flag.Duration("timeout-write", 2*time.Second, "Write timeout")
	flag.Parse()
	if inputFile == "" {
		fmt.Println("Please specify inputFile with -if")
		os.Exit(0)
	}
}
