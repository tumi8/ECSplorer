// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"net"
	"time"
)

// Output format
const ECSResultsHeader string = "domain,ns,family,clientAddress,sourcePrefixLength,scopePrefixLength,error,errStr,nsid,answers,cnames,timestamp"

// global Variables:
var version string = "0.3.1"

var limiter chan struct{}

var queryList []net.IPNet

var EcsResultWriter *SynchronizedWriter

// global constants indicate the kind of network (0 = not BGPANNOUNCED routable, 1 = BGPANNOUNCED routable, 2 = special use)

const (
	UNANNOUNCED = iota
	BGPANNOUNCED
	SPECIAL
	TOTAL
)

type error_type int

const (
	NO_ERR  = iota
	NO_AUTH // non-authoritative answer
	NO_ADD
	NO_EDNS
	NO_ECS
	WRONG_FAM
	SCOPE_OOB
	NO_ANS // no answer RR ins reply
	NO_REC // no fitting record in answer
	INTERNAL_ERR
	WRONG_PARAM
	TRUNCATED_NO_TCP
)

func isPerm(error error_type) bool {
	switch error {
	case NO_ERR:
		return false
	case NO_AUTH:
		return true
	case NO_ADD:
		return true
	case NO_EDNS:
		return true
	case NO_ECS:
		return false
	case WRONG_FAM:
		return true
	case SCOPE_OOB:
		return true
	case NO_ANS:
		return false
	case NO_REC:
		return false
	case TRUNCATED_NO_TCP:
		return false
	case INTERNAL_ERR:
		return true
	}
	return true
}

// // Input Flags ////
//
// In/Output Files
var storeDir string //directory where results will be stored
var inputFile string
var fileToLogTo string
var cpuProfileFile string
var memProfileFile string
var bgpPrefixFile string
var specialPrefixesFile string
var queryListFile string
var configFile string

// flags for backendLogic
var capacityForChannelsFlag int
var numberOfIPGenerators int
var loggingLevel int
var printFinalResult bool
var scanLimits = make(map[int][]int) //first position indicates the kind of network
var maxSpecialPrefixScans int
var totalNotroutedLimit int
var prefixLengthToScanWith int
var scanResultsToFinish uint8 //should not exceed 255
var bgpPrefixes map[int64][]int
var bgpPrefixesSlice []int64
var specialPrefixes map[int64][]int
var specialPrefixesSlice []int64
var maximumTempErrors int
var maxNumScopeZeros int

// flags for scanner
var queryRate int
var retries int
var domainOutstanding int
var ip4flag string
var ip6flag string
var nostore bool
var versionf bool
var resolver string
var ipv6Scan bool
var randomizeDepth int
var scanBGPOnly bool

var timeoutDial *time.Duration
var timeoutRead *time.Duration
var timeoutWrite *time.Duration
