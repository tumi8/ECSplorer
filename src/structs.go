// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"net"
	"sync"
)

// Controller types

// ControllerQueue struct is used to receive results in the Controller
type ControllerQueue struct {
	condition                    *sync.Cond
	sliceIPGeneratorToController []*ipGeneratorResult
	sliceScannerToController     []*dnsResult
}

///// IPGENERATOR Types /////

type ipGeneratorResult interface {
}

func domainIdentifier(domain string, nameserverIP net.IP) string {
	return domain + nameserverIP.String()
}

type domainScanFinished struct {
	domainState *domainState
}

type waitingForMoreResults struct {
	domainState *domainState
}

type queryRequest struct { // queryRequest contains the newly created parameters for a new EDNS request
	ipAddressClient    net.IP // IPv4 or IPv6 Address that will be seen in EDNS CS extension.
	sourcePrefixLength byte   // leftmost number of significant bits of ipAddressClient that can be used. the other bits of ipAddressClient must be padded with 0, according to RFC7871
	family             byte   // indicates the type of AddressFamily. Is in fact 2 bytes long in the ECS extension. Relevant for us are only IPv4 (=1) and IPv6 (=2)
	domainState        *domainState
}

type queryRequestList struct {
	queryRequests []*queryRequest
}

func (request *queryRequest) isNil() bool {
	erg := false
	if request.ipAddressClient == nil {
		erg = true
	}
	return erg
}

func (request *queryRequest) printNewRequest() {
	fmt.Println("		EDNS REQUEST Parameters (domain: '",
		request.domainState.domain,
		"', subnet: '",
		request.ipAddressClient, "/", request.sourcePrefixLength,
		"')")
}

///// SCANNER Types /////

type dnsResult interface{}
type queryResponse struct { //queryResponse contains the relevant content of one single DNS request and the corresponding DNS response.
	request           *queryRequest
	scopePrefixLength byte //leftmost number of bits the Authoritative NameServer wants to use
	error             error_type
}

type queryResponseList struct {
	responses []*queryResponse
}

func (response *queryResponse) printRequestAndResponse() {
	fmt.Println("		Scan Result (domain: '",
		response.request.domainState.domain,
		"', client subnet: '",
		response.request.ipAddressClient, "/", response.request.sourcePrefixLength,
		"', error: '",
		response.error,
		"', scope prefix length: '",
		response.scopePrefixLength,
		"')")
}

///// Global State types /////

type domainState struct { //domainState contains the Trie that represents the scanned IP addresses for one domain
	domain            string
	nameserverIP      net.IP
	identifier        string
	tempErrors        uint8
	permError         bool
	state             *root
	listResponseIndex int
	listScanIndex     int
}

type ipGeneratorRequest struct {
	domainState *domainState
	lastScans   []*queryResponse
}
