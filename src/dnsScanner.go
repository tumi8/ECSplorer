// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"github.com/miekg/dns"
	"net"
	"strconv"
	"time"
)

var localAddress *net.IP

func InitScanner(localAddressIP net.IP) {
	localAddress = &localAddressIP
}

func scannerHandler(requestChan <-chan *ipGeneratorResult, controllerQueue *ControllerQueue) { //scannerHandler simulates a scanner
	for requestInterface := range requestChan {
		if requestInterface == nil {
			break
		}

		request := (*requestInterface).(queryRequest)

		debuglog("scannerHandler received request for %v with %v / %v", request.domainState.domain, request.ipAddressClient, request.sourcePrefixLength)

		<-limiter

		var result dnsResult = *performQuery(&request)
		controllerQueue.condition.L.Lock()
		controllerQueue.sliceScannerToController = append(controllerQueue.sliceScannerToController, &result)
		controllerQueue.condition.Signal()
		controllerQueue.condition.L.Unlock()
	}
}

func scannerListHandler(requestChan <-chan *ipGeneratorResult, controllerQueue *ControllerQueue) { //scannerHandler simulates a scanner
	for requestInterface := range requestChan {
		if requestInterface == nil {
			break
		}

		request := (*requestInterface).(queryRequestList)

		debuglog("scannerHandler received request list of domains with length %v", len(request.queryRequests))

		var resultObj queryResponseList
		for _, queryRequest := range request.queryRequests {
			<-limiter

			result := performQuery(queryRequest)
			resultObj.responses = append(resultObj.responses, result)
		}
		var dnsresult dnsResult = resultObj
		controllerQueue.condition.L.Lock()
		controllerQueue.sliceScannerToController = append(controllerQueue.sliceScannerToController, &dnsresult)
		controllerQueue.condition.Signal()
		controllerQueue.condition.L.Unlock()
	}
}

func createDNSMessage(request *queryRequest) *dns.Msg {
	qname := dns.Fqdn(request.domainState.domain)

	var qtype uint16 // Type to be queried, e.g. A,
	if request.family == 1 {
		qtype = dns.TypeA
	} else {
		qtype = dns.TypeAAAA
	}
	qclass := uint16(dns.ClassINET)

	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Authoritative:     false,
			AuthenticatedData: false,
			CheckingDisabled:  false,
			RecursionDesired:  resolver != "",
			Opcode:            dns.OpcodeQuery,
			Rcode:             dns.RcodeSuccess,
		},
		Question: make([]dns.Question, 1),
	}
	optrr := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	nsid_option := &dns.EDNS0_NSID{
		Code: dns.EDNS0NSID,
	}
	optrr.Option = append(optrr.Option, nsid_option)
	// NSD will not return nsid when the udp message size is too small
	optrr.SetUDPSize(dns.DefaultMsgSize)
	ecs_option := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Address:       request.ipAddressClient,
		Family:        uint16(request.family),
		SourceNetmask: request.sourcePrefixLength,
	}

	optrr.Option = append(optrr.Option, ecs_option)
	msg.Extra = append(msg.Extra, optrr)
	msg.Question[0] = dns.Question{Name: qname, Qtype: qtype, Qclass: qclass}
	msg.Id = dns.Id()

	return msg
}

func performQuery(request *queryRequest) *queryResponse {
	msg := createDNSMessage(request)

	c := new(dns.Client)
	c.DialTimeout = *timeoutDial
	c.ReadTimeout = *timeoutRead
	c.WriteTimeout = *timeoutWrite
	c.Dialer = &net.Dialer{Timeout: c.DialTimeout}

	if localAddress != nil {
		c.Dialer.LocalAddr = &net.UDPAddr{IP: *localAddress}
	}

	nameserverPort := net.JoinHostPort(request.domainState.nameserverIP.String(), strconv.Itoa(53))
	var response *dns.Msg
	var err error
	response, _, err = c.Exchange(msg, nameserverPort)

	var answers []string
	var cnames []string

	var optrr *dns.OPT

	ecs := &dns.EDNS0_SUBNET{
		SourceScope: 255,
	}
	var nsid *dns.EDNS0_NSID

	var errorType error_type = NO_ERR
	var errStr string = ""
	if err != nil {
		// Assuming a timeout here 3 retries
		for i := 0; i < retries; i++ {
			response, _, err = c.Exchange(msg, nameserverPort)
			if err == nil {
				break
			} else if i > 0 {
				c.Net = "tcp"
			}
		}
		if err != nil {
			errorType = INTERNAL_ERR
			debuglog("Result is not usable after 3 retries. Got error %s", err)
			errStr = err.Error()
			goto exit
		}
	}

	if response.Truncated {
		c.Net = "tcp"
		for i := 0; i < retries; i++ {
			response, _, err = c.Exchange(msg, nameserverPort)
			if err == nil {
				break
			}
		}
		if err != nil {
			errorType = TRUNCATED_NO_TCP
			debuglog("Result is not usable. Got error %s", err)
			errStr = err.Error()
			goto exit
		}
	}

	if !response.Authoritative && resolver == "" {
		debuglog("Received response does not point to authoritative name server")
		errorType = NO_AUTH
		goto exit
	}

	if len(response.Extra) == 0 {
		debuglog("Received response does not contain Additional RRs")
		errorType = NO_ADD
	}

	optrr = response.IsEdns0()
	if optrr == nil {
		debuglog("Received response has no EDNS RR")
		errorType = NO_EDNS
	} else {

		for _, ednsoption := range optrr.Option {
			switch ednsoption.(type) {
			case *dns.EDNS0_SUBNET:
				ecs = ednsoption.(*dns.EDNS0_SUBNET)
				if ecs.Family != uint16(request.family) {
					errorlog("wrong family in ECS")
					errorType = WRONG_FAM
					errStr = ecs.String()
					goto exit
				}

				if (ecs.Family == 1 && ecs.SourceNetmask > 32) || (ecs.Family == 2 && ecs.SourceNetmask > 128) {
					errorlog("impossible Source prefix length")
					errorType = SCOPE_OOB
					errStr = ecs.String()
					goto exit
				}
				if !ecs.Address.Equal(request.ipAddressClient) {
					errorlog("returned wrong ip address in ecs")
					errorType = WRONG_PARAM
					errStr = ecs.String()
					goto exit
				}
			case *dns.EDNS0_NSID:
				nsid = ednsoption.(*dns.EDNS0_NSID)
			}
		}
		if ecs.SourceScope == 255 {
			errorType = NO_ECS
		}
	}

	for _, answer := range response.Answer {
		debuglog("Received valid response, counting answers")
		switch answer.(type) {
		case *dns.A:
			answers = append(answers, answer.(*dns.A).A.String())
		case *dns.AAAA:
			answers = append(answers, answer.(*dns.AAAA).AAAA.String())
		case *dns.CNAME:
			cnames = append(cnames, answer.(*dns.CNAME).Target)
		}

	}

exit:
	if nsid != nil {
		err = EcsResultWriter.writeECSResult(time.Now(), request.domainState.domain, request.domainState.nameserverIP, request.family, request.sourcePrefixLength, ecs.SourceScope, request.ipAddressClient, answers, cnames, errorType, nsid.Nsid, errStr)
	} else {
		err = EcsResultWriter.writeECSResult(time.Now(), request.domainState.domain, request.domainState.nameserverIP, request.family, request.sourcePrefixLength, ecs.SourceScope, request.ipAddressClient, answers, cnames, errorType, "[]", errStr)
	}
	if err != nil {
		errorlog("failed writing result for %s", request.domainState.domain)
	}

	var qResponse queryResponse
	qResponse = queryResponse{
		request:           request,
		scopePrefixLength: ecs.SourceScope,
		error:             errorType,
	}

	return &qResponse
}
