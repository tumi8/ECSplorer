// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"net"
)

/*
ipgenerator takes a new order (order contains the important parts of the state for one Domain (e.g. last request
and radix trie, that illustrates all former scans, needed for generating the next request parameters.
Based on these parameters the requestGenerator generates the new parameters for the next DNS request for that particular Domain. This includes a Client IP Address and a
source prefix length. It also includes whether this was the last EDNS request for this Domain (finished flag).
*/

func ipgenerator(requests <-chan *ipGeneratorRequest, controllerQueue *ControllerQueue) {
	if queryListFile != "" {
		listGenerator(requests, controllerQueue)
	} else {
		trieGenerator(requests, controllerQueue)
	}
}

// This generate parameters from a given list
func listGenerator(requests <-chan *ipGeneratorRequest, controllerQueue *ControllerQueue) {
	var maxInfligth = 500
	var maxListLength = 1000
	for receivedRequest := range requests {
		receivedRequest.domainState.listResponseIndex += len(receivedRequest.lastScans)
		var newResult ipGeneratorResult
		if receivedRequest.domainState.listScanIndex < len(queryList) && receivedRequest.domainState.listResponseIndex > receivedRequest.domainState.listScanIndex-maxInfligth {
			newResult = getRequestQueryList(receivedRequest, maxListLength)
		} else {
			if receivedRequest.domainState.listResponseIndex >= len(queryList) {
				newResult = domainScanFinished{
					domainState: receivedRequest.domainState,
				}
			} else {
				newResult = waitingForMoreResults{
					domainState: receivedRequest.domainState,
				}
			}
		}

		controllerQueue.condition.L.Lock()
		debuglog("IPGenerator: adding new query Parameters %+v.", newResult)
		controllerQueue.sliceIPGeneratorToController = append(controllerQueue.sliceIPGeneratorToController, &newResult) //the newly generated parameters will be sent back to the Controller via the responses queue
		controllerQueue.condition.Signal()
		controllerQueue.condition.L.Unlock()
	}
}

func getRequestQueryList(receivedRequest *ipGeneratorRequest, maxListLength int) ipGeneratorResult {
	var results []*queryRequest
	for _, listElement := range queryList[receivedRequest.domainState.listScanIndex:] {
		length, _ := listElement.Mask.Size()
		ip := listElement.IP
		var family byte
		// to check wether the ip is an IPv4 or IPv6
		if ip.To4() == nil {
			family = 2
		} else {
			family = 1
		}
		var resultElement = queryRequest{
			ipAddressClient:    ip,
			sourcePrefixLength: byte(length),
			family:             family,
			domainState:        receivedRequest.domainState,
		}
		receivedRequest.domainState.listScanIndex += 1
		results = append(results, &resultElement)
		// limit result size to 1000 elements
		if len(results) >= maxListLength {
			break
		}
	}
	return queryRequestList{
		queryRequests: results,
	}
}

// if not explicit domain list was given we use a trie based approach to
// get new parameters
func trieGenerator(requests <-chan *ipGeneratorRequest, controllerQueue *ControllerQueue) {
	for receivedRequest := range requests {
		if receivedRequest == nil {
			debuglog("IPGENERATOR: Channel was closed, exiting.")
			break //intended for dealing with closing the channel
		}
		debuglog("IPGenerator: Received request for %+v.", *receivedRequest.domainState)

		//the parameters for the "calculateNextParameters" function are set.
		var lastScanClientIP net.IP
		var lastScanScope byte
		var newResult ipGeneratorResult

		// trieGenerator can only receive a single response
		if len(receivedRequest.lastScans) > 1 {
			panic("Trie generator cannot receive more than a single result")
		}

		if len(receivedRequest.lastScans) == 0 { //check if this domain has not been scanned before
			debuglog("IPGenerator: Received request for new domain initializing new trie")
			newRoot := root{childs: make([]trieElement, 2), scopeZeroObserved: 0, rootIsScanned: false}
			receivedRequest.domainState.state = &newRoot
		} else {
			lastScan := receivedRequest.lastScans[0]
			if lastScan.error == 0 {
				lastScanClientIP = lastScan.request.ipAddressClient
				lastScanScope = lastScan.scopePrefixLength
				if lastScan.request.sourcePrefixLength < lastScanScope {
					lastScanScope = lastScan.request.sourcePrefixLength
				}
				lastScanClientIPShortened := firstBitsOfIPasField(lastScanScope, convertIPFromNetIPToField(lastScanClientIP, ipv6Scan))
				if receivedRequest.domainState.state.rootHandleResponse(lastScanClientIPShortened) {
					// domain scanning finished
					newResult = domainScanFinished{
						domainState: receivedRequest.domainState,
					}
				}
			}
		}

		if newResult == nil {
			if receivedRequest.domainState.permError || receivedRequest.domainState.tempErrors > byte(maximumTempErrors) {
				// if there was a permanent error or more then 3 temporary errors, we will not calculate new parameters
				debuglog("IPGENERATOR: Too many errors on domain %v, finishing scanning", receivedRequest.domainState.domain)
				newResult = domainScanFinished{
					domainState: receivedRequest.domainState,
				}
			} else {
				debuglog("IPGENERATOR: Calculating new ECS parameters")
				//generates the next parameters (Client IP and Client source Scope) based on previous scans
				newIPforNewScope, newSourcePrefix, finished := calculateNextParameters(receivedRequest.domainState.state)
				if finished {
					newResult = domainScanFinished{
						domainState: receivedRequest.domainState,
					}
				} else {
					var family uint8 = 1
					if ipv6Scan {
						family = 2
					}
					newResult = queryRequest{
						ipAddressClient:    newIPforNewScope,
						sourcePrefixLength: newSourcePrefix,
						family:             family,
						domainState:        receivedRequest.domainState,
					}
				}
			}
		}

		controllerQueue.condition.L.Lock()
		debuglog("IPGenerator: adding new query Parameters %+v.", newResult)
		controllerQueue.sliceIPGeneratorToController = append(controllerQueue.sliceIPGeneratorToController, &newResult) //the newly generated parameters will be sent back to the Controller via the responses queue
		controllerQueue.condition.Signal()
		controllerQueue.condition.L.Unlock()
	}
}

func calculateNextParameters(trie *root) (net.IP, byte, bool) {
	var newNet []uint8

	newNet = getNewParameters(trie, make([]uint8, 0))
	if newNet == nil {
		return nil, 0, true
	} else {
		newSource := byte(len(newNet))
		newIPhelp := convertIPFromFieldToNetIP(newNet, ipv6Scan)
		return ensureConcatinatingWithZeros(newIPhelp, newSource, ipv6Scan), newSource, false
	}
}
