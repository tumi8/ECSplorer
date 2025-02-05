// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"reflect"
	"sync"
)

func printDomainResult(scannedDomain *domainState) {
	debuglog("CONTROLLER:   Domain : %v", scannedDomain.domain)
	if printFinalResult {
		debuglog("	Scanned Domain: %v", scannedDomain.domain)
		debuglog("      With element: %v", scannedDomain)
	}
}

/*
Controller is responsible for taking a list of domain names that need to be scanned.
The controller keeps track of the state of each domain and sends the state of a domain to the ipgenerator. The ipgenerator answers with the next EDNS-parameters.
The controller then sends the ECS-parameters to the scannerHandler (a function to convert the request into the right format), that will forward it to the Scanner.
After receiving the answer from the scanner via the receiveResponse function, the controller orders new EDNS-parameters from the ip generator. This repeats until scanning is finished.
*/
func controller(nextDomainState func() *domainState) {
	debuglog("CONTROLLER:   Function was started.")

	channelControllerToIPGenerator := make(chan *ipGeneratorRequest, capacityForChannelsFlag)
	channelControllerToScannerHandler := make(chan *ipGeneratorResult, capacityForChannelsFlag)
	debuglog("CONTROLLER:   All Channels are initialized.")

	//create ControllerQueue that communicates the new requests from the IP Generator to the Controller and the completed scans from the scanner to the controller
	var controllerQueue ControllerQueue
	controllerQueue.condition = sync.NewCond(&sync.Mutex{})
	controllerQueue.sliceIPGeneratorToController = make([]*ipGeneratorResult, 0, 1)
	controllerQueue.sliceScannerToController = make([]*dnsResult, 0, 1)
	debuglog("CONTROLLER:   The controllerQueue is initialized.")

	//create IP generators, scanner and scannerHandlers
	for i := numberOfIPGenerators; i > 0; i-- {
		go ipgenerator(channelControllerToIPGenerator, &controllerQueue)
	}
	for i := 0; i < queryRate; i++ {
		if len(queryList) > 0 {
			go scannerListHandler(channelControllerToScannerHandler, &controllerQueue)
		} else {
			go scannerHandler(channelControllerToScannerHandler, &controllerQueue)
		}
	}
	debuglog("CONTROLLER:   All IP Generators and the ScannerHandler is initialized.")

	currentlyScannedDomains := make(map[string]struct{}) // map of all scanned Domains with their Domain+nameserverip as key and a pointer to their state as value. Includes also Domains for whose scanning has already been finished.

	/*
		For the given capacity of a channel, we start with that amount of domains in our scanning routines. For each of these domains
		we send their state (currently quite empty as nothing has been scanned) to the channel to the IP Generator so that the IP
		Generator can calculate the first parameters for the first scan of these domains. We also increment the waitinggroup for each of them
	*/
	var noMoreDomains = false

	for !noMoreDomains || len(currentlyScannedDomains) > 0 {
		// add new requests to queue
		for len(currentlyScannedDomains) < domainOutstanding && !noMoreDomains {
			domainState := nextDomainState()
			if domainState == nil {
				noMoreDomains = true
				debuglog("Controller: no more domains available to scan")
			} else {
				currentlyScannedDomains[domainState.identifier] = struct{}{}
				newRequest := ipGeneratorRequest{
					domainState: domainState,
				}
				debuglog("CONTROLLER: Request to IP Generator will be sent for %v ", domainState.domain)
				channelControllerToIPGenerator <- &newRequest
			}
		}

		controllerQueue.condition.L.Lock()

		if len(controllerQueue.sliceScannerToController) == 0 && len(controllerQueue.sliceIPGeneratorToController) == 0 && (!noMoreDomains || len(currentlyScannedDomains) > 0) {
			// if no new request or response is there wait for one but only wait if there is something to wait for
			controllerQueue.condition.Wait()
		}
		debuglog("Controller: ipgenlen %v", len(controllerQueue.sliceIPGeneratorToController))
		debuglog("Controller: scan_resultslen %v", len(controllerQueue.sliceScannerToController))
		if len(controllerQueue.sliceIPGeneratorToController) > 0 {
			// Process new request
			newRequest := *controllerQueue.sliceIPGeneratorToController[0]
			controllerQueue.sliceIPGeneratorToController = controllerQueue.sliceIPGeneratorToController[1:] //we receive new request parameters from an IP generator

			debuglog("Controller: ipgen type %v", reflect.TypeOf(newRequest))
			switch newRequest.(type) {
			case domainScanFinished:
				debuglog("CONTROLLER:   We have finished scanning for Domain %v ", newRequest.(domainScanFinished).domainState.domain)
				printDomainResult(newRequest.(domainScanFinished).domainState)
				delete(currentlyScannedDomains, newRequest.(domainScanFinished).domainState.identifier)
			case waitingForMoreResults:
				debuglog("CONTROLLER:   Waiting for more results for %v", newRequest.(waitingForMoreResults).domainState.domain)
				break
			case queryRequest:
				newQueryRequest := newRequest.(queryRequest)
				debuglog("CONTROLLER:   IPGen sent us: Domain = %v , IP = %v / %v ", newQueryRequest.domainState.domain, newQueryRequest.ipAddressClient, newQueryRequest.sourcePrefixLength)
				debuglog("CONTROLLER:   We now send the new Request to the scannerHandler")
				channelControllerToScannerHandler <- &newRequest
			case queryRequestList:
				requestList := newRequest.(queryRequestList).queryRequests
				debuglog("CONTROLLER:   Sending Request list with len %v", len(requestList))
				channelControllerToScannerHandler <- &newRequest
			}
		}
		if len(controllerQueue.sliceScannerToController) > 0 {
			// Process new result
			newCompletedScan := *controllerQueue.sliceScannerToController[0]
			controllerQueue.sliceScannerToController = controllerQueue.sliceScannerToController[1:]
			var newOrder *ipGeneratorRequest
			switch newCompletedScan.(type) {
			case queryResponse:
				queryResponseObj := newCompletedScan.(queryResponse)
				if isPerm(queryResponseObj.error) {
					queryResponseObj.request.domainState.permError = true
				}
				if queryResponseObj.error != 0 {
					queryResponseObj.request.domainState.tempErrors++
				}
				debuglog("CONTROLLER:   Scanner sent us: domain = %v , ClientIP = %v / %v Scope PL = %v", queryResponseObj.request.domainState.domain, queryResponseObj.request.ipAddressClient, queryResponseObj.request.sourcePrefixLength, queryResponseObj.scopePrefixLength)

				newOrder = &ipGeneratorRequest{
					domainState: queryResponseObj.request.domainState,
					lastScans:   []*queryResponse{&queryResponseObj},
				}
			case queryResponseList:
				queryResponseList := newCompletedScan.(queryResponseList)
				var domainState *domainState
				for _, queryResponseObj := range queryResponseList.responses {
					if isPerm(queryResponseObj.error) {
						queryResponseObj.request.domainState.permError = true
					}
					if queryResponseObj.error != 0 {
						queryResponseObj.request.domainState.tempErrors++
					}
					debuglog("CONTROLLER:   Scanner sent us: domain = %v , ClientIP = %v / %v Scope PL = %v", queryResponseObj.request.domainState.domain, queryResponseObj.request.ipAddressClient, queryResponseObj.request.sourcePrefixLength, queryResponseObj.scopePrefixLength)
					domainState = queryResponseObj.request.domainState
				}

				newOrder = &ipGeneratorRequest{
					domainState: domainState,
					lastScans:   queryResponseList.responses,
				}
			}

			channelControllerToIPGenerator <- newOrder
		}

		controllerQueue.condition.L.Unlock()
	}
	debuglog("CONTROLLER:   We will now close all channels")
	close(channelControllerToIPGenerator)
	close(channelControllerToScannerHandler)
	debuglog("CONTROLLER:   We have closed all channels")
}
