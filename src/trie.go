// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"math/rand"
	"slices"
	"sort"
)

const (
	SAMPLE_MODE = iota
	BGP_MODE
	BGP_PREFIX_MODE
	FINISHED_SCANNING
)

func isBGPannounced(prefix []uint8, isIPv6 bool) bool {
	isBGPPrefix := false
	prefixLengths, exists := bgpPrefixes[convertIPFromShortFieldToKeyInt(prefix, isIPv6)]
	if exists {
		isBGPPrefix = slices.Contains(prefixLengths, len(prefix))
	}
	return isBGPPrefix
}

func isSpecial(prefix []uint8, isIPv6 bool) bool {
	isSpecialPrefix := false
	prefixLengths, exists := specialPrefixes[convertIPFromShortFieldToKeyInt(prefix, isIPv6)]
	if exists {
		prefixLength := slices.Max(prefixLengths)
		isSpecialPrefix = prefixLength <= len(prefix)
	}
	return isSpecialPrefix
}

func hasBGPsubnet(prefix []uint8) bool {
	startKey := convertIPFromShortFieldToKeyInt(prefix, ipv6Scan)
	endKey := calculateBiggestKeyInSubnet(prefix, ipv6Scan)
	// Finds the smallest Index with a value larger than out network address (startKey)
	smallestKeyAfterStartKeyIndex := sort.Search(len(bgpPrefixesSlice),
		func(i int) bool {
			return bgpPrefixesSlice[i] >= startKey
		})
	if len(bgpPrefixesSlice) == smallestKeyAfterStartKeyIndex {
		return false
	}
	// Checks if the BGP prefixes network address is inside the checked prefix
	return bgpPrefixesSlice[smallestKeyAfterStartKeyIndex] <= endKey && bgpPrefixesSlice[smallestKeyAfterStartKeyIndex] >= startKey
}

// Allocate and fill a new child node
func makeNewNode(prefixUpToParent []uint8, thisValue uint8, kindOfNetParent uint8, isAnnounced bool) *node {
	// Default kind is UNANNOUNCED for all subnets
	kindOfPrefix := uint8(UNANNOUNCED)

	prefixHelpVariable := make([]uint8, len(prefixUpToParent))
	copy(prefixHelpVariable, prefixUpToParent)
	prefixIncludingValue := append(prefixHelpVariable, thisValue)
	if kindOfNetParent == SPECIAL || isSpecial(prefixIncludingValue, ipv6Scan) {
		kindOfPrefix = SPECIAL
	} else if isBGPannounced(prefixIncludingValue, ipv6Scan) {
		kindOfPrefix = BGPANNOUNCED
	}
	hasBGPnet := hasBGPsubnet(prefixIncludingValue)
	newNode := node{ //childs are nil
		whichKindofPrefix: kindOfPrefix,
		value:             thisValue,
		hasBGPsubnet:      hasBGPnet,
		childs:            make([]trieElement, 2),
		isAnnounced:       isAnnounced || kindOfPrefix == BGPANNOUNCED,
	}
	return &newNode
}

type trieElement interface {
	finishThisTrieElement() trieElement // summarizes this Trie Element (a leaf is returned that stores how many (BGPANNOUNCED)scans have been performed in the subtree
	finishChildElement(index uint8)
	//howManyScansAndBGPScansInsideThisPrefix() (int, int)      // returns number of scans (first returned int) and BGPANNOUNCED scans (second returned int) were performed in the network of this Prefix (equally precise and more precise scans are included)
	anyNotFinishedBGPSubnetsLeft(prefixUpToThis []uint8) bool // returns if there are any BGPANNOUNCED announced subnets in the current net, which have not been scansAnnounced enough (= are not finished)
	hasBGPSubnet() bool                                       // returns hasBGPsubnet value
	getChild(prefixUpToParent []uint8, index uint8) trieElement
	markAsInResponse() bool // increment the number of times this prefix has been referred to in responses and return if scanning for this node is complete
	getValue() uint8
	wasScanned() bool
	setScanned()
	setChildScanned(isBGPAnnounced bool)
	getScanningMode(currentPrefixUpToThis []uint8) int
	isBGPPrefix() bool
	isInAnnouncedSpace() bool
	isMarkedInResponse() bool
}

type leaf struct {
	leafScanned       uint8
	scansAnnounced    int
	scansUnnanounced  int
	whichKindofPrefix uint8 //indicates which kind of prefix this leaf represents (0 = non-BGPANNOUNCED or special use, 1 = BGPANNOUNCED announced). For possible more precise distinctions in the future no bool was used.
	hasBGPsubnet      bool
	value             uint8 // 0 or 1
	isAnnounced       bool
}

func (currentLeaf *leaf) getValue() uint8 {
	return currentLeaf.value
}

func (currentLeaf *leaf) wasScanned() bool {
	return currentLeaf.leafScanned >= 1
}

func (currentLeaf *leaf) setScanned() {
	currentLeaf.leafScanned += 1

	if currentLeaf.whichKindofPrefix == BGPANNOUNCED {
		currentLeaf.scansAnnounced += 1
	} else {
		currentLeaf.scansUnnanounced += 1
	}
}

func (currentLeaf *leaf) setChildScanned(isBGPAnnounced bool) {
	if isBGPAnnounced || currentLeaf.whichKindofPrefix == BGPANNOUNCED {
		currentLeaf.scansAnnounced += 1
	} else {
		currentLeaf.scansUnnanounced += 1
	}
}

func (currentLeaf *leaf) getScanningMode(_ []uint8) int {
	return FINISHED_SCANNING
}

func (currentLeaf *leaf) hasBGPSubnet() bool {
	return currentLeaf.hasBGPsubnet
}

func (currentLeaf *leaf) isBGPPrefix() bool {
	return currentLeaf.whichKindofPrefix == BGPANNOUNCED
}

func (currentLeaf *leaf) isInAnnouncedSpace() bool {
	return currentLeaf.isAnnounced
}

func (currentLeaf *leaf) handleResponse(_ []uint8, _ uint8) trieElement { //we have already cut that subnet
	return currentLeaf
}
func (currentLeaf *leaf) finishThisTrieElement() trieElement {
	return currentLeaf
}
func (currentLeaf *leaf) finishChildElement(_ uint8) {
	panic("leaf cannot finish child element")
}
func (currentLeaf *leaf) howManyScansAndBGPScansInsideThisPrefix() (int, int) {
	return currentLeaf.scansUnnanounced, currentLeaf.scansAnnounced
}
func (currentLeaf *leaf) getNewParameters(_ []uint8) ([]uint8, bool) {
	//if len(currentPrefix) == prefixLengthToScanWith {
	//	if !currentLeaf.wasScanned {
	//		currentLeaf.wasScanned = true
	//		return append(currentPrefix, currentLeaf.value), true, false
	//	}
	//}
	return nil, false
}

func (currentLeaf *leaf) anyNotFinishedBGPSubnetsLeft(_ []uint8) bool {
	return false
}

func (currentLeaf *leaf) getChild(_ []uint8, _ uint8) trieElement {
	return nil
}

func (currentLeaf *leaf) markAsInResponse() bool {
	return true
}

func (currentLeaf *leaf) isMarkedInResponse() bool {
	return true
}

type node struct {
	counterReturnedAsScope uint8 //how often have we received an ANS answer with that particular scope (indicating that all answers for requests with ClientIPs in this subnet would get the same answer)
	nodeScans              uint8 // number of scans for exactly this prefix
	scansAnounced          int
	scansUnanounced        int
	whichKindofPrefix      uint8 //indicates which kind of prefix this leaf represents
	hasBGPsubnet           bool
	isAnnounced            bool
	value                  uint8 // 0 or 1
	childs                 []trieElement
}

func (currentNode *node) getValue() uint8 {
	return currentNode.value
}

func (currentNode *node) wasScanned() bool {
	return currentNode.nodeScans >= 1
}

func (currentNode *node) setScanned() {
	currentNode.nodeScans += 1
	if currentNode.whichKindofPrefix == BGPANNOUNCED {
		currentNode.scansAnounced += 1
	} else {
		currentNode.scansUnanounced += 1
	}
}

func (currentNode *node) setChildScanned(isBGPAnnounced bool) {
	if isBGPAnnounced || currentNode.whichKindofPrefix == BGPANNOUNCED {
		currentNode.scansAnounced += 1
	} else {
		currentNode.scansUnanounced += 1
	}
}

func (currentNode *node) hasBGPSubnet() bool {
	return currentNode.hasBGPsubnet
}

func (currentNode *node) isBGPPrefix() bool {
	return currentNode.whichKindofPrefix == BGPANNOUNCED
}

func (currentNode *node) isInAnnouncedSpace() bool {
	return currentNode.isAnnounced
}

func (currentNode *node) finishThisTrieElement() trieElement {
	leaf := leaf{
		scansAnnounced:    currentNode.scansAnounced,
		scansUnnanounced:  currentNode.scansUnanounced,
		value:             currentNode.value,
		hasBGPsubnet:      currentNode.hasBGPsubnet,
		whichKindofPrefix: currentNode.whichKindofPrefix,
		isAnnounced:       currentNode.isAnnounced,
	}
	return &leaf
}

func (currentNode *node) finishChildElement(index uint8) {
	currentNode.childs[index] = currentNode.childs[index].finishThisTrieElement()
}

func (currentNode *node) getScanningMode(currentPrefixUpToThis []uint8) int {
	depth := len(currentPrefixUpToThis)

	if currentNode.whichKindofPrefix == SPECIAL && maxSpecialPrefixScans <= currentNode.scansUnanounced {
		debuglog("trie: finish scanning special prefix %v/%v", convertIPFromFieldToNetIP(currentPrefixUpToThis, ipv6Scan), depth)
		return FINISHED_SCANNING
	}

	var totalUnnanouncedLimitHit = currentNode.scansUnanounced+currentNode.scansAnounced >= totalNotroutedLimit
	var defaultMode = SAMPLE_MODE
	if totalUnnanouncedLimitHit {
		defaultMode = BGP_MODE
	}
	var noLimits = scanLimits[BGPANNOUNCED][depth] == 0 && scanLimits[UNANNOUNCED][depth] == 0 && scanLimits[TOTAL][depth] == 0
	if noLimits {
		return defaultMode
	}
	if currentNode.isMarkedInResponse() {
		if currentNode.anyNotFinishedBGPSubnetsLeft(currentPrefixUpToThis) {
			return BGP_PREFIX_MODE
		} else {
			debuglog("trie: finish scanning as marked in response %v/%v", convertIPFromFieldToNetIP(currentPrefixUpToThis, ipv6Scan), depth)
			return FINISHED_SCANNING
		}
	}
	var totalLimitHit = scanLimits[TOTAL][depth] != 0 && scanLimits[TOTAL][depth] <= currentNode.scansUnanounced+currentNode.scansAnounced
	var announcedLimitHit = scanLimits[BGPANNOUNCED][depth] != 0 && scanLimits[BGPANNOUNCED][depth] <= currentNode.scansAnounced
	var unannouncedLimitHit = scanLimits[UNANNOUNCED][depth] != 0 && scanLimits[UNANNOUNCED][depth] <= currentNode.scansUnanounced
	if totalLimitHit || announcedLimitHit || unannouncedLimitHit {
		var bgpLeft = currentNode.anyNotFinishedBGPSubnetsLeft(currentPrefixUpToThis)
		if totalLimitHit || announcedLimitHit {
			if bgpLeft {
				return BGP_PREFIX_MODE
			} else {
				debuglog("trie: finish scanning - limit hit %v %v --- %v/%v", announcedLimitHit, totalLimitHit, convertIPFromFieldToNetIP(currentPrefixUpToThis, ipv6Scan), depth)
				return FINISHED_SCANNING
			}
		} else {
			// Only hit unannounced limit -> scan only stuff which is in BGP announced space
			return BGP_MODE
		}
	} else {
		return defaultMode
	}
}
func (currentNode *node) anyNotFinishedBGPSubnetsLeft(prefixUpToThis []uint8) bool { //prefixUpToThis includes the value of the currentNode already

	if currentNode.whichKindofPrefix == BGPANNOUNCED && !currentNode.wasScanned() {
		//this node itself is a BGPANNOUNCED announced prefix and not finished yet.
		return true
	} else if !currentNode.hasBGPsubnet {
		return false
	}
	if len(prefixUpToThis) == prefixLengthToScanWith {
		return false
	}
	for index := range currentNode.childs {
		child := currentNode.getChild(prefixUpToThis, uint8(index))
		prefixHelpVariable3 := make([]uint8, len(prefixUpToThis))
		copy(prefixHelpVariable3, prefixUpToThis)
		if child.anyNotFinishedBGPSubnetsLeft(append(prefixHelpVariable3, uint8(index))) {
			return true
		}
	}

	return false
}

func (currentNode *node) getChild(currentPrefix []uint8, indexValue uint8) trieElement {
	if currentNode.childs[indexValue] == nil {
		//debuglog("node: Making new root child %v for %v", indexValue, prefixUpToParent)
		currentNode.childs[indexValue] = makeNewNode(currentPrefix, indexValue, currentNode.whichKindofPrefix, currentNode.isAnnounced)
	}
	return currentNode.childs[indexValue]
}

func (currentNode *node) markAsInResponse() bool {
	currentNode.counterReturnedAsScope++
	return currentNode.counterReturnedAsScope >= scanResultsToFinish
}

func (currentNode *node) isMarkedInResponse() bool {
	return currentNode.counterReturnedAsScope >= scanResultsToFinish
}

type root struct {
	scopeZeroObserved int
	rootIsScanned     bool
	childs            []trieElement
}

func (root *root) getValue() uint8 {
	panic("root has no value")
}

func (root *root) wasScanned() bool {
	return false
}

func (_ *root) setScanned() {
}

func (_ *root) setChildScanned(_ bool) {
}

func (root *root) finishThisTrieElement() trieElement {
	return nil
}

func (root *root) finishChildElement(index uint8) {
	root.childs[index] = root.childs[index].finishThisTrieElement()
}

func (root *root) hasBGPSubnet() bool {
	return len(bgpPrefixes) > 0
}

func (_ *root) isBGPPrefix() bool {
	return false
}

func (_ *root) isInAnnouncedSpace() bool {
	return false
}

func (root *root) anyNotFinishedBGPSubnetsLeft(prefixUpToThis []uint8) bool {
	for _, child := range root.childs {
		if child != nil {
			if child.anyNotFinishedBGPSubnetsLeft(prefixUpToThis) {
				return true
			}
		}
	}
	return false
}

func getNewParameters(nodeElement trieElement, prefixUpToParent []uint8) []uint8 {
	prefix, _ := getNewParametersWithMode(nodeElement, prefixUpToParent, SAMPLE_MODE)
	return prefix
}

func getNewParametersWithMode(nodeElement trieElement, prefixUpToParent []uint8, scanningMode int) ([]uint8, bool) {
	if prefixLengthToScanWith <= 0 {
		panic("prefixLengthToScanWith cannot be <= 0")
	}

	currentPrefixSlice := make([]uint8, len(prefixUpToParent))
	switch nodeElement.(type) {
	case *node:
		copy(currentPrefixSlice, prefixUpToParent)
		currentPrefixSlice = append(currentPrefixSlice, nodeElement.getValue())
	case *leaf:
		return nil, false
	}
	lengthOfCurrentPrefix := len(currentPrefixSlice)

	var nodeScanningMode = nodeElement.getScanningMode(currentPrefixSlice)
	if nodeScanningMode == FINISHED_SCANNING {
		return nil, false
	}
	if nodeScanningMode > scanningMode {
		scanningMode = nodeScanningMode
	}
	if (scanningMode == BGP_MODE || scanningMode == BGP_PREFIX_MODE) && !nodeElement.hasBGPSubnet() && !nodeElement.isInAnnouncedSpace() {
		return nil, false
	}

	// depth to scan with is reached
	if lengthOfCurrentPrefix == prefixLengthToScanWith {
		if nodeElement.wasScanned() {
			return nil, false
		} else if scanningMode == SAMPLE_MODE || (scanningMode == BGP_PREFIX_MODE && nodeElement.isBGPPrefix()) || (scanningMode == BGP_MODE && nodeElement.isInAnnouncedSpace()) {
			nodeElement.setScanned()
			return currentPrefixSlice, nodeElement.isBGPPrefix()
		} else {
			return nil, false
		}
	}

	firstChildIndex := uint8(0)
	if lengthOfCurrentPrefix >= randomizeDepth {
		firstChildIndex = uint8(rand.Int() % 2)
	}
	secondChildIndex := uint8(1)
	if firstChildIndex == 1 {
		secondChildIndex = 0
	}
	var searchOrder = make([]trieElement, 2)
	var childAvailable = false
	var onlySecondChildHasBGP = true
	for sliceIndex, childIndex := range []uint8{firstChildIndex, secondChildIndex} {
		searchOrder[sliceIndex] = nodeElement.getChild(currentPrefixSlice, childIndex)
		switch searchOrder[sliceIndex].(type) {
		case *leaf:
			searchOrder[sliceIndex] = nil
		default:
			if scanningMode == BGP_PREFIX_MODE && !searchOrder[sliceIndex].isBGPPrefix() && !searchOrder[sliceIndex].hasBGPSubnet() {
				debuglog("trie: finish child because of BGP prefix scanning mode %v/%v scanning mode %v", convertIPFromFieldToNetIP(append(currentPrefixSlice, searchOrder[sliceIndex].getValue()), ipv6Scan), lengthOfCurrentPrefix+1, scanningMode)
				nodeElement.finishChildElement(childIndex)
				searchOrder[sliceIndex] = nil
			} else if searchOrder[sliceIndex].wasScanned() {
				debuglog("trie: finish child because it was scansAnnounced %v/%v scanning mode %v", convertIPFromFieldToNetIP(append(currentPrefixSlice, searchOrder[sliceIndex].getValue()), ipv6Scan), lengthOfCurrentPrefix+1, scanningMode)
				nodeElement.finishChildElement(childIndex)
				searchOrder[sliceIndex] = nil
			} else {
				if (sliceIndex == 0 && (searchOrder[sliceIndex].hasBGPSubnet() || searchOrder[sliceIndex].isInAnnouncedSpace())) ||
					(sliceIndex == 1 && !searchOrder[sliceIndex].hasBGPSubnet() && !searchOrder[sliceIndex].isInAnnouncedSpace()) {
					onlySecondChildHasBGP = false
				}
				childAvailable = true
			}
		}
	}
	if childAvailable {
		if onlySecondChildHasBGP {
			searchOrder = []trieElement{searchOrder[1], searchOrder[0]}
		}

		for index, child := range searchOrder {
			if child == nil {
				continue
			}
			childPrefix, prefixIsAnnounced := getNewParametersWithMode(child, currentPrefixSlice, scanningMode)
			if childPrefix != nil {
				nodeElement.setChildScanned(prefixIsAnnounced)
				return childPrefix, prefixIsAnnounced || nodeElement.isBGPPrefix()
			} else {
				debuglog("trie: finish child because it told us no more scans to do %v/%v scanning mode %v", convertIPFromFieldToNetIP(append(currentPrefixSlice, child.getValue()), ipv6Scan), lengthOfCurrentPrefix+1, scanningMode)
				if index == 0 {
					nodeElement.finishChildElement(firstChildIndex)
				} else {
					nodeElement.finishChildElement(secondChildIndex)
				}
			}
		}
	}

	if nodeElement.isBGPPrefix() {
		nodeElement.setScanned()
		return currentPrefixSlice, true
	}
	return nil, false
} // get the next prefix of Length prefixLength that has not been finished yet . if the second return value is false, it means that we have finished scanning for all prefixes with this prefix length

func (root *root) getChild(prefixUpToParent []uint8, index uint8) trieElement {
	if root.childs[index] == nil {
		debuglog("TRIE: Making new root child")
		root.childs[index] = makeNewNode(prefixUpToParent, index, UNANNOUNCED, false)
	}
	return root.childs[index]
}

func (_ *root) markAsInResponse() bool {
	return false
}

func (_ *root) isMarkedInResponse() bool {
	return false
}

func (root *root) getScanningMode(currentPrefixUpToThis []uint8) int {
	var scanningMode = FINISHED_SCANNING
	for _, child := range root.childs {
		if child != nil {
			var childMode = child.getScanningMode(currentPrefixUpToThis)
			if childMode < scanningMode {
				scanningMode = childMode
			}
		} else {
			return SAMPLE_MODE
		}
	}
	return scanningMode
}

// increments the counter of indications from the ANS that there will be the same answer for all IPs in a certain subnet. If the counter exceeds a threshold the subtree will be summarized
// depth of root is -1!
func handleResponse(currentNode trieElement, shortenedLastClientIP []uint8, depth uint8) bool {
	if currentNode == nil {
		// found leaf node -> we do not care anymore about results there
		return false
	}
	if uint8(len(shortenedLastClientIP)) == depth {
		return currentNode.markAsInResponse()
	} else { //we have not reached the responsible node that represents the received lastClientIP/scopePrefixLength
		if handleResponse(currentNode.getChild(shortenedLastClientIP[:depth], shortenedLastClientIP[depth]), shortenedLastClientIP, depth+1) {
			return currentNode.getScanningMode(shortenedLastClientIP[:depth]) == FINISHED_SCANNING
		} else {
			return false
		}
	}
}

func (root *root) rootHandleResponse(shortenedLastClientIP []uint8) bool {
	if len(shortenedLastClientIP) > 0 {
		return handleResponse(root, shortenedLastClientIP, 0)
	} else {
		root.scopeZeroObserved += 1
		return maxNumScopeZeros > 0 && root.scopeZeroObserved > maxNumScopeZeros
	}
}
