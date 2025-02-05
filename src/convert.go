// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"net"
)

func bytesForIpVersion(isIPv6 bool) int {
	if isIPv6 {
		return net.IPv6len
	} else {
		return net.IPv4len
	}
}

func convertIPFromNetIPToField(ipAsNetIP net.IP, isIPv6 bool) []uint8 {
	var asField []uint8
	var ipBytes = bytesForIpVersion(isIPv6)
	for i := 0; i < ipBytes; i++ {
		x := int(ipAsNetIP[i])
		for j := 7; j >= 0; j-- {
			if x >= 1<<j { //x >= 2^j
				asField = append(asField, 1)
				x = x - (1 << j) //x = x - 2^j
			} else {
				asField = append(asField, 0)
			}
		}
	}
	return asField
}

func convertIPFromFieldToNetIP(ipAsField []uint8, isIPv6 bool) net.IP {
	var ipBytes = bytesForIpVersion(isIPv6)
	bytesOfIP := make([]byte, ipBytes)
	for i := len(ipAsField); i < ipBytes*8; i++ {
		ipAsField = append(ipAsField, 0)
	}
	for i := 0; i < ipBytes; i++ {
		var x byte
		x = 0
		for j := 8; j > 0; j-- {
			if ipAsField[i*8+j-1] == 1 {
				x = x + (1 << (8 - byte(j))) //x = x + 2^(8-j)
			}
		}
		bytesOfIP[i] = x
	}
	return bytesOfIP
}

func convertIPFromStringToKeyInt(ipAsString string) int64 {
	ip := net.ParseIP(ipAsString)
	var ipAsInt int64 = 0
	for i, bytevalue := range ip {
		if i >= 8 {
			break
		}
		ipAsInt = int64(bytevalue) + (ipAsInt << 8)
	}
	return ipAsInt
}

func convertIPFromShortFieldToKeyInt(ipAsShortField []uint8, isIPv6 bool) int64 {
	var ipAsInt int64 = 0
	for i := uint8(0); i < uint8(len(ipAsShortField)); i++ {
		currentBit := ipAsShortField[i]
		ipAsInt = (ipAsInt << 1) + int64(currentBit)
	}
	var ipBytes = bytesForIpVersion(isIPv6)
	if isIPv6 {
		// we only use the first 64 bits
		ipBytes = ipBytes / 2
	}
	for i := len(ipAsShortField); i < ipBytes*8; i++ {
		ipAsInt = ipAsInt << 1
	}
	return ipAsInt
}

func calculateBiggestKeyInSubnet(ipAsShortField []uint8, isIPv6 bool) int64 {
	var ipAsInt int64 = 0
	for i := uint8(0); i < uint8(len(ipAsShortField)); i++ {
		currentBit := ipAsShortField[i]
		ipAsInt = (ipAsInt << 1) + int64(currentBit)
	}
	var ipBytes = bytesForIpVersion(isIPv6)
	if isIPv6 {
		// we only use the first 64 bits
		ipBytes = ipBytes / 2
	}
	for i := len(ipAsShortField); i < ipBytes*8; i++ {
		ipAsInt = ipAsInt << 1
		ipAsInt++
	}
	return ipAsInt
}

func firstBitsOfIPasField(scope byte, ip []uint8) []uint8 {
	return ip[:scope]
}

func ensureConcatinatingWithZeros(ip net.IP, scope byte, isIPv6 bool) net.IP {
	var ipBytes = bytesForIpVersion(isIPv6)
	sourcePrefixMask := net.CIDRMask(int(scope), ipBytes*8)
	newIP := ip.Mask(sourcePrefixMask) //we ensure that the bit representation of IP address indeed is padded with 0 after the amount of sourcePrefix has ended
	return newIP
}
