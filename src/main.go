// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/spf13/viper"
	"math"
	"net"
	"os"
	"os/signal"
	"runtime/pprof"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func startLogging() { //will  initialize the Logging functionality. This will depend on the level of Logging specified and the fileToLogTo specified. If no fileToLogTo was specified, we will use the standard error
	//We use two loggers. One for the scanner and one for the backend

	var logFile *os.File
	if fileToLogTo != "" {
		var err error
		logFile, err = os.OpenFile(fileToLogTo, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 666)
		if err != nil {
			panic("could not create logging file")
		}
	} else {
		logFile = os.Stderr
	}
	switch loggingLevel {
	case 3:
		Init_Logging(logFile, logFile, logFile)
	case 2:
		Init_Logging(LogDiscard, logFile, logFile)
	case 1:
		Init_Logging(LogDiscard, LogDiscard, logFile)
	case 0:
		Init_Logging(logFile, logFile, logFile)
	}
}

func readQueryList() {
	if queryListFile == "" {
		return
	}
	file, err := os.Open(queryListFile)
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			errorlog("could not close querylist file")
		}
	}(file)
	if err != nil {
		errorlog("MAIN:   could not read File %v !", queryListFile)
		panic("Could not read the file containg query list")

	}
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		_, nextNet, err := net.ParseCIDR(scanner.Text())
		if err != nil {
			errorlog(err.Error())
			continue
		}
		queryList = append(queryList, *nextNet)
	}
}

func readSpecialprefixesAndInitializeCorespondingmap() {
	specialPrefixes = make(map[int64][]int)
	if specialPrefixesFile != "" {
		fileSpecial, err := os.Open(specialPrefixesFile)
		if err != nil {
			errorlog("MAIN:   could not read File %v !", specialPrefixesFile)
			panic("Could not read the file for special (e.g. private) prefixes.")

		}
		scanner := bufio.NewScanner(fileSpecial)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			nextSpecialNet := scanner.Text()
			splittedNextSpecialnet := strings.Split(nextSpecialNet, "/")
			prefixLength, err := strconv.Atoi(splittedNextSpecialnet[1])
			if err != nil {
				errorlog("Reading '%v' from File with special prefixes produced error: %s", nextSpecialNet, err)
			} else {
				ipAsInt := convertIPFromStringToKeyInt(splittedNextSpecialnet[0])
				storedPrefixLengths, ok := specialPrefixes[ipAsInt]
				if ok {
					specialPrefixes[ipAsInt] = append(storedPrefixLengths, prefixLength)
				} else {
					specialPrefixes[ipAsInt] = []int{prefixLength}
				}
			}
		}
		for k := range specialPrefixes {
			specialPrefixesSlice = append(specialPrefixesSlice, k)
		}
		debuglog("MAIN: Following Special Prefixes were stored with corresponding key value: %+v", specialPrefixes)
	} else {
		debuglog("MAIN: No file for special prefixes specified. Scanning without")
	}
}

func readBGPprefixesAndInitializeMap() {
	bgpPrefixes = make(map[int64][]int)
	if bgpPrefixFile != "" {
		fileBGP, err := os.Open(bgpPrefixFile)
		if err != nil {
			errorlog("MAIN:   could not read File %v !", bgpPrefixFile)
			panic("Could not read the file for BGPANNOUNCED announced prefixes.")
		}
		scanner := bufio.NewScanner(fileBGP)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			nextBGPnet := scanner.Text()
			splittedNextBGPnet := strings.Split(nextBGPnet, "/")
			prefixLength, err := strconv.Atoi(splittedNextBGPnet[1])
			if err != nil {
				errorlog("Reading '%v' from File with special prefixes produced error: %s", nextBGPnet, err)
			} else {
				ipAsInt := convertIPFromStringToKeyInt(splittedNextBGPnet[0])
				storedPrefixLengths, ok := bgpPrefixes[ipAsInt]
				if ok {
					bgpPrefixes[ipAsInt] = append(storedPrefixLengths, prefixLength)
				} else {
					bgpPrefixes[ipAsInt] = []int{prefixLength}
				}
			}
		}
		for k := range bgpPrefixes {
			bgpPrefixesSlice = append(bgpPrefixesSlice, k)
		}
		slices.Sort(bgpPrefixesSlice)
		debuglog("MAIN:    BGPANNOUNCED Prefixes were stored.")
	} else {
		debuglog("MAIN: No File was specified for BGPANNOUNCED announced prefixes. Will scan without.")
	}

}

func startScanner() {
	if versionf {
		return
	}
	if storeDir == "" && !nostore {
		panic("did not specify a storagedir")
	}

	var err error
	_, err = os.Stat(storeDir)
	if err == nil {
		panic("storagedir '" + storeDir + "' already exists")
	} else if !os.IsNotExist(err) {
		panic("storagedir '" + storeDir + "' access err " + err.Error())
	}
	err = os.MkdirAll(storeDir, 0750)
	if ip4flag != "" {
		ip4 := net.ParseIP(ip4flag).To4()
		if ip4flag != "" && ip4 == nil {
			panic(ip4flag + "is not a IPv4 addr")
		}
		InitScanner(ip4)
	}
	if ip6flag != "" {
		ip6 := net.ParseIP(ip6flag).To16()
		if ip6flag != "" && ip6 == nil {
			panic(ip6flag + "is not a IPv6 addr")
		}
		InitScanner(ip6)
	}

	EcsResultWriter = SetupSynchronizedWriter(storeDir, "ecsresults.csv", ECSResultsHeader)

	limiter = make(chan struct{}, queryRate)

	for i := 0; i < queryRate; i++ {
		limiter <- struct{}{}
	}
	go rateLimitFiller(queryRate)
}

// rateLimitFiller Runs each ms if necessary or 1/queryRateLimit
func rateLimitFiller(queryRateLimit int) {
	var begin time.Time
	var wait time.Duration

	var bucketRate int
	if queryRateLimit >= 500 {
		bucketRate = int(math.Ceil(float64(queryRateLimit) / 1000))
	} else {
		bucketRate = 1
	}
	defaultWait := time.Duration(bucketRate * int(time.Second) / queryRateLimit)

	for {
		begin = time.Now()
		for i := 0; i < bucketRate; i++ {
			limiter <- struct{}{}
		}
		wait = defaultWait - time.Now().Sub(begin)

		if wait > 0 {
			time.Sleep(wait)
		}
	}
}

func getPrefixLimits() {
	viper.SetConfigFile(configFile) // name of config file (without extension)
	viper.SetConfigType("yaml")     // REQUIRED if the config file does not have the extension in the name
	err := viper.ReadInConfig()     // Find and read the config file
	if err != nil {                 // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
	fmt.Println(viper.AllKeys())
	limitsName := "ipv4Limits"
	limitBits := 32
	if ipv6Scan {
		limitsName = "ipv6Limits"
		limitBits = 128
	}
	ipv4limitsconf := viper.GetStringMapString(limitsName + ".bgprouted")
	//	ipv4limits := make(map[int]int)
	scanLimits[BGPANNOUNCED] = make([]int, 129)
	scanLimits[UNANNOUNCED] = make([]int, 129)
	scanLimits[TOTAL] = make([]int, 129)
	for key, val := range ipv4limitsconf {
		keyInt, err := strconv.Atoi(key)
		if err != nil {
			errorlog("Could not convert %v to int prefixlength", key)
			os.Exit(2)
		}
		if keyInt > limitBits {
			errorlog("'%v' prefix length is too long", key)
			os.Exit(2)
		}
		valInt, err := strconv.Atoi(val)
		if err != nil {
			errorlog("Could not convert %v to int prefixlength limit", val)
			os.Exit(2)
		}
		scanLimits[BGPANNOUNCED][keyInt] = valInt
	}
	ipv4limitsconf = viper.GetStringMapString(limitsName + ".notrouted")
	//	ipv4limits := make(map[int]int)
	for key, val := range ipv4limitsconf {
		keyInt, err := strconv.Atoi(key)
		if err != nil {
			errorlog("Could not convert %v to int prefixlength", key)
			os.Exit(2)
		}
		if keyInt > limitBits {
			errorlog("'%v' prefix length is too long", key)
			os.Exit(2)
		}
		valInt, err := strconv.Atoi(val)
		if err != nil {
			errorlog("Could not convert %v to int prefixlength limit", val)
			os.Exit(2)
		}
		scanLimits[UNANNOUNCED][keyInt] = valInt
	}
	ipv4limitsconf = viper.GetStringMapString(limitsName + ".total")
	for key, val := range ipv4limitsconf {
		keyInt, err := strconv.Atoi(key)
		if err != nil {
			errorlog("Could not convert %v to int prefixlength", key)
			os.Exit(2)
		}
		if keyInt > limitBits {
			errorlog("'%v' prefix length is too long", key)
			os.Exit(2)
		}
		valInt, err := strconv.Atoi(val)
		if err != nil {
			errorlog("Could not convert %v to int prefixlength limit", val)
			os.Exit(2)
		}
		scanLimits[TOTAL][keyInt] = valInt
	}
	fmt.Println(scanLimits)
	maxSpecialPrefixScans = viper.GetInt("maxSpecialPrefixScans")
	fmt.Println(maxSpecialPrefixScans)
	scanResultsToFinish = uint8(viper.GetInt("scanResultsToFinish"))
	fmt.Println(scanResultsToFinish)
	totalNotroutedLimit = viper.GetInt("totalNotroutedLimit")
	fmt.Println(totalNotroutedLimit)
}

func main() {
	interruptsChan := make(chan os.Signal, 1)
	signal.Notify(interruptsChan, os.Interrupt, syscall.SIGPIPE)

	parseFlags()
	if versionf {
		fmt.Printf("ECS-Scanner version: [%v].\n", version)
		os.Exit(0)
	}
	startLogging()

	if queryListFile == "" {
		getPrefixLimits()
	}

	var resolverIP net.IP = nil
	if resolver != "" {
		resolverIP = net.ParseIP(resolver)
		if resolverIP != nil {
			if resolverIP.To4() != nil {
				resolverIP = resolverIP.To4()
			}
		} else {
			errorlog("resolver is set but cannot be converted to an IP address")
			os.Exit(1)
		}
	}

	//For debugging purposes we note down the set flags
	debuglog("MAIN: Flags are set and parsed. Logging has started")
	startScanner()
	infolog("ECS Scanner: Version: %s", version)
	debuglog("cmdline: %s", os.Args)
	flag.Visit(func(flag *flag.Flag) {
		debuglog("MAIN:   Flag - %v has Value: %v", flag.Name, flag.Value)
	})

	if cpuProfileFile != "" {
		f, err := os.Create(cpuProfileFile)
		if err != nil {
			errorlog("MAIN:   Could not create File for CPU Profile %v", cpuProfileFile)
			panic(err)
		}
		err = pprof.StartCPUProfile(f)
		if err != nil {
			errorlog("could not start cpu profile")
			panic(err)
		}
		defer pprof.StopCPUProfile()
	}

	go func() {
		<-interruptsChan
		infolog("INTERRUPTED")
		if cpuProfileFile != "" {
			pprof.StopCPUProfile()
		}
		if memProfileFile != "" {
			f, err := os.Create(memProfileFile)
			if err != nil {
				errorlog("Error while creating mem Profile file '%s' ; Error: %s", memProfileFile, err)
			}
			err = pprof.WriteHeapProfile(f)
			if err != nil {
				errorlog("Error while writing mem Profile; Error: %s", err)
			}
			err = f.Close()
			if err != nil {
				errorlog("Error while closing mem Profile; file '%s' ;Error: %s", memProfileFile, err)
			}
		}
		os.Exit(1)
	}()

	readBGPprefixesAndInitializeMap()
	readSpecialprefixesAndInitializeCorespondingmap()
	readQueryList()

	fileInput, err := os.Open(inputFile)
	if err != nil {
		errorlog("MAIN:   could not read File %v !", inputFile)
		panic("Could not read Input File")
	}

	fileBuf := bufio.NewScanner(fileInput)
	fileBuf.Split(bufio.ScanLines)

	defer func(fileInput *os.File) {
		err := fileInput.Close()
		if err != nil {
			errorlog("MAIN: Could not close Input File: %v ", fileInput)
		}
	}(fileInput)

	var nextDomainState func() *domainState
	nextDomainState = func() *domainState {
		if fileBuf.Scan() {
			domainAndNamerserver := fileBuf.Text()
			splittedDomainAndNameserver := strings.Split(domainAndNamerserver, ",")
			debuglog("DOMAINSTATE: reading line \"" + domainAndNamerserver + "\"")
			var nameserverIP net.IP = nil
			if resolverIP != nil {
				nameserverIP = resolverIP
			} else {
				if len(splittedDomainAndNameserver) < 2 {
					errorlog("Line '" + domainAndNamerserver + "' is missing a ,")
					return nextDomainState()
				}
				nameserverIP = net.ParseIP(splittedDomainAndNameserver[1])
				if nameserverIP != nil {
					if nameserverIP.To4() != nil {
						nameserverIP = nameserverIP.To4()
					}
				} else {
					errorlog("Could not parse nameserver IP %v", splittedDomainAndNameserver[1])
					return nextDomainState()
				}
			}
			return &domainState{
				domain:       splittedDomainAndNameserver[0],
				nameserverIP: nameserverIP,
				identifier:   domainIdentifier(splittedDomainAndNameserver[0], nameserverIP),
			}
		}
		return nil
	}

	controller(nextDomainState) //the actual magic starts
	if memProfileFile != "" {
		f, err := os.Create(memProfileFile)
		if err != nil {
			errorlog("Error while creating mem Profile file '%s' ; Error: %s", memProfileFile, err)
		}
		errorMP := pprof.WriteHeapProfile(f)
		if errorMP != nil {
			errorlog("Error while writing mem Profile; Error: %s", err)
		}
		errorMP2 := f.Close()
		if errorMP2 != nil {
			errorlog("Error while closing mem Profile; file '%s' ;Error: %s", memProfileFile, err)
		}
	}
	EcsResultWriter.Close()
}
