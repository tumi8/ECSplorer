// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"runtime"
	"strconv"
	"strings"
)

var (
	debugLog *log.Logger
	infoLog  *log.Logger
	errorLog *log.Logger

	debugDisable bool
	infoDisable  bool
	errorDisable bool
)

func ReturnLoggers() (*log.Logger, *log.Logger, *log.Logger) {
	return debugLog, infoLog, errorLog
}
func ReturnDisables() (bool, bool, bool) {
	return debugDisable, infoDisable, errorDisable
}

var LogDiscard = ioutil.Discard

// Init_Logging sets the writer of the data for each loglevel.
// Use LogDiscard to disable a certain Loglevel
func Init_Logging(debugWriter io.Writer, infoWriter io.Writer, errorWriter io.Writer) {
	debugLog = log.New(debugWriter, "<D>", log.Lmicroseconds)
	infoLog = log.New(infoWriter, "<I>", log.Lmicroseconds)
	errorLog = log.New(errorWriter, "<E>", log.Lmicroseconds)

	if debugWriter == LogDiscard {
		debugDisable = true
	}
	if infoWriter == LogDiscard {
		infoDisable = true
	}
	if errorWriter == LogDiscard {
		errorDisable = true
	}
	infoLog.Printf("LOGGER: Level: debugDisable=%t infoDisable=%t errorDisable=%t", debugDisable, infoDisable, errorDisable)
}

func debuglog(fmt string, v ...interface{}) {
	if !debugDisable {
		debugLog.Printf(fmt, v...)
	}
}

func infolog(fmt string, v ...interface{}) {
	if !infoDisable {
		infoLog.Printf(fmt, v...)
	}
}

func ErrorLog(fmt string, v ...interface{}) {
	errorlog(fmt, v...)
}

func errorlog(fmt string, v ...interface{}) {
	if !errorDisable {
		errorLog.Printf(fmt, v...)
	}
}

func goid() int {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	idField := strings.Fields(strings.TrimPrefix(string(buf[:n]), "goroutine "))[0]
	id, err := strconv.Atoi(idField)
	if err != nil && !errorDisable {
		errorLog.Printf("cannot get goroutine id: %v", err)
	}
	return id
}

func PrintStacktrace(all bool) {
	debuglog("Printing stack trace:")
	n := 0
	buf := make([]byte, 1024)
	for {
		n = runtime.Stack(buf, all)
		if n < len(buf) {
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	if !errorDisable {
		errorLog.Printf("\n%s", buf[:n])
	} else {
		fmt.Printf("\n%s", buf[:n])
	}
}

