// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"bufio"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// Struct to allow synchronized writing to a file
type SynchronizedWriter struct {
	filename   string
	fileWriter *bufio.Writer
	mutex      sync.Mutex
}

// Set up a new writer and write header in the first line
func SetupSynchronizedWriter(dir string, filename string, header string) *SynchronizedWriter {
	syncWriter := new(SynchronizedWriter)
	syncWriter.filename = filename

	f, err := os.Create(dir + "/" + filename)
	if err != nil {
		panic("can't create file " + dir + "/" + filename)
	}
	err = os.Truncate(dir+"/"+filename, 0)
	if err != nil {
		panic("can't clear file " + dir + "/" + filename)
	}

	syncWriter.fileWriter = bufio.NewWriter(f)
	if header != "" {
		_, err = syncWriter.fileWriter.WriteString(header + "\n")
		if err != nil {
			return nil
		}
	}

	return syncWriter
}

// write a singular line to file
// adds a newline
func (w *SynchronizedWriter) writeAsLine(line string) error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	_, err := w.fileWriter.WriteString(line + "\n")
	return err
}

// format the result and write it to file
// for format see ECSResultsHeader
func (w *SynchronizedWriter) writeECSResult(timestamp time.Time, domain string, ns net.IP, family byte, sourcePL byte, scopePL byte, address net.IP, answers []string, cnames []string, error error_type, nsid string, errStr string) error {

	lineElements := make([]byte, 0)
	lineElements = append(lineElements, []byte(domain)...)
	lineElements = append(lineElements, ',')
	lineElements = append(lineElements, []byte(ns.String())...)
	lineElements = append(lineElements, ',')
	lineElements = strconv.AppendUint(lineElements, uint64(family), 10)
	lineElements = append(lineElements, ',')
	lineElements = append(lineElements, []byte(address.String())...)
	lineElements = append(lineElements, ',')
	lineElements = strconv.AppendUint(lineElements, uint64(sourcePL), 10)
	lineElements = append(lineElements, ',')
	lineElements = strconv.AppendUint(lineElements, uint64(scopePL), 10)
	lineElements = append(lineElements, ',')
	lineElements = strconv.AppendInt(lineElements, int64(error), 10)
	lineElements = append(lineElements, ',')
	if errStr != "" {
		// quote errStr to escape comma
		lineElements = append(lineElements, '"')
		lineElements = append(lineElements, []byte(errStr)...)
		lineElements = append(lineElements, '"')
	}
	lineElements = append(lineElements, ',')
	lineElements = append(lineElements, []byte(nsid)...)
	lineElements = append(lineElements, ',')

	if len(answers) > 0 {
		lineElements = append(lineElements, '"')
		lineElements = append(lineElements, '[')
		for i, answer := range answers {
			lineElements = append(lineElements, '\'')
			lineElements = append(lineElements, []byte(answer)...)
			lineElements = append(lineElements, '\'')
			if i < len(answers)-1 {
				lineElements = append(lineElements, ',')
			}
		}
		lineElements = append(lineElements, ']')
		lineElements = append(lineElements, '"')
	}
	lineElements = append(lineElements, ',')
	if len(cnames) > 0 {
		lineElements = append(lineElements, '"')
		lineElements = append(lineElements, '[')
		for i, answer := range cnames {
			lineElements = append(lineElements, '\'')
			lineElements = append(lineElements, []byte(answer)...)
			lineElements = append(lineElements, '\'')
			if i < len(cnames)-1 {
				lineElements = append(lineElements, ',')
			}
		}
		lineElements = append(lineElements, ']')
		lineElements = append(lineElements, '"')
	}
	lineElements = append(lineElements, ',')
	lineElements = strconv.AppendInt(lineElements, timestamp.Unix(), 10)
	lineElements = append(lineElements, '\n')

	w.mutex.Lock()
	defer w.mutex.Unlock()
	_, err := w.fileWriter.Write(lineElements)
	return err
}

func (w *SynchronizedWriter) Close() {
	err := w.fileWriter.Flush()
	if err != nil {
		errorlog("Error while flushing file %s", w.filename)
	}
}
