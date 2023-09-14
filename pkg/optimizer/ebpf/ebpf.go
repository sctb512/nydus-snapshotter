/*
 * Copyright (c) 2023. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package ebpf

import (
	"encoding/csv"
	"fmt"
	"log/syslog"
	"os"
	"time"

	"github.com/containerd/containerd/log"
	"github.com/containerd/nydus-snapshotter/pkg/optimizer/ebpf/conn"
	"github.com/containerd/nydus-snapshotter/pkg/utils/display"
	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type Server struct {
	ContainerID    string
	Close          chan struct{}
	ImageName      string
	PersistFile    *os.File
	PersistCSVFile *os.File
	Readable       bool
	Overwrite      bool
	Timeout        time.Duration
	LogWriter      *syslog.Writer
}

func NewServer(containerID string, imageName string, file *os.File, csvFile *os.File, readable bool, overwrite bool, timeout time.Duration, logWriter *syslog.Writer) Server {
	server := Server{
		ContainerID:    containerID,
		ImageName:      imageName,
		PersistFile:    file,
		PersistCSVFile: csvFile,
		Readable:       readable,
		Overwrite:      overwrite,
		Timeout:        timeout,
		LogWriter:      logWriter,
	}

	server.Close = make(chan struct{}, 1)

	return server
}

var (
	ContainerIDTable *bpf.Table
	Module           *bpf.Module
	PerfMap          *bpf.PerfMap
)

var receiveClose = make(chan struct{})
var resultMap = make(map[string](chan conn.EventInfo))

func StartEbpfProgram() error {
	m, table, err := conn.InitKprobeTable()
	if err != nil {
		logrus.Infof("InitKprobeTable err: %v", err)
		return err
	}

	ContainerIDTable = bpf.NewTable(m.TableId("id_buf"), m)

	channel := make(chan []byte)
	PerfMap, err = bpf.InitPerfMapWithPageCnt(table, channel, nil, 1024)
	if err != nil {
		logrus.Infof("init perf map err: %v", err)
		return err
	}
	Module = m
	client := &conn.Client{
		Channel: channel,
	}

	go func() {
		receiveLoop(client, receiveClose)
	}()

	PerfMap.Start()

	return nil
}

func receiveLoop(client *conn.Client, receiveClose <-chan struct{}) {
	for {
		select {
		case <-receiveClose:
			return
		default:
			eventInfo, err := client.GetEventInfo()
			if err != nil {
				log.L.Errorf("failed to get event information: %v", err)
			}

			if eventInfo != nil {
				resultMap[eventInfo.ContainerID] <- *eventInfo
			}
		}
	}
}

func StopEbpfProgram() error {
	if PerfMap != nil {
		PerfMap.Stop()
		receiveClose <- struct{}{}
		Module.Close()
	}
	return nil
}

func addEbpfMap(id string) error {
	byteID := [128]byte{0}
	copy(byteID[:], id)

	if err := ContainerIDTable.Set(byteID[:], []byte{1}); err != nil {
		return err
	}
	return nil
}

func removeEbpfMap(id string) error {
	byteID := [128]byte{0}
	copy(byteID[:], id)

	if err := ContainerIDTable.Delete(byteID[:]); err != nil {
		log.L.WithError(err).Warnf("failed to remove id")
	}

	return nil
}

func (eserver Server) Start() error {
	resultMap[eserver.ContainerID] = make(chan conn.EventInfo, 1024)

	go func() {
		if err := eserver.Receive(); err != nil {
			logrus.WithError(err).Errorf("Failed to receive event information from server")
		}
	}()

	if err := addEbpfMap(eserver.ContainerID); err != nil {
		return err
	}

	if eserver.Timeout > 0 {
		go func() {
			time.Sleep(eserver.Timeout)
			eserver.Stop()
		}()
	}

	return nil
}

func (eserver Server) Stop() {
	if err := removeEbpfMap(eserver.ContainerID); err != nil {
		log.L.WithError(err).Errorf("failed to stop server")
	}

	eserver.Close <- struct{}{}
	close(resultMap[eserver.ContainerID])
	delete(resultMap, eserver.ContainerID)
}

func (eserver Server) Receive() error {
	defer eserver.PersistFile.Close()
	defer eserver.PersistCSVFile.Close()

	csvWriter := csv.NewWriter(eserver.PersistCSVFile)
	if err := csvWriter.Write([]string{"timestamp", "command", "path", "position", "size"}); err != nil {
		return errors.Wrapf(err, "failed to write csv header")
	}
	csvWriter.Flush()

	fileList := make(map[string]struct{})
	for {
		select {
		case <-eserver.Close:
			for key := range fileList {
				delete(fileList, key)
			}
			return nil
		case eventInfo := <-resultMap[eserver.ContainerID]:
			if _, ok := fileList[eventInfo.Path]; !ok {
				fmt.Fprintln(eserver.PersistFile, eventInfo.Path)
				fileList[eventInfo.Path] = struct{}{}
			}

			var line []string
			if eserver.Readable {
				eventTime := time.Unix(0, eventInfo.Timestamp*int64(time.Millisecond)).Format("2006-01-02 15:04:05.000")
				line = []string{eventTime, eventInfo.Command, eventInfo.Path, fmt.Sprint(eventInfo.Position), display.ByteToReadableIEC(eventInfo.Size)}
			} else {
				line = []string{fmt.Sprint(eventInfo.Timestamp), eventInfo.Command, eventInfo.Path, fmt.Sprint(eventInfo.Position), fmt.Sprint(eventInfo.Size)}
			}
			if err := csvWriter.Write(line); err != nil {
				return errors.Wrapf(err, "failed to write csv")
			}
			csvWriter.Flush()
		}
	}
}
