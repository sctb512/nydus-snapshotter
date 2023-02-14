/*
 * Copyright (c) 2023. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package conn

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	fdPrefix  = "fd:"
	msgPrefix = "msg:"
)

type StdPipe struct {
	Reader  io.Reader
	Writer  io.Writer
	Client  *bufio.Scanner
	Timeout time.Duration
}

func NewStdPipe(r io.Reader, w io.Writer, timeout time.Duration) *StdPipe {
	return &StdPipe{
		Reader:  r,
		Writer:  w,
		Client:  bufio.NewScanner(r),
		Timeout: timeout,
	}
}

func (pipe *StdPipe) RecvWithTimeout() (string, error) {
	notifyCh := make(chan string)
	errCh := make(chan error)
	go func() {
		if !pipe.Client.Scan() {
			errCh <- io.EOF
		}
		notifyCh <- pipe.Client.Text()
	}()
	select {
	case mes := <-notifyCh:
		return mes, nil
	case err := <-errCh:
		return "", err
	case <-time.After(pipe.Timeout):
		return "", fmt.Errorf("timeout")
	}
}

func (pipe *StdPipe) Send(msg string) error {
	if _, err := io.WriteString(pipe.Writer, msg+"\n"); err != nil {
		return err
	}
	return nil
}

func (pipe *StdPipe) SendFd(fd int32) error {
	if err := pipe.Send(fmt.Sprintf("%s%d", fdPrefix, fd)); err != nil {
		return err
	}
	msg, err := pipe.RecvWithTimeout()
	if err != nil {
		return err
	}

	if !strings.HasPrefix(msg, msgPrefix) {
		return fmt.Errorf("get message from client falied: %s", msg)
	}
	if msg[len(msgPrefix):] != "ok" {
		return fmt.Errorf("get ok from client falied: %s", msg)
	}

	return nil
}

func (pipe *StdPipe) GetPathFromFd(serverPid int) (string, error) {
	if !pipe.Client.Scan() { // NOTE: no timeout
		return "", io.EOF
	}
	mes := pipe.Client.Text()
	if !strings.HasPrefix(mes, fdPrefix) {
		return "", fmt.Errorf("unexpected prefix for message %q", mes)
	}
	fd, err := strconv.ParseInt(mes[len(fdPrefix):], 10, 32)
	if err != nil {
		return "", fmt.Errorf("invalid fd %q: %w", mes, err)
	}
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", serverPid, fd))
	if err != nil {
		return "", fmt.Errorf("failed to get link from fd %q: %w", mes, err)
	}
	err = pipe.Send(msgPrefix + "ok")
	return path, err
}

func (pipe *StdPipe) SendExit() error {
	if err := pipe.Send(msgPrefix + "exit"); err != nil {
		return err
	}
	return nil
}
