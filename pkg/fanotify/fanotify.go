/*
 * Copyright (c) 2023. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fanotify

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/containerd/nydus-snapshotter/pkg/fanotify/conn"
	"github.com/containerd/nydus-snapshotter/pkg/fanotify/tools"
)

func StartFanotifier(client *conn.Client, persistentWriter io.Writer) error {
	var accessedFiles []string
	for {
		path, err := client.GetPath()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to get notified path: %v", err)
		}
		if !tools.AccessedFileExist(accessedFiles, path) {
			accessedFiles = append(accessedFiles, path)
			fmt.Fprintln(persistentWriter, path)
		}

	}
	return nil
}

type Server struct {
	BinaryPath   string
	ContainerPid uint32
	ImageName    string
	PersistFile  string
	Overwrite    bool
	Timeout      time.Duration
	Client       *conn.Client
	Cmd          *exec.Cmd
}

func NewServer(binaryPath string, containerPid uint32, imageName string, persistFile string, overwrite bool, timeout time.Duration) *Server {
	return &Server{
		BinaryPath:   binaryPath,
		ContainerPid: containerPid,
		ImageName:    imageName,
		PersistFile:  persistFile,
		Overwrite:    overwrite,
		Timeout:      timeout,
	}
}

func (fserver *Server) RunServer() error {
	if !fserver.Overwrite {
		if file, err := os.Stat(fserver.PersistFile); err == nil && !file.IsDir() {
			return nil
		}
	}

	cmd := exec.Command(fserver.BinaryPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS,
	}
	cmd.Env = append(cmd.Env, "_MNTNS_PID="+fmt.Sprint(fserver.ContainerPid))
	cmd.Env = append(cmd.Env, "_TARGET=/")

	notifyR, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	fserver.Client = &conn.Client{
		Scanner: bufio.NewScanner(notifyR),
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	f, err := os.OpenFile(fserver.PersistFile, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file %q: %w", fserver.PersistFile, err)
	}

	fserver.Cmd = cmd

	go StartFanotifier(fserver.Client, f)

	if fserver.Timeout > 0 {
		go func() {
			time.Sleep(fserver.Timeout)
			fserver.StopServer()
		}()
	}

	return nil
}

func (fserver *Server) StopServer() {
	if fserver.Cmd != nil {
		if err := fserver.Cmd.Process.Signal(syscall.SIGINT); err != nil {
			fserver.Cmd.Process.Kill()
		}
	}
}
