/*
 * Copyright (c) 2023. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fanotify

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/containerd/nydus-snapshotter/pkg/fanotify/conn"
	"github.com/containerd/nydus-snapshotter/pkg/fanotify/tools"
)

func StartFanotifier(ctx context.Context, pipe *conn.StdPipe, persistentWriter io.Writer, pid int) error {
	var accessedFiles []string
	for {
		select {
		case <-ctx.Done():
			pipe.SendExit()
			return nil
		default:
			path, err := pipe.GetPathFromFd(pid)
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

	}
}

type Server struct {
	BinaryPath       string
	ContainerPid     uint32
	ImageName        string
	PersistFile      string
	Overwrite        bool
	Timeout          time.Duration
	Pipe             *conn.StdPipe
	FanotifierCancel *context.CancelFunc
	Cmd              *exec.Cmd
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
	notifyW, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	fserver.Pipe = conn.NewStdPipe(notifyR, notifyW, 5*time.Second)

	if err := cmd.Start(); err != nil {
		return err
	}

	f, err := os.OpenFile(fserver.PersistFile, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file %q: %w", fserver.PersistFile, err)
	}

	fanotifierCtx, fanotifierCancel := context.WithCancel(context.Background())
	fserver.Cmd = cmd
	fserver.FanotifierCancel = &fanotifierCancel

	go StartFanotifier(fanotifierCtx, fserver.Pipe, f, cmd.Process.Pid)

	if fserver.Timeout > 0 {
		go func() {
			time.Sleep(fserver.Timeout)
			fserver.StopServer()
		}()
	}

	return nil
}

func (fserver *Server) StopServer() {
	if fserver.FanotifierCancel != nil {
		(*fserver.FanotifierCancel)()
	}
	if fserver.Cmd != nil {
		if err := fserver.Cmd.Process.Signal(syscall.SIGINT); err != nil {
			fserver.Cmd.Process.Kill()
		}
	}
}
