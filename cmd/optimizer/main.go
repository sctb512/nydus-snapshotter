/*
 * Copyright (c) 2023. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/containerd/nydus-snapshotter/pkg/fanotify"
)

type config struct {
	LogFile string   `yaml:"logFile"`
	Events  []string `yaml:"events"`

	ServerPath string `yaml:"serverPath"`
	PersistDir string `yaml:"persistDir"`
	Timeout    int    `yaml:"timeout"`
	Overwrite  bool   `yaml:"overwrite"`
}

type plugin struct {
	stub stub.Stub
	mask stub.EventMask
}

var (
	cfg                  config
	log                  *logrus.Logger
	_                    = stub.ConfigureInterface(&plugin{})
	globalFanotifyServer = make(map[string]*fanotify.Server)
)

const (
	imageNameLabel = "io.kubernetes.cri.image-name"
)

func (p *plugin) Configure(config, runtime, version string) (stub.EventMask, error) {
	log.Infof("got configuration data: %q from runtime %s %s", config, runtime, version)
	if config == "" {
		return p.mask, nil
	}

	oldCfg := cfg
	err := yaml.Unmarshal([]byte(config), &cfg)
	if err != nil {
		return 0, fmt.Errorf("failed to parse provided configuration: %w", err)
	}

	p.mask, err = api.ParseEventMask(cfg.Events...)
	if err != nil {
		return 0, fmt.Errorf("failed to parse events in configuration: %w", err)
	}

	if cfg.LogFile != oldCfg.LogFile {
		f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Errorf("failed to open log file %q: %v", cfg.LogFile, err)
			return 0, fmt.Errorf("failed to open log file %q: %w", cfg.LogFile, err)
		}

		os.Stdout = f
		os.Stderr = f
		log.SetOutput(f)
	}
	log.Infof("configuration: %#v", cfg)

	return p.mask, nil
}

func (p *plugin) StartContainer(pod *api.PodSandbox, container *api.Container) error {
	dump("StartContainer", "pod", pod, "container", container)

	imageName := GetImageName(container.Annotations)
	persistFile := filepath.Join(cfg.PersistDir, imageName)
	if cfg.Timeout > 0 {
		persistFile = fmt.Sprintf("%s.timeout%ds", persistFile, cfg.Timeout)
	}

	fanotifyServer := fanotify.NewServer(cfg.ServerPath, container.Pid, imageName, persistFile, cfg.Overwrite, time.Duration(cfg.Timeout)*time.Second)
	err := fanotifyServer.RunServer()
	if err != nil {
		return err
	}

	globalFanotifyServer[imageName] = fanotifyServer

	return nil
}

func (p *plugin) StopContainer(_ *api.PodSandbox, container *api.Container) ([]*api.ContainerUpdate, error) {
	var update = []*api.ContainerUpdate{}
	imageName := GetImageName(container.Annotations)
	if fanotifyServer, ok := globalFanotifyServer[imageName]; ok {
		fanotifyServer.StopServer()
	} else {
		return nil, errors.New("can not find fanotify server for container image " + imageName)
	}

	return update, nil
}

func GetImageName(annotations map[string]string) string {
	image := annotations[imageNameLabel]
	imageNameSlice := strings.Split(image, "/")
	imageName := imageNameSlice[len(imageNameSlice)-1]
	return imageName
}

func dump(args ...interface{}) {
	var (
		prefix string
		idx    int
	)

	if len(args)&0x1 == 1 {
		prefix = args[0].(string)
		idx++
	}

	for ; idx < len(args)-1; idx += 2 {
		tag, obj := args[idx], args[idx+1]
		msg, err := yaml.Marshal(obj)
		if err != nil {
			log.Infof("%s: %s: failed to dump object: %v", prefix, tag, err)
			continue
		}

		if prefix != "" {
			log.Infof("%s: %s:", prefix, tag)
			for _, line := range strings.Split(strings.TrimSpace(string(msg)), "\n") {
				log.Infof("%s:    %s", prefix, line)
			}
		} else {
			log.Infof("%s:", tag)
			for _, line := range strings.Split(strings.TrimSpace(string(msg)), "\n") {
				log.Infof("  %s", line)
			}
		}
	}
}

func (p *plugin) onClose() {
	for _, fanotifyServer := range globalFanotifyServer {
		fanotifyServer.StopServer()
	}

	os.Exit(0)
}

func main() {
	var (
		pluginName string
		pluginIdx  string
		events     string
		opts       []stub.Option
		err        error
	)

	log = logrus.StandardLogger()
	log.SetFormatter(&logrus.TextFormatter{
		PadLevelText: true,
	})

	flag.StringVar(&pluginName, "name", "", "plugin name to register to NRI")
	flag.StringVar(&pluginIdx, "idx", "", "plugin index to register to NRI")
	flag.StringVar(&events, "events", "all", "comma-separated list of events to subscribe for")
	flag.StringVar(&cfg.LogFile, "log-file", "", "logfile name, if logging to a file")

	flag.StringVar(&cfg.ServerPath, "server-path", "", "the notifier server binary path")
	flag.StringVar(&cfg.PersistDir, "persist-dir", "", "the path to persist accessed files list")
	flag.IntVar(&cfg.Timeout, "timeout", 0, "timeout to kill fanotify server, in seconds")
	flag.BoolVar(&cfg.Overwrite, "overwrite", false, "whether to overwrite the existing persist contents")

	flag.Parse()

	if pluginName != "" {
		opts = append(opts, stub.WithPluginName(pluginName))
	}
	if pluginIdx != "" {
		opts = append(opts, stub.WithPluginIdx(pluginIdx))
	}

	p := &plugin{}

	if p.mask, err = api.ParseEventMask(events); err != nil {
		log.Fatalf("failed to parse events: %v", err)
	}
	cfg.Events = strings.Split(events, ",")

	if p.stub, err = stub.New(p, append(opts, stub.WithOnClose(p.onClose))...); err != nil {
		log.Fatalf("failed to create plugin stub: %v", err)
	}

	err = p.stub.Run(context.Background())
	if err != nil {
		log.Errorf("plugin exited with error %v", err)
		os.Exit(1)
	}
}
