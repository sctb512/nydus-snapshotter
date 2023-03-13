/*
 * Copyright (c) 2023. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package conn

import (
	"bufio"
	"encoding/json"
	"io"
)

type Client struct {
	Reader *bufio.Reader
}

type EventInfo struct {
	Path      string `json:"path"`
	Size      uint32 `json:"size"`
	Timestamp int64  `json:"timestamp"`
}

func (c *Client) ReadEventBytes() ([]byte, error) {
	var (
		isPrefix   = true
		err        error
		line, data []byte
	)

	for isPrefix && err == nil {
		line, isPrefix, err = c.Reader.ReadLine()
		data = append(data, line...)
	}
	if err != io.EOF {
		return data, err
	}

	return data, nil
}

func (c *Client) GetEventInfo() ([]EventInfo, error) {
	data, err := c.ReadEventBytes()
	if err != nil {
		return nil, err
	}

	eventInfo := []EventInfo{}
	if err := json.Unmarshal(data, &eventInfo); err != nil {
		return nil, err
	}

	return eventInfo, nil
}
