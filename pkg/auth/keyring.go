/*
 * Copyright (c) 2023. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package auth

import (
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const (
	defaultSessionName = "_ses.nydus"
)

type KeyRing struct {
	lock *sync.RWMutex
}

func NewKeyRing() *KeyRing {
	return &KeyRing{
		&sync.RWMutex{},
	}
}

func (k *KeyRing) Add(id, value string) (int, error) {
	sessKeyID, err := unix.KeyctlJoinSessionKeyring(defaultSessionName)
	if err != nil {
		return 0, errors.Wrap(err, "unable to session key")
	}

	if err := k.modifyKeyringPerm(sessKeyID, 0xffffffff, 0x80000); err != nil {
		return 0, errors.Wrap(err, "unable to mod keyring permissions")
	}

	k.lock.Lock()
	defer k.lock.Unlock()

	keyID, err := unix.AddKey("user", id, []byte(value), sessKeyID)
	if err != nil {
		return 0, err
	}

	return keyID, nil
}

func (k *KeyRing) modifyKeyringPerm(ringID int, mask, setbits uint32) error {
	dest, err := unix.KeyctlString(unix.KEYCTL_DESCRIBE, int(ringID))
	if err != nil {
		return err
	}

	res := strings.Split(dest, ";")
	if len(res) < 5 {
		return errors.New("destination buffer for key description is too small")
	}

	perm64, err := strconv.ParseUint(res[3], 16, 32)
	if err != nil {
		return err
	}
	perm := (uint32(perm64) & mask) | setbits

	return unix.KeyctlSetperm(ringID, perm)
}

func (k *KeyRing) Search(id string) (string, error) {
	sessKeyID, err := unix.KeyctlJoinSessionKeyring(defaultSessionName)
	if err != nil {
		return "", errors.Wrap(err, "unable to session key")
	}

	if err := k.modifyKeyringPerm(sessKeyID, 0xffffffff, 0x80000); err != nil {
		return "", errors.Wrap(err, "unable to mod keyring permissions")
	}

	key, err := unix.KeyctlSearch(sessKeyID, "user", id, 0)
	if err != nil {
		return "", err
	}

	return k.GetData(key)
}

func (k *KeyRing) GetData(key int) (string, error) {
	size := 512
	buffer := make([]byte, 512)
	sizeRead := size + 1

	for sizeRead > size {
		len, err := unix.KeyctlBuffer(unix.KEYCTL_READ, key, buffer, size)
		if err != nil {
			return "", err
		}

		if sizeRead = len; sizeRead > size {
			buffer = make([]byte, sizeRead)
			size = sizeRead
			sizeRead = size + 1
		} else {
			size = sizeRead
		}
	}
	return string(buffer[:size]), nil
}
