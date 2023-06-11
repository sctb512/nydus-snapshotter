/*
 * Copyright (c) 2023. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package filesystem

import (
	"context"
	"fmt"

	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/mount"
	snpkg "github.com/containerd/containerd/pkg/snapshotters"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
)

func (fs *Filesystem) ReferrerDetectEnabled() bool {
	return fs.referrerMgr != nil && fs.referrerMgr.ReferrerDetectEnabled()
}

func (fs *Filesystem) StreamUnpackEnabled() bool {
	return fs.referrerMgr != nil && fs.referrerMgr.StreamUnpackEnabled()
}

func (fs *Filesystem) CheckReferrer(ctx context.Context, labels map[string]string) bool {
	if !fs.ReferrerDetectEnabled() {
		return false
	}

	ref, ok := labels[snpkg.TargetRefLabel]
	if !ok {
		return false
	}

	manifestDigest := digest.Digest(labels[snpkg.TargetManifestDigestLabel])
	if manifestDigest.Validate() != nil {
		return false
	}

	if _, err := fs.referrerMgr.CheckReferrer(ctx, ref, manifestDigest); err != nil {
		return false
	}

	return true
}

func (fs *Filesystem) TryFetchMetadata(ctx context.Context, labels map[string]string, metadataPath string) error {
	ref, ok := labels[snpkg.TargetRefLabel]
	if !ok {
		return fmt.Errorf("empty label %s", snpkg.TargetRefLabel)
	}

	manifestDigest := digest.Digest(labels[snpkg.TargetManifestDigestLabel])
	if err := manifestDigest.Validate(); err != nil {
		return fmt.Errorf("invalid label %s=%s", snpkg.TargetManifestDigestLabel, manifestDigest)
	}

	if err := fs.referrerMgr.TryFetchMetadata(ctx, ref, manifestDigest, metadataPath); err != nil {
		return errors.Wrap(err, "try fetch metadata")
	}

	return nil
}

func (fs *Filesystem) TryFetchAndApplyLayer(ctx context.Context, labels map[string]string, mounts []mount.Mount, doneErr chan error) error {
	log.L.Infof("[abin] in TryFetchAndApplyLayer labels: %v", labels)
	ref, ok := labels[snpkg.TargetRefLabel]
	if !ok {
		return fmt.Errorf("empty label %s", snpkg.TargetRefLabel)
	}

	layerdigest := digest.Digest(labels[snpkg.TargetLayerDigestLabel])
	if err := layerdigest.Validate(); err != nil {
		return fmt.Errorf("invalid label %s=%s", snpkg.TargetLayerDigestLabel, layerdigest)
	}

	log.L.Infof("[abin] TryFetchAndApplyLayer ref: %s", ref)

	if err := fs.referrerMgr.TryFetchAndApplyLayer(ctx, ref, layerdigest, mounts, doneErr); err != nil {
		return errors.Wrap(err, "try fetch and apply layer")
	}

	return nil
}
