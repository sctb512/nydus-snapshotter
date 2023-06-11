/*
 * Copyright (c) 2023. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package referrer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/containerd/containerd/archive"
	"github.com/containerd/containerd/archive/compression"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/pkg/userns"
	"github.com/containerd/nydus-snapshotter/pkg/auth"
	"github.com/containerd/nydus-snapshotter/pkg/label"
	"github.com/containerd/nydus-snapshotter/pkg/remote"

	"github.com/containerd/nydus-snapshotter/pkg/remote/remotes"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// Containerd restricts the max size of manifest index to 8M, follow it.
const maxManifestIndexSize = 0x800000
const metadataNameInLayer = "image/image.boot"

var (
	manifestCache = make(map[string]ocispec.Manifest, 10)
)

type referrer struct {
	remote *remote.Remote
}

func newReferrer(keyChain *auth.PassKeyChain, insecure bool) *referrer {
	return &referrer{
		remote: remote.New(keyChain, insecure),
	}
}

// checkReferrer fetches the referrers and parses out the nydus
// image by specified manifest digest.
// it's using distribution list referrers API.
func (r *referrer) checkReferrer(ctx context.Context, ref string, manifestDigest digest.Digest) (*ocispec.Descriptor, error) {
	handle := func() (*ocispec.Descriptor, error) {
		// Create an new resolver to request.
		fetcher, err := r.remote.Fetcher(ctx, ref)
		if err != nil {
			return nil, errors.Wrap(err, "get fetcher")
		}

		// Fetch image referrers from remote registry.
		rc, _, err := fetcher.(remotes.ReferrersFetcher).FetchReferrers(ctx, manifestDigest)
		if err != nil {
			return nil, errors.Wrap(err, "fetch referrers")
		}
		defer rc.Close()

		// Parse image manifest list from referrers.
		var index ocispec.Index
		bytes, err := io.ReadAll(io.LimitReader(rc, maxManifestIndexSize))
		if err != nil {
			return nil, errors.Wrap(err, "read referrers")
		}
		if err := json.Unmarshal(bytes, &index); err != nil {
			return nil, errors.Wrap(err, "unmarshal referrers index")
		}
		if len(index.Manifests) == 0 {
			return nil, fmt.Errorf("empty referrer list")
		}

		// Prefer to fetch the last manifest and check if it is a nydus image.
		// TODO: should we search by matching ArtifactType?
		rc, err = fetcher.Fetch(ctx, index.Manifests[0])
		if err != nil {
			return nil, errors.Wrap(err, "fetch referrers")
		}
		defer rc.Close()

		var manifest ocispec.Manifest
		bytes, err = io.ReadAll(rc)
		if err != nil {
			return nil, errors.Wrap(err, "read manifest")
		}
		if err := json.Unmarshal(bytes, &manifest); err != nil {
			return nil, errors.Wrap(err, "unmarshal manifest")
		}
		if len(manifest.Layers) < 1 {
			return nil, fmt.Errorf("invalid manifest")
		}
		metaLayer := manifest.Layers[len(manifest.Layers)-1]
		if !label.IsNydusMetaLayer(metaLayer.Annotations) {
			return nil, fmt.Errorf("invalid nydus manifest")
		}

		return &metaLayer, nil
	}

	desc, err := handle()
	if err != nil && r.remote.RetryWithPlainHTTP(ref, err) {
		return handle()
	}

	return desc, err
}

// fetchMetadata fetches and unpacks nydus metadata file to specified path.
func (r *referrer) fetchMetadata(ctx context.Context, ref string, desc ocispec.Descriptor, metadataPath string) error {
	handle := func() error {
		// Create an new resolver to request.
		resolver := r.remote.Resolve(ctx, ref)
		fetcher, err := resolver.Fetcher(ctx, ref)
		if err != nil {
			return errors.Wrap(err, "get fetcher")
		}

		// Unpack nydus metadata file to specified path.
		rc, err := fetcher.Fetch(ctx, desc)
		if err != nil {
			return errors.Wrap(err, "fetch nydus metadata")
		}
		defer rc.Close()

		if err := remote.Unpack(rc, metadataNameInLayer, metadataPath); err != nil {
			os.Remove(metadataPath)
			return errors.Wrap(err, "unpack metadata from layer")
		}

		return nil
	}

	// TODO: check metafile already exists
	err := handle()
	if err != nil && r.remote.RetryWithPlainHTTP(ref, err) {
		return handle()
	}

	return err
}

func (r *referrer) fetchImageInfo(ctx context.Context, ref string, digest digest.Digest) (*ocispec.Descriptor, error) {
	log.L.Infof("[abin] Fetching image info, ref: %s, manifestCache: %v", ref, manifestCache)
	manifest, ok := manifestCache[ref]
	log.L.Infof("[abin] manifest: %v, ok: %v", manifest, ok)
	if ok {
		for _, layer := range manifest.Layers {
			log.L.Infof("[abin] cache layer: %v", layer.Digest)
			if layer.Digest == digest {
				return &layer, nil
			}
		}
	}

	resolver := r.remote.Resolve(ctx, ref)

	name, manifestDesc, err := resolver.Resolve(ctx, ref)
	log.L.Infof("[abin] name: %v", name)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to resolve reference for %q", ref)
	}

	fetcher, err := resolver.Fetcher(ctx, name)
	if err != nil {
		return nil, errors.Wrap(err, "get fetcher")
	}

	m, err := fetchManifest(ctx, fetcher, manifestDesc)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch manifest for %q", ref)
	}

	log.L.Infof("[abin] fetche manifest succesful: %v", m)

	// cfg, err := fetchConfig(ctx, fetcher, m.Config)
	// if err != nil {
	// 	return nil, errors.Wrapf(err, "failed to fetch config for %q", ref)
	// }
	// log.L.WithField("test", "abin").Infof("cfg: %v", cfg)
	manifestCache[ref] = *m

	log.L.Infof("[abin] manifest: %v", m)
	for _, layer := range m.Layers {
		log.L.Infof("[abin] layer: %v", layer.Digest)
		if layer.Digest == digest {
			return &layer, nil
		}
	}

	return nil, errors.Errorf("failed to find layer %v", digest)
}

func fetchManifest(ctx context.Context, fetcher remotes.Fetcher, desc ocispec.Descriptor) (*ocispec.Manifest, error) {
	rc, err := fetchBlob(ctx, fetcher, desc)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch manifest blob")
	}

	bytes, err := io.ReadAll(rc)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read manifest blob")
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(bytes, &manifest); err != nil {
		return nil, err
	}

	return &manifest, nil
}

// func fetchConfig(ctx context.Context, fetcher remotes.Fetcher, desc ocispec.Descriptor) (*ocispec.Image, error) {
// 	rc, err := fetchBlob(ctx, fetcher, desc)
// 	if err != nil {
// 		return nil, errors.Wrapf(err, "failed to fetch manifest blob")
// 	}

// 	bytes, err := io.ReadAll(rc)
// 	if err != nil {
// 		return nil, errors.Wrapf(err, "failed to read manifest blob")
// 	}

// 	var config ocispec.Image
// 	if err := json.Unmarshal(bytes, &config); err != nil {
// 		return nil, err
// 	}

// 	return &config, nil
// }

func fetchBlob(ctx context.Context, fetcher remotes.Fetcher, desc ocispec.Descriptor) (io.ReadCloser, error) {
	return fetcher.Fetch(ctx, desc)
}

func getOverlayPath(options []string) (upper string, lower []string, err error) {
	const upperdirPrefix = "upperdir="
	const lowerdirPrefix = "lowerdir="

	for _, o := range options {
		if strings.HasPrefix(o, upperdirPrefix) {
			upper = strings.TrimPrefix(o, upperdirPrefix)
		} else if strings.HasPrefix(o, lowerdirPrefix) {
			lower = strings.Split(strings.TrimPrefix(o, lowerdirPrefix), ":")
		}
	}
	if upper == "" {
		return "", nil, fmt.Errorf("upperdir not found: %w", errdefs.ErrInvalidArgument)
	}

	return
}

// getAufsPath handles options as given by the containerd aufs package only,
// formatted as "br:<upper>=rw[:<lower>=ro+wh]*"
func getAufsPath(options []string) (upper string, lower []string, err error) {
	const (
		sep      = ":"
		brPrefix = "br:"
		rwSuffix = "=rw"
		roSuffix = "=ro+wh"
	)
	for _, o := range options {
		if strings.HasPrefix(o, brPrefix) {
			o = strings.TrimPrefix(o, brPrefix)
		} else {
			continue
		}

		for _, b := range strings.Split(o, sep) {
			if strings.HasSuffix(b, rwSuffix) {
				if upper != "" {
					return "", nil, fmt.Errorf("multiple rw branch found: %w", errdefs.ErrInvalidArgument)
				}
				upper = strings.TrimSuffix(b, rwSuffix)
			} else if strings.HasSuffix(b, roSuffix) {
				if upper == "" {
					return "", nil, fmt.Errorf("rw branch be first: %w", errdefs.ErrInvalidArgument)
				}
				lower = append(lower, strings.TrimSuffix(b, roSuffix))
			} else {
				return "", nil, fmt.Errorf("unhandled aufs suffix: %w", errdefs.ErrInvalidArgument)
			}

		}
	}
	if upper == "" {
		return "", nil, fmt.Errorf("rw branch not found: %w", errdefs.ErrInvalidArgument)
	}
	return
}

func apply(ctx context.Context, mounts []mount.Mount, r io.Reader) error {
	switch {
	case len(mounts) == 1 && mounts[0].Type == "overlay":
		// OverlayConvertWhiteout (mknod c 0 0) doesn't work in userns.
		// https://github.com/containerd/containerd/issues/3762
		if userns.RunningInUserNS() {
			break
		}
		path, parents, err := getOverlayPath(mounts[0].Options)
		if err != nil {
			if errdefs.IsInvalidArgument(err) {
				break
			}
			return err
		}
		opts := []archive.ApplyOpt{
			archive.WithConvertWhiteout(archive.OverlayConvertWhiteout),
		}
		if len(parents) > 0 {
			opts = append(opts, archive.WithParents(parents))
		}
		_, err = archive.Apply(ctx, path, r, opts...)
		return err
	case len(mounts) == 1 && mounts[0].Type == "aufs":
		path, parents, err := getAufsPath(mounts[0].Options)
		if err != nil {
			if errdefs.IsInvalidArgument(err) {
				break
			}
			return err
		}
		opts := []archive.ApplyOpt{
			archive.WithConvertWhiteout(archive.AufsConvertWhiteout),
		}
		if len(parents) > 0 {
			opts = append(opts, archive.WithParents(parents))
		}
		_, err = archive.Apply(ctx, path, r, opts...)
		return err
	}
	return mount.WithTempMount(ctx, mounts, func(root string) error {
		_, err := archive.Apply(ctx, root, r)
		return err
	})
}

func (r *referrer) fetchLayer(ctx context.Context, ref string, layer ocispec.Descriptor,
	mounts []mount.Mount, doneErr chan error) error {

	// Create an new resolver to request.
	resolver := r.remote.Resolve(ctx, ref)

	fetcher, err := resolver.Fetcher(ctx, ref)
	if err != nil {
		return errors.Wrap(err, "get fetcher")
	}

	go func() {
		log.L.Infof("[abin] fetch blob %s, type: %s", layer.Digest, layer.MediaType)
		blobRc, err := fetchBlob(ctx, fetcher, layer)
		if err != nil {
			doneErr <- errors.Wrapf(err, "failed to fetch blob %s", layer.Digest)
		}
		log.L.Infof("[abin] fetch blob %s successful, type: %s", layer.Digest, layer.MediaType)
		defer func() {
			if blobRc != nil {
				blobRc.Close()
			}
		}()

		newBlobRc := blobRc.(io.Reader)

		ds, err := compression.DecompressStream(newBlobRc)
		if err != nil {
			doneErr <- errors.Wrap(err, "unpack stream")
		}
		defer func() {
			if ds != nil {
				ds.Close()
			}
		}()

		log.L.Infof("[abin] apply mounts: %v", mounts)
		if err := apply(ctx, mounts, ds); err != nil {
			doneErr <- errors.Wrap(err, "apply blob from layer")
		}
		log.L.Infof("[abin] apply successful, mounts: %v", mounts)

		close(doneErr)
	}()

	return nil
}

// applyLayer fetches and apply OCI blob file with mounts.
func (r *referrer) applyLayer(ctx context.Context, ref string, digest digest.Digest, mounts []mount.Mount, doneErr chan error) error {
	handle := func() error {
		log.L.Infof("[abin] apply layer ref: %s", ref)

		layer, err := r.fetchImageInfo(ctx, ref, digest)
		if err != nil {
			return errors.Wrap(err, "fetch manifest")
		}

		if err := r.fetchLayer(ctx, ref, *layer, mounts, doneErr); err != nil {
			return errors.Wrap(err, "fetch blobs")
		}

		return nil
	}

	// TODO: check metafile already exists
	err := handle()
	if err != nil && r.remote.RetryWithPlainHTTP(ref, err) {
		return handle()
	}

	return err
}
