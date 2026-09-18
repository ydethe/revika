package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/revika/revika/internal/provider"
)

const rvkPrefix = "rvk:"

func isRemotePath(path string) bool {
	return strings.HasPrefix(path, rvkPrefix)
}

func stripRvkPrefix(path string) string {
	return strings.TrimPrefix(path, rvkPrefix)
}

func splitSegments(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func joinRemote(parent, name string) string {
	if parent == "" {
		return name
	}
	return strings.TrimSuffix(parent, "/") + "/" + name
}

// splitParent splits a namespace path (rvk: prefix optional) into its parent directory
// path and base name.
func splitParent(path string) (parent string, name string) {
	segments := splitSegments(stripRvkPrefix(path))
	if len(segments) == 0 {
		return "", ""
	}
	return strings.Join(segments[:len(segments)-1], "/"), segments[len(segments)-1]
}

// resolve walks path (rvk: prefix optional) from the namespace root and returns the item.
func resolve(ctx context.Context, prov provider.Provider, path string) (provider.Item, error) {
	root, err := prov.Root(ctx)
	if err != nil {
		return provider.Item{}, err
	}
	current, err := prov.Stat(ctx, root)
	if err != nil {
		return provider.Item{}, err
	}
	for _, segment := range splitSegments(stripRvkPrefix(path)) {
		current, err = prov.Lookup(ctx, current.ID, segment)
		if err != nil {
			return provider.Item{}, fmt.Errorf("resolve %q: %w", path, err)
		}
	}
	return current, nil
}

// ensureDir walks path (rvk: prefix optional) from the root, creating any missing
// directories along the way (mkdir -p), and returns the final directory's ID.
func ensureDir(ctx context.Context, prov provider.Provider, path string) (provider.ItemID, error) {
	root, err := prov.Root(ctx)
	if err != nil {
		return "", err
	}
	current := root
	for _, segment := range splitSegments(stripRvkPrefix(path)) {
		item, lookupErr := prov.Lookup(ctx, current, segment)
		switch {
		case lookupErr == nil:
			if !item.IsDir {
				return "", fmt.Errorf("ensure directory %q: %q is not a directory", path, segment)
			}
			current = item.ID
		case errors.Is(lookupErr, provider.ErrNotFound):
			created, createErr := prov.CreateItem(ctx, current, provider.CreateRequest{Name: segment, IsDir: true})
			if createErr != nil {
				return "", fmt.Errorf("create directory %q: %w", segment, createErr)
			}
			current = created.ID
		default:
			return "", fmt.Errorf("resolve directory %q: %w", path, lookupErr)
		}
	}
	return current, nil
}

// resolveUploadTarget decides the parent directory path and file name for an upload
// destination: a path naming an existing directory (or ending in "/", or empty) receives
// fallbackName as its file name; otherwise the path's own last segment is the new name.
func resolveUploadTarget(ctx context.Context, prov provider.Provider, remotePath, fallbackName string) (parentPath, name string, err error) {
	stripped := stripRvkPrefix(remotePath)
	if stripped == "" || strings.HasSuffix(stripped, "/") {
		return remotePath, fallbackName, nil
	}
	if existing, lookupErr := resolve(ctx, prov, remotePath); lookupErr == nil && existing.IsDir {
		return remotePath, fallbackName, nil
	}
	parent, name := splitParent(remotePath)
	return parent, name, nil
}
