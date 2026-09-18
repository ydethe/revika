package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/revika/revika/internal/provider"
)

func runCP(ctx context.Context, prov provider.Provider, database *sql.DB, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("cp: expected source and destination")
	}
	src, dst := args[0], args[1]
	srcRemote, dstRemote := isRemotePath(src), isRemotePath(dst)
	switch {
	case srcRemote && !dstRemote:
		return downloadPath(ctx, prov, database, src, dst)
	case !srcRemote && dstRemote:
		return uploadPath(ctx, prov, database, src, dst)
	default:
		return fmt.Errorf("cp: exactly one of source or destination must have the %q prefix", rvkPrefix)
	}
}

// uploadPath copies a local file or directory tree onto the revika namespace.
func uploadPath(ctx context.Context, prov provider.Provider, database *sql.DB, localPath, remotePath string) error {
	info, err := os.Stat(localPath)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return uploadDir(ctx, prov, database, localPath, remotePath)
	}
	return uploadFile(ctx, prov, database, localPath, remotePath)
}

func uploadFile(ctx context.Context, prov provider.Provider, database *sql.DB, localPath, remotePath string) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	parentPath, name, err := resolveUploadTarget(ctx, prov, remotePath, filepath.Base(localPath))
	if err != nil {
		return err
	}
	parentID, err := ensureDir(ctx, prov, parentPath)
	if err != nil {
		return err
	}
	return createEncryptedFile(ctx, prov, database, parentID, name, data)
}

func uploadDir(ctx context.Context, prov provider.Provider, database *sql.DB, localRoot, remoteRoot string) error {
	parentPath, name, err := resolveUploadTarget(ctx, prov, remoteRoot, filepath.Base(localRoot))
	if err != nil {
		return err
	}
	baseRemote := joinRemote(parentPath, name)
	if _, err := ensureDir(ctx, prov, baseRemote); err != nil {
		return err
	}
	return filepath.WalkDir(localRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(localRoot, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		remotePath := joinRemote(baseRemote, filepath.ToSlash(relative))
		if entry.IsDir() {
			_, err := ensureDir(ctx, prov, remotePath)
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		itemParent, itemName := splitParent(remotePath)
		parentID, err := ensureDir(ctx, prov, itemParent)
		if err != nil {
			return err
		}
		return createEncryptedFile(ctx, prov, database, parentID, itemName, data)
	})
}

func createEncryptedFile(ctx context.Context, prov provider.Provider, database *sql.DB, parentID provider.ItemID, name string, data []byte) error {
	envelope, key, err := encryptContent(data)
	if err != nil {
		return err
	}
	item, err := prov.CreateItem(ctx, parentID, provider.CreateRequest{Name: name, Contents: bytes.NewReader(envelope)})
	if err != nil {
		return err
	}
	return putFileKey(database, item.ID, key)
}

// downloadPath copies a revika file or directory tree onto the local filesystem.
func downloadPath(ctx context.Context, prov provider.Provider, database *sql.DB, remotePath, localPath string) error {
	item, err := resolve(ctx, prov, remotePath)
	if err != nil {
		return err
	}
	target := resolveDownloadTarget(localPath, item.Name)
	if item.IsDir {
		return downloadDir(ctx, prov, database, item, target)
	}
	return downloadFile(ctx, prov, database, item, target)
}

// resolveDownloadTarget places the item inside localPath if it already names a directory,
// otherwise treats localPath as the exact destination.
func resolveDownloadTarget(localPath, fallbackName string) string {
	if info, err := os.Stat(localPath); err == nil && info.IsDir() {
		return filepath.Join(localPath, fallbackName)
	}
	return localPath
}

func downloadFile(ctx context.Context, prov provider.Provider, database *sql.DB, item provider.Item, localPath string) error {
	key, err := getFileKey(database, item.ID)
	if err != nil {
		return err
	}
	var buffer bytes.Buffer
	if _, err := prov.FetchContents(ctx, item.ID, &buffer); err != nil {
		return err
	}
	plaintext, err := decryptContent(key, buffer.Bytes())
	if err != nil {
		return err
	}
	if dir := filepath.Dir(localPath); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(localPath, plaintext, 0o600)
}

func downloadDir(ctx context.Context, prov provider.Provider, database *sql.DB, item provider.Item, localRoot string) error {
	if err := os.MkdirAll(localRoot, 0o700); err != nil {
		return err
	}
	children, err := prov.Enumerate(ctx, item.ID)
	if err != nil {
		return err
	}
	for _, child := range children {
		childPath := filepath.Join(localRoot, child.Name)
		if child.IsDir {
			if err := downloadDir(ctx, prov, database, child, childPath); err != nil {
				return err
			}
			continue
		}
		if err := downloadFile(ctx, prov, database, child, childPath); err != nil {
			return err
		}
	}
	return nil
}
