// Package ipfsstore implements store.Store against a Kubo (go-ipfs) node over its HTTP
// RPC API, using the mutable-files (MFS) namespace to give opaque ObjectIDs plain
// create/read/stat/remove semantics. It talks to Kubo purely over net/http so the adapter
// stays cgo-free and does not pull in the go-ipfs module tree. It is the backend behind the
// out-of-process IPFS adapter (Hop B in docs/Architecture.md §4.5.1); only opaque ciphertext
// and hashed identifiers ever reach it.
package ipfsstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"github.com/revika/revika/internal/store"
)

// basePath is the MFS directory under which every object is written.
const basePath = "/revika"

// Store is a store.Store backed by a Kubo node's MFS namespace.
type Store struct {
	apiURL string
	client *http.Client
}

var _ store.Store = (*Store)(nil)

// New returns a Store that reaches Kubo's RPC API at apiURL (for example
// "http://kubo:5001"). A nil httpClient uses http.DefaultClient.
func New(apiURL string, httpClient *http.Client) *Store {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Store{apiURL: strings.TrimRight(apiURL, "/"), client: httpClient}
}

// mfsPath maps an opaque ObjectID to a stable, filesystem-safe MFS path by hashing it,
// mirroring the on-disk scheme in internal/store/disk.go.
func mfsPath(id store.ObjectID) string {
	sum := sha256.Sum256([]byte(id))
	return basePath + "/" + hex.EncodeToString(sum[:])
}

func (s *Store) Put(ctx context.Context, id store.ObjectID, content io.Reader) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	present, err := s.stat(ctx, id)
	if err != nil {
		return err
	}
	if present {
		return store.ErrAlreadyExists
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("data", "object")
	if err != nil {
		return fmt.Errorf("build upload: %w", err)
	}
	if _, err := io.Copy(part, content); err != nil {
		return fmt.Errorf("read object: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finalize upload: %w", err)
	}

	query := url.Values{}
	query.Set("arg", mfsPath(id))
	query.Set("create", "true")
	query.Set("parents", "true")
	query.Set("truncate", "true")
	response, err := s.post(ctx, "/api/v0/files/write", query, writer.FormDataContentType(), &body)
	if err != nil {
		return err
	}
	return closeResponse(response)
}

func (s *Store) Get(ctx context.Context, id store.ObjectID) (io.ReadCloser, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	query := url.Values{}
	query.Set("arg", mfsPath(id))
	response, err := s.post(ctx, "/api/v0/files/read", query, "", nil)
	if err != nil {
		if isNotExist(err) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return response.Body, nil
}

func (s *Store) Has(ctx context.Context, id store.ObjectID) (bool, error) {
	if err := ctxErr(ctx); err != nil {
		return false, err
	}
	return s.stat(ctx, id)
}

func (s *Store) Delete(ctx context.Context, id store.ObjectID) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	present, err := s.stat(ctx, id)
	if err != nil {
		return err
	}
	if !present {
		return store.ErrNotFound
	}
	query := url.Values{}
	query.Set("arg", mfsPath(id))
	query.Set("force", "true")
	response, err := s.post(ctx, "/api/v0/files/rm", query, "", nil)
	if err != nil {
		return err
	}
	return closeResponse(response)
}

func (s *Store) Close() error { return nil }

// stat reports whether the object exists via files/stat.
func (s *Store) stat(ctx context.Context, id store.ObjectID) (bool, error) {
	query := url.Values{}
	query.Set("arg", mfsPath(id))
	response, err := s.post(ctx, "/api/v0/files/stat", query, "", nil)
	if err != nil {
		if isNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, closeResponse(response)
}

// post issues a Kubo RPC call. Kubo's API is POST-only. A non-2xx response is turned into
// an apiError carrying the status and body so callers can classify "file does not exist".
func (s *Store) post(ctx context.Context, path string, query url.Values, contentType string, body io.Reader) (*http.Response, error) {
	endpoint := s.apiURL + path
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("ipfs request: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		response.Body.Close()
		return nil, &apiError{status: response.StatusCode, message: string(message)}
	}
	return response, nil
}

func ctxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func closeResponse(response *http.Response) error {
	_, _ = io.Copy(io.Discard, response.Body)
	return response.Body.Close()
}
