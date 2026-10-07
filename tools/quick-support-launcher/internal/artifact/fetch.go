// Package artifact downloads a reviewed client without executing it.
package artifact

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

const MaxBytes int64 = 128 << 20

var ErrRejected = errors.New("support client artifact rejected")

// Policy must be authenticated by the launcher's pinned manifest verifier.
type Policy struct {
	URL, Origin, SHA256, PublisherThumbprint string
	Bytes                                    int64
}

// VerifyAuthenticode must validate public trust and the exact expected publisher.
// Nil fails closed. This is a mandatory Windows integration, not a hash substitute.
type VerifyAuthenticode func(context.Context, string, string) error

// Fetch creates an exclusive file in an already private session-owned directory.
// It rejects existing paths, redirects, HTTP, credentials, unexpected hosts,
// oversized downloads, digest mismatch and rejected Authenticode. It never runs
// the binary. On Windows the caller must establish an owner-only directory ACL.
func Fetch(ctx context.Context, client *http.Client, policy Policy, destination string, verify VerifyAuthenticode) (err error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if client == nil || verify == nil || policy.Bytes <= 0 || policy.Bytes > MaxBytes || len(policy.PublisherThumbprint) != 40 {
		return ErrRejected
	}
	digest, err := hex.DecodeString(policy.SHA256)
	if err != nil || len(digest) != sha256.Size {
		return ErrRejected
	}
	if _, err = hex.DecodeString(policy.PublisherThumbprint); err != nil {
		return ErrRejected
	}
	address, err := url.Parse(policy.URL)
	if err != nil {
		return ErrRejected
	}
	origin, err := url.Parse(policy.Origin)
	if err != nil || !safeHTTPS(address) || !safeHTTPS(origin) || origin.Path != "" || origin.RawQuery != "" || address.Host != origin.Host {
		return ErrRejected
	}
	// Preserve the trusted TLS transport without mutating a shared HTTP client.
	bounded := *client
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address.String(), nil)
	if err != nil {
		return ErrRejected
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("Accept-Encoding", "identity")
	response, err := bounded.Do(request)
	if err != nil {
		return ErrRejected
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" || (response.ContentLength >= 0 && response.ContentLength != policy.Bytes) {
		return ErrRejected
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrRejected
	}
	owned := true
	defer func() {
		if owned {
			if removeErr := os.Remove(destination); removeErr != nil {
				err = errors.Join(err, removeErr)
			}
		}
	}()
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, policy.Bytes+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || written != policy.Bytes || subtle.ConstantTimeCompare(hash.Sum(nil), digest) != 1 {
		return ErrRejected
	}
	if err = verify(ctx, destination, policy.PublisherThumbprint); err != nil {
		return ErrRejected
	}
	owned = false
	return nil
}

func safeHTTPS(address *url.URL) bool {
	return address != nil && address.Scheme == "https" && address.Hostname() != "" && address.User == nil && address.Fragment == "" && address.Opaque == ""
}
