package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T, body string) (*httptest.Server, Policy) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
	t.Cleanup(server.Close)
	sum := sha256.Sum256([]byte("reviewed-client"))
	return server, Policy{URL: server.URL + "/client.exe", Origin: server.URL, SHA256: hex.EncodeToString(sum[:]), Bytes: 15, PublisherThumbprint: "4230334F8A7DD84E50D0273EF379E8B4A82F5DA5"}
}

func TestDigestAndAuthenticodeAreBothRequired(t *testing.T) {
	for _, test := range []struct {
		name, body string
		trusted    bool
	}{
		{"valid", "reviewed-client", true}, {"wrong digest", "tampered-client", true},
		{"truncated", "short", true}, {"oversized", "reviewed-client-extra", true},
		{"untrusted signature", "reviewed-client", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, policy := fixture(t, test.body)
			path := filepath.Join(t.TempDir(), "client.exe")
			verified := false
			err := Fetch(t.Context(), server.Client(), policy, path, func(ctx context.Context, file, publisher string) error {
				verified = true
				if publisher != policy.PublisherThumbprint {
					t.Fatal("wrong publisher")
				}
				if !test.trusted {
					return errors.New("untrusted")
				}
				return nil
			})
			if test.name == "valid" {
				if err != nil || !verified {
					t.Fatalf("valid download failed: %v", err)
				}
				if Fetch(t.Context(), server.Client(), policy, path, func(context.Context, string, string) error { return nil }) == nil {
					t.Fatal("overwrote existing file")
				}
			} else {
				if err == nil {
					t.Fatal("accepted bad artifact")
				}
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatalf("failed download retained: %v", err)
				}
			}
		})
	}
}

func TestUnsafePoliciesAndMissingVerifierFailClosed(t *testing.T) {
	server, valid := fixture(t, "reviewed-client")
	for _, change := range []func(*Policy){
		func(p *Policy) { p.URL = "http://example.test/client.exe" }, func(p *Policy) { p.URL = "https://attacker.example.test/client.exe" },
		func(p *Policy) { p.URL = "https://user:password@example.test/client.exe" }, func(p *Policy) { p.URL += "#secret" },
		func(p *Policy) { p.SHA256 = "" }, func(p *Policy) { p.Bytes = MaxBytes + 1 }, func(p *Policy) { p.PublisherThumbprint = "" },
	} {
		policy := valid
		change(&policy)
		if Fetch(t.Context(), server.Client(), policy, filepath.Join(t.TempDir(), "client.exe"), func(context.Context, string, string) error { return nil }) == nil {
			t.Fatal("unsafe policy accepted")
		}
	}
	if Fetch(t.Context(), server.Client(), valid, filepath.Join(t.TempDir(), "client.exe"), nil) == nil {
		t.Fatal("missing verifier accepted")
	}
}

func TestRedirectAndCancellationFailClosed(t *testing.T) {
	alternate := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("redirect contacted alternate host") }))
	defer alternate.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, alternate.URL, http.StatusFound) }))
	defer server.Close()
	_, policy := fixture(t, "reviewed-client")
	policy.URL = server.URL + "/client.exe"
	policy.Origin = server.URL
	if Fetch(t.Context(), server.Client(), policy, filepath.Join(t.TempDir(), "client.exe"), func(context.Context, string, string) error { return nil }) == nil {
		t.Fatal("redirect accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if Fetch(ctx, server.Client(), policy, filepath.Join(t.TempDir(), "client.exe"), func(context.Context, string, string) error { return nil }) == nil {
		t.Fatal("canceled request accepted")
	}
}
