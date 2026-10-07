package artifact

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func releaseFixture(t *testing.T) (ReleaseTrust, releasePayload, ed25519.PrivateKey) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	trust := ReleaseTrust{PublicKey: key.Public().(ed25519.PublicKey), Issuer: "https://issuer.example.test", Origin: "https://downloads.example.test", Version: "1.5.0+mtg.qs.1", SourceRevision: strings.Repeat("a", 40)}
	var payload releasePayload
	payload.Issuer, payload.Audience = trust.Issuer, "quick-support-client-release"
	payload.Version, payload.SourceRevision = trust.Version, trust.SourceRevision
	payload.Artifact.URL, payload.Artifact.Origin = trust.Origin+"/client.exe", trust.Origin
	payload.Artifact.SHA256, payload.Artifact.PublisherThumbprint = strings.Repeat("b", 64), strings.Repeat("c", 40)
	payload.Artifact.Bytes = 12345
	return trust, payload, key
}

func signRelease(t *testing.T, key ed25519.PrivateKey, header, payload []byte) string {
	t.Helper()
	message := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return message + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(message)))
}

func encodeRelease(t *testing.T, key ed25519.PrivateKey, payload releasePayload) string {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return signRelease(t, key, []byte(`{"alg":"EdDSA","typ":"rd-qs-release+jwt"}`), data)
}

func TestReleaseAuthenticatesExactApprovedArtifact(t *testing.T) {
	trust, payload, key := releaseFixture(t)
	policy, err := VerifyRelease(encodeRelease(t, key, payload), trust)
	if err != nil || policy.URL != payload.Artifact.URL || policy.SHA256 != payload.Artifact.SHA256 || policy.PublisherThumbprint != payload.Artifact.PublisherThumbprint || policy.Bytes != payload.Artifact.Bytes {
		t.Fatalf("approved release rejected or changed: %v", err)
	}
}

func TestReleaseRejectsForgeryAndCrossScopeMetadata(t *testing.T) {
	trust, payload, key := releaseFixture(t)
	for _, field := range []string{"issuer", "audience", "version", "source", "origin", "host", "http", "credentials", "fragment", "size", "hash", "publisher"} {
		t.Run(field, func(t *testing.T) {
			changed := payload
			switch field {
			case "issuer":
				changed.Issuer = "https://other.example.test"
			case "audience":
				changed.Audience = "rustdesk-quick-support"
			case "version":
				changed.Version = "old-release"
			case "source":
				changed.SourceRevision = strings.Repeat("d", 40)
			case "origin":
				changed.Artifact.Origin = "https://other.example.test"
			case "host":
				changed.Artifact.URL = "https://other.example.test/client.exe"
			case "http":
				changed.Artifact.URL = "http://downloads.example.test/client.exe"
			case "credentials":
				changed.Artifact.URL = "https://user@downloads.example.test/client.exe"
			case "fragment":
				changed.Artifact.URL += "#private"
			case "size":
				changed.Artifact.Bytes = MaxBytes + 1
			case "hash":
				changed.Artifact.SHA256 = strings.Repeat("z", 64)
			case "publisher":
				changed.Artifact.PublisherThumbprint = ""
			}
			policy, err := VerifyRelease(encodeRelease(t, key, changed), trust)
			if !errors.Is(err, ErrRejected) || policy != (Policy{}) {
				t.Fatal("unapproved release metadata accepted")
			}
		})
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	if _, err := VerifyRelease(encodeRelease(t, other, payload), trust); !errors.Is(err, ErrRejected) {
		t.Fatal("untrusted signer accepted")
	}
	token := encodeRelease(t, key, payload)
	parts := strings.Split(token, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"tampered"}`))
	if _, err := VerifyRelease(strings.Join(parts, "."), trust); !errors.Is(err, ErrRejected) {
		t.Fatal("modified payload accepted")
	}
}

func TestReleaseRejectsAmbiguousSignedJSONAndHeaders(t *testing.T) {
	trust, payload, key := releaseFixture(t)
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	header := []byte(`{"alg":"EdDSA","typ":"rd-qs-release+jwt"}`)
	for _, badHeader := range []string{
		`{"alg":"none","typ":"rd-qs-release+jwt"}`,
		`{"alg":"EdDSA","typ":"rd-qs+jwt"}`,
		`{"alg":"EdDSA","alg":"EdDSA","typ":"rd-qs-release+jwt"}`,
		`{"ALG":"EdDSA","typ":"rd-qs-release+jwt"}`,
		`{"alg":"EdDSA","typ":"rd-qs-release+jwt","jku":"https://other.example.test"}`,
	} {
		if _, err := VerifyRelease(signRelease(t, key, []byte(badHeader), data), trust); !errors.Is(err, ErrRejected) {
			t.Fatal("invalid JWS header accepted")
		}
	}
	for _, badPayload := range []string{
		strings.Replace(string(data), `"bytes":12345`, `"bytes":1,"bytes":12345`, 1),
		strings.Replace(string(data), `"bytes":12345`, `"bytes":1,"BYTES":12345`, 1),
		string(data[:len(data)-1]) + `,"unexpected":true}`,
		string(data) + `{}`,
	} {
		if _, err := VerifyRelease(signRelease(t, key, header, []byte(badPayload)), trust); !errors.Is(err, ErrRejected) {
			t.Fatal("ambiguous or unknown signed JSON accepted")
		}
	}
}

func TestReleaseRejectsUnboundedTokensAndInvalidTrustWithoutPanicking(t *testing.T) {
	trust, payload, key := releaseFixture(t)
	token := encodeRelease(t, key, payload)
	for _, malformed := range []string{"", token + ".extra", strings.Repeat("a", 16385), "e30=.e30=.AA", strings.Replace(token, ".", "\n.", 1)} {
		if _, err := VerifyRelease(malformed, trust); !errors.Is(err, ErrRejected) {
			t.Fatal("malformed token accepted")
		}
	}
	for _, length := range []int{0, 31, 33} {
		changed := trust
		changed.PublicKey = make([]byte, length)
		if _, err := VerifyRelease(token, changed); !errors.Is(err, ErrRejected) {
			t.Fatal("invalid pinned key accepted")
		}
	}
	for _, origin := range []string{"http://downloads.example.test", "https://downloads.example.test/path", "https://downloads.example.test?query", "https://user@downloads.example.test", ""} {
		changed := trust
		changed.Origin = origin
		if _, err := VerifyRelease(token, changed); !errors.Is(err, ErrRejected) {
			t.Fatal("unsafe pinned origin accepted")
		}
	}
}
