package artifact

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"strings"
)

// PublicKey, Issuer and Origin must be pinned in the signed launcher. Version
// and SourceRevision may come from an independently verified session bootstrap.
// Never construct trust from the downloaded manifest or customer URL.
type ReleaseTrust struct {
	PublicKey                               ed25519.PublicKey
	Issuer, Origin, Version, SourceRevision string
}

type releaseHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type releasePayload struct {
	Issuer         string `json:"iss"`
	Audience       string `json:"aud"`
	Version        string `json:"version"`
	SourceRevision string `json:"source_revision"`
	Artifact       struct {
		URL                 string `json:"url"`
		Origin              string `json:"origin"`
		SHA256              string `json:"sha256"`
		PublisherThumbprint string `json:"publisher_thumbprint"`
		Bytes               int64  `json:"bytes"`
	} `json:"artifact"`
}

// VerifyRelease verifies an immutable release descriptor, not a session grant.
// The exact approved source/version is supplied by trusted configuration; live
// session authorization, revocation and expiry remain separate requirements.
// A verified descriptor still requires Fetch's hash and Windows trust checks.
func VerifyRelease(token string, trust ReleaseTrust) (Policy, error) {
	var rejected Policy
	if len(token) > 16384 || len(trust.PublicKey) != ed25519.PublicKeySize || trust.Issuer == "" || trust.Version == "" || len(trust.Version) > 100 || len(trust.SourceRevision) != 40 {
		return rejected, ErrRejected
	}
	if _, err := hex.DecodeString(trust.SourceRevision); err != nil {
		return rejected, ErrRejected
	}
	origin, err := url.Parse(trust.Origin)
	if err != nil || !safeHTTPS(origin) || origin.Path != "" || origin.RawQuery != "" {
		return rejected, ErrRejected
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return rejected, ErrRejected
	}
	decoded := make([][]byte, 3)
	for index, part := range parts {
		if part == "" || strings.IndexFunc(part, func(character rune) bool {
			return !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_')
		}) >= 0 {
			return rejected, ErrRejected
		}
		decoded[index], err = base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil {
			return rejected, ErrRejected
		}
	}
	if len(decoded[0]) > 512 || len(decoded[1]) > 8192 || len(decoded[2]) != ed25519.SignatureSize {
		return rejected, ErrRejected
	}
	var header releaseHeader
	if !strictReleaseJSON(decoded[0], &header) || header.Algorithm != "EdDSA" || header.Type != "rd-qs-release+jwt" {
		return rejected, ErrRejected
	}
	if !ed25519.Verify(trust.PublicKey, []byte(parts[0]+"."+parts[1]), decoded[2]) {
		return rejected, ErrRejected
	}
	var payload releasePayload
	if !strictReleaseJSON(decoded[1], &payload) || payload.Issuer != trust.Issuer || payload.Audience != "quick-support-client-release" || payload.Version != trust.Version || payload.SourceRevision != trust.SourceRevision {
		return rejected, ErrRejected
	}
	policy := Policy{URL: payload.Artifact.URL, Origin: payload.Artifact.Origin, SHA256: payload.Artifact.SHA256, PublisherThumbprint: payload.Artifact.PublisherThumbprint, Bytes: payload.Artifact.Bytes}
	address, err := url.Parse(policy.URL)
	if err != nil || !safeHTTPS(address) || address.Host != origin.Host || policy.Origin != trust.Origin || policy.Bytes <= 0 || policy.Bytes > MaxBytes || len(policy.SHA256) != 64 || len(policy.PublisherThumbprint) != 40 {
		return rejected, ErrRejected
	}
	for _, digest := range []string{policy.SHA256, policy.PublisherThumbprint} {
		if _, err := hex.DecodeString(digest); err != nil {
			return rejected, ErrRejected
		}
	}
	return policy, nil
}

func strictReleaseJSON(data []byte, destination any) bool {
	// encoding/json otherwise accepts duplicate object keys and keeps the last.
	reader := json.NewDecoder(bytes.NewReader(data))
	if !uniqueReleaseValue(reader, 0) {
		return false
	}
	if _, err := reader.Token(); err != io.EOF {
		return false
	}
	reader = json.NewDecoder(bytes.NewReader(data))
	reader.DisallowUnknownFields()
	return reader.Decode(destination) == nil
}

func uniqueReleaseValue(reader *json.Decoder, depth int) bool {
	if depth > 8 {
		return false
	}
	token, err := reader.Token()
	if err != nil {
		return false
	}
	delimiter, isContainer := token.(json.Delim)
	if !isContainer {
		return true
	}
	if delimiter != '{' {
		return false // This descriptor has no array-valued fields.
	}
	seen := map[string]bool{}
	for reader.More() {
		key, err := reader.Token()
		name, isName := key.(string)
		folded := strings.ToLower(name)
		if err != nil || !isName || name != folded || seen[folded] {
			return false
		}
		seen[folded] = true
		if !uniqueReleaseValue(reader, depth+1) {
			return false
		}
	}
	end, err := reader.Token()
	return err == nil && end == json.Delim('}')
}
