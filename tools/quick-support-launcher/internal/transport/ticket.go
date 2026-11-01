// Package transport handles only an ephemeral transport capability. A lease is
// not a receiver grant, proof of consent, or permission to start remote control.
package transport

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

var ErrRejected = errors.New("quick support transport rejected")

const origin = "https://quick-support-api.midtowntg.com"
const maxLease = 10 * time.Minute

type PublicRecipient struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type Pending struct {
	mu                 sync.Mutex
	key                *rsa.PrivateKey
	sessionID, leaseID string
	created            time.Time
}

type receipt struct {
	SessionID     string `json:"session_id"`
	LeaseID       string `json:"lease_id"`
	ExpiresAt     int64  `json:"expires_at"`
	Qualified     *bool  `json:"qualified"`
	RendezvousURL string `json:"rendezvous_url"`
	RelayURL      string `json:"relay_url"`
	Envelope      struct {
		Algorithm  string `json:"algorithm"`
		Ciphertext string `json:"ciphertext"`
		Label      string `json:"label"`
	} `json:"envelope"`
}

type leaseLabel struct {
	Contract  string `json:"contract"`
	LeaseID   string `json:"lease_id"`
	SessionID string `json:"session_id"`
	ExpiresAt int64  `json:"expires_at"`
}

type Lease struct {
	mu      sync.Mutex
	token   [32]byte
	expires time.Time
	created time.Time
	closed  bool
	done    chan struct{}
}

func validID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for index, character := range id {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
		} else if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

// NewPending pins the expected session and application request ID before the
// workflow call. The key remains private to this helper; send only PublicKey.
func NewPending(sessionID, requestID string, now time.Time) (*Pending, error) {
	if !validID(sessionID) || !validID(requestID) || now.IsZero() {
		return nil, ErrRejected
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, ErrRejected
	}
	return &Pending{key: key, sessionID: sessionID, leaseID: requestID, created: now}, nil
}

func (p *Pending) PublicKey() (PublicRecipient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.key == nil {
		return PublicRecipient{}, ErrRejected
	}
	return PublicRecipient{Kty: "RSA", N: base64.RawURLEncoding.EncodeToString(p.key.N.Bytes()), E: "AQAB"}, nil
}

func (p *Pending) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.key = nil // Drop ownership; Go does not guarantee private-key zeroization.
}

func uniqueObject(decoder *json.Decoder, depth int) error {
	if depth > 3 {
		return ErrRejected
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrRejected
	}
	if delimiter, ok := token.(json.Delim); ok {
		if delimiter != '{' {
			return ErrRejected
		}
		seen := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return ErrRejected
			}
			seen[name] = true
			if err := uniqueObject(decoder, depth+1); err != nil {
				return err
			}
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
			return ErrRejected
		}
	}
	return nil
}

func (p *Pending) Accept(raw []byte, now time.Time) (*Lease, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.key == nil || len(raw) > 8192 || now.Before(p.created) || !now.Before(p.created.Add(maxLease)) {
		return nil, ErrRejected
	}
	probe := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueObject(probe, 0); err != nil {
		return nil, ErrRejected
	}
	if _, err := probe.Token(); err != io.EOF {
		return nil, ErrRejected
	}
	var data receipt
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&data); err != nil {
		return nil, ErrRejected
	}
	expires := time.UnixMilli(data.ExpiresAt)
	if data.SessionID != p.sessionID || data.LeaseID != p.leaseID || data.Qualified == nil || *data.Qualified ||
		!expires.After(now) || expires.After(p.created.Add(maxLease+30*time.Second)) ||
		data.RendezvousURL != "wss://quick-support-api.midtowntg.com/ws/id" ||
		data.RelayURL != "wss://quick-support-api.midtowntg.com/ws/relay" ||
		data.Envelope.Algorithm != "RSA-OAEP-256" || len(data.Envelope.Ciphertext) != 344 {
		return nil, ErrRejected
	}
	label, err := json.Marshal(leaseLabel{"quick-support-transport/1", p.leaseID, p.sessionID, data.ExpiresAt})
	if err != nil || string(label) != data.Envelope.Label {
		return nil, ErrRejected
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(data.Envelope.Ciphertext)
	if err != nil || len(ciphertext) != 256 || base64.StdEncoding.EncodeToString(ciphertext) != data.Envelope.Ciphertext {
		return nil, ErrRejected
	}
	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, p.key, ciphertext, label)
	defer clear(plain)
	if err != nil || len(plain) != 64 {
		return nil, ErrRejected
	}
	decoded, err := hex.DecodeString(string(plain))
	defer clear(decoded)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != string(plain) {
		return nil, ErrRejected
	}
	lease := &Lease{expires: expires, created: now}
	copy(lease.token[:], decoded)
	p.key = nil
	return lease, nil
}

// AuthorizeUpgrade permits only the two fixed TLS upgrade routes. It does not
// dial, follow redirects, start a process or grant receiver control.
func (l *Lease) AuthorizeUpgrade(request *http.Request, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || now.Before(l.created) || !now.Before(l.expires) || request == nil || request.URL == nil || request.Method != "GET" ||
		(request.URL.String() != origin+"/ws/id" && request.URL.String() != origin+"/ws/relay") ||
		(request.Host != "" && request.Host != "quick-support-api.midtowntg.com") || request.Header.Get("Upgrade") != "websocket" {
		return ErrRejected
	}
	request.Header.Set("Authorization", "Bearer "+hex.EncodeToString(l.token[:]))
	return nil
}

func (l *Lease) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	clear(l.token[:])
	if !l.closed && l.done != nil {
		close(l.done)
	}
	l.closed = true
}

func (p *Pending) String() string   { return "QuickSupportPending(redacted)" }
func (p *Pending) GoString() string { return p.String() }
func (l *Lease) String() string     { return "QuickSupportLease(redacted)" }
func (l *Lease) GoString() string   { return l.String() }
