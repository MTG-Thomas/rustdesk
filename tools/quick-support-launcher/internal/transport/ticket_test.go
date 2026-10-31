package transport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const session = "11111111-1111-4111-8111-111111111111"
const requestID = "22222222-2222-4222-8222-222222222222"
const otherID = "33333333-3333-4333-8333-333333333333"

var now = time.Unix(1793470000, 0)
var syntheticTicket = strings.Repeat("ab", 32)

func pending(t *testing.T) *Pending {
	t.Helper()
	p, err := NewPending(session, requestID, now)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func encrypted(t *testing.T, p *Pending) receipt {
	t.Helper()
	pub, err := p.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	n, err := base64.RawURLEncoding.DecodeString(pub.N)
	if err != nil {
		t.Fatal(err)
	}
	if pub.Kty != "RSA" || pub.E != "AQAB" || len(pub.N) != 342 {
		t.Fatal("invalid public recipient")
	}
	expires := now.Add(5 * time.Minute).UnixMilli()
	label, err := json.Marshal(leaseLabel{"quick-support-transport/1", requestID, session, expires})
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}, []byte(syntheticTicket), label)
	if err != nil {
		t.Fatal(err)
	}
	qualified := false
	r := receipt{SessionID: session, LeaseID: requestID, ExpiresAt: expires, Qualified: &qualified, RendezvousURL: "wss://quick-support-api.midtowntg.com/ws/id", RelayURL: "wss://quick-support-api.midtowntg.com/ws/relay"}
	r.Envelope.Algorithm = "RSA-OAEP-256"
	r.Envelope.Label = string(label)
	r.Envelope.Ciphertext = base64.StdEncoding.EncodeToString(cipher)
	return r
}
func encoded(t *testing.T, r receipt) []byte {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func upgrade(t *testing.T, target string) *http.Request {
	t.Helper()
	r, err := http.NewRequest("GET", target, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Upgrade", "websocket")
	return r
}
func TestTicketAcceptedOnceAndOnlyAttachedToPinnedTLSRoutes(t *testing.T) {
	p := pending(t)
	raw := encoded(t, encrypted(t, p))
	lease, err := p.Accept(raw, now)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if _, err := p.Accept(raw, now); err != ErrRejected {
		t.Fatal("reused recipient")
	}
	if _, err := p.PublicKey(); err != ErrRejected {
		t.Fatal("recipient remains available after acceptance")
	}
	for _, path := range []string{"/ws/id", "/ws/relay"} {
		r := upgrade(t, origin+path)
		if err := lease.AuthorizeUpgrade(r, now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		if r.Header.Get("Authorization") != "Bearer "+syntheticTicket {
			t.Fatal("wrong capability")
		}
	}
	for _, target := range []string{"http://quick-support-api.midtowntg.com/ws/id", origin + "/ws/id?ticket=x", origin + "/ws/id#fragment", origin + "/other", "https://evil.test/ws/id", "https://quick-support-api.midtowntg.com.evil.test/ws/id"} {
		r := upgrade(t, target)
		if err := lease.AuthorizeUpgrade(r, now); err != ErrRejected || r.Header.Get("Authorization") != "" {
			t.Fatal("unsafe target accepted")
		}
	}
	r := upgrade(t, origin+"/ws/id")
	r.Host = "evil.test"
	if lease.AuthorizeUpgrade(r, now) != ErrRejected {
		t.Fatal("alternate host accepted")
	}
	r = upgrade(t, origin+"/ws/id")
	r.Method = "POST"
	if lease.AuthorizeUpgrade(r, now) != ErrRejected {
		t.Fatal("non-upgrade accepted")
	}
	if lease.AuthorizeUpgrade(upgrade(t, origin+"/ws/id"), now.Add(5*time.Minute)) != ErrRejected {
		t.Fatal("expired capability accepted")
	}
	if lease.AuthorizeUpgrade(upgrade(t, origin+"/ws/id"), now.Add(-time.Second)) != ErrRejected {
		t.Fatal("clock rollback accepted")
	}
}
func TestConfusedTamperedAndExpiredReceiptsDenied(t *testing.T) {
	mutations := map[string]func(*receipt){
		"session": func(r *receipt) { r.SessionID = otherID }, "request": func(r *receipt) { r.LeaseID = otherID },
		"expired": func(r *receipt) { r.ExpiresAt = now.UnixMilli() }, "unbounded": func(r *receipt) { r.ExpiresAt = now.Add(time.Hour).UnixMilli() },
		"qualified": func(r *receipt) { v := true; r.Qualified = &v }, "missing-qualified": func(r *receipt) { r.Qualified = nil },
		"label": func(r *receipt) { r.Envelope.Label += " " }, "algorithm": func(r *receipt) { r.Envelope.Algorithm = "RSA1_5" },
		"ciphertext": func(r *receipt) {
			raw, _ := base64.StdEncoding.DecodeString(r.Envelope.Ciphertext)
			raw[0] ^= 1
			r.Envelope.Ciphertext = base64.StdEncoding.EncodeToString(raw)
		},
		"rendezvous": func(r *receipt) { r.RendezvousURL = "wss://evil.test/ws/id" }, "relay": func(r *receipt) { r.RelayURL += "?key=x" },
	}
	p := pending(t)
	good := encrypted(t, p)
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			r := good
			mutate(&r)
			if _, err := p.Accept(encoded(t, r), now); err != ErrRejected {
				t.Fatal("invalid receipt accepted")
			}
		})
	}
	foreign := pending(t)
	if _, err := foreign.Accept(encoded(t, good), now); err != ErrRejected {
		t.Fatal("foreign recipient decrypted")
	}
	if _, err := p.Accept(encoded(t, good), now.Add(maxLease)); err != ErrRejected {
		t.Fatal("stale pending key accepted")
	}
	if _, err := p.Accept(encoded(t, good), now.Add(-time.Second)); err != ErrRejected {
		t.Fatal("pending clock rollback accepted")
	}
	if _, err := p.Accept(encoded(t, good), now); err != nil {
		t.Fatal("denials consumed a valid retry")
	}
}
func TestDuplicateUnknownOversizedAndTrailingJSONDenied(t *testing.T) {
	p := pending(t)
	raw := string(encoded(t, encrypted(t, p)))
	cases := []string{strings.Replace(raw, "{", `{"session_id":"`+otherID+`",`, 1), strings.Replace(raw, `"algorithm":`, `"algorithm":"RSA1_5","algorithm":`, 1), strings.TrimSuffix(raw, "}") + `,"ticket":"synthetic-plaintext"}`, raw + " {}", strings.Repeat(" ", 8193) + raw, `{"envelope":[]}`, `null`}
	for _, bad := range cases {
		if _, err := p.Accept([]byte(bad), now); err != ErrRejected {
			t.Fatal("unsafe JSON accepted")
		}
	}
}
func TestCloseRedactsAndPreventsAuthorization(t *testing.T) {
	p := pending(t)
	lease, err := p.Accept(encoded(t, encrypted(t, p)), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, lease), syntheticTicket) {
			t.Fatal("capability logged")
		}
	}
	for _, value := range []any{p, lease} {
		b, err := json.Marshal(value)
		if err != nil || string(b) != "{}" {
			t.Fatal("private state serialized")
		}
	}
	lease.Close()
	lease.Close()
	if lease.token != ([32]byte{}) {
		t.Fatal("token retained after close")
	}
	if lease.AuthorizeUpgrade(upgrade(t, origin+"/ws/id"), now) != ErrRejected {
		t.Fatal("closed lease accepted")
	}
	p = pending(t)
	p.Close()
	if _, err := p.PublicKey(); err != ErrRejected {
		t.Fatal("closed recipient accepted")
	}
}
func TestConcurrentAcceptanceAndClose(t *testing.T) {
	p := pending(t)
	raw := encoded(t, encrypted(t, p))
	var group sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for range 8 {
		group.Go(func() {
			lease, err := p.Accept(raw, now)
			if err == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
				lease.Close()
			}
		})
	}
	group.Wait()
	if accepted != 1 {
		t.Fatal("recipient accepted more than once")
	}
	p = pending(t)
	lease, err := p.Accept(encoded(t, encrypted(t, p)), now)
	if err != nil {
		t.Fatal(err)
	}
	for range 8 {
		group.Go(func() {
			r := &http.Request{Method: "GET", URL: &url.URL{Scheme: "https", Host: "quick-support-api.midtowntg.com", Path: "/ws/id"}, Header: http.Header{"Upgrade": []string{"websocket"}}}
			_ = lease.AuthorizeUpgrade(r, now)
			lease.Close()
		})
	}
	group.Wait()
}
