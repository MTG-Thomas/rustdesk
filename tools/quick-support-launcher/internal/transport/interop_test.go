//go:build quick_support_interop

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"
)

// The optional cross-repository test executes the reviewed authority's actual
// envelope function. Only the ephemeral public recipient and a synthetic token
// enter Node; the private RSA key remains inside Pending.
func TestAuthorityWebCryptoEnvelope(t *testing.T) {
	source := os.Getenv("BIFROST_QS_AUTHORITY_SOURCE")
	if source == "" {
		t.Fatal("BIFROST_QS_AUTHORITY_SOURCE must identify the reviewed ticket-envelope.ts")
	}
	p := pending(t)
	public, err := p.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(map[string]any{"recipient": public, "ticket": syntheticTicket, "session_id": session, "lease_id": requestID, "expires_at": now.Add(time.Minute).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	script := `
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const input=JSON.parse(readFileSync(0,'utf8'));
const authority=await import(pathToFileURL(process.env.BIFROST_QS_AUTHORITY_SOURCE).href);
const {key}=await authority.recipient(input.recipient);
const context={lease_id:input.lease_id,session_id:input.session_id,expires_at:input.expires_at};
const envelope=await authority.envelope(key,input.ticket,context);
process.stdout.write(JSON.stringify({...context,envelope,qualified:false,
 rendezvous_url:'wss://quick-support-api.midtowntg.com/ws/id',relay_url:'wss://quick-support-api.midtowntg.com/ws/relay'}));`
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "node", "--experimental-strip-types", "--input-type=module", "-e", script)
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "BIFROST_QS_AUTHORITY_SOURCE=" + source}
	command.Stdin = bytes.NewReader(input)
	raw, err := command.Output()
	if err != nil {
		t.Fatalf("authority WebCrypto bridge failed: %v", err)
	}
	lease, err := p.Accept(raw, now)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	request := upgrade(t, origin+"/ws/id")
	if lease.AuthorizeUpgrade(request, now) != nil || request.Header.Get("Authorization") != "Bearer "+syntheticTicket {
		t.Fatal("cross-runtime envelope mismatch")
	}
}
