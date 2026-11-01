# Portable Quick Support launcher components

This is the unmanaged-Windows launcher under construction, not a distributable
launcher executable. Its artifact download component never executes a client.
The signed release manifest must authenticate the URL, exact origin, byte count,
SHA-256 and publisher certificate before a download is requested. Redirects,
plaintext HTTP, embedded credentials and a missing Authenticode verifier fail
closed. Files are created exclusively in a caller-owned private directory.
Failed downloads are removed; pre-existing files are never overwritten.

`VerifyRelease` authenticates compact Ed25519 release descriptors before they
become download policies. Pin the release key, issuer and HTTPS origin in the
signed launcher; require the exact approved version and source revision from
trusted configuration. The verifier rejects forged signatures, cross-purpose
tokens, duplicate/unknown JSON fields, oversized data and unsafe artifact
metadata. These immutable release descriptors have no session authority: live
consent, lease expiry and revocation remain mandatory. The release signer must
remain separate from session-grant issuance.

Windows signature verification invokes protected system PowerShell with a
constant, noninteractive script and an explicit system security module. It
requires Windows `Valid` Authenticode, the expected publisher certificate and a
timestamp. Environment fields carry file/publisher values; they are not script
interpolation. No OS output is forwarded. Windows CI verifies the pinned,
unmodified signed RustDesk 1.5.0 fixture and rejects a different publisher,
without executing the fixture. This qualifies the verification component;
our patched client and launcher still need their own signatures and device tests.

Construct the explicit module path with language primitives. `Join-Path` loads
the unrelated Management module in the restricted process environment and can
exhaust the 30-second deadline. A same-run Windows comparison measured 26.3
seconds with the helper and 0.42 seconds without it in
[run 37687026630](https://github.com/MTG-Thomas/rustdesk/actions/runs/37687026630).
Temporary probes were removed; the public trust/publisher test remains in CI.

Remaining launcher gates include embedding the production release trust pins,
owner-only Windows ACLs, isolated RustDesk configuration and IPC, private credential
handoff, session-owned Job Objects, lease renewal, expiry/crash teardown, and
separate consent-preserving elevation. Do not substitute ordinary RustDesk
startup for those gates or advertise this package as customer-ready.

Artifact verification and ticket cryptography use the Go standard library. The
binary WebSocket adapter pins [coder/websocket v1.8.15](https://github.com/coder/websocket/tree/v1.8.15) to avoid
implementing a separate WebSocket framing/handshake stack; it adds no transitive
module dependencies.
The Windows private-pipe component additionally pins Microsoft go-winio v0.6.4
and golang.org/x/sys v0.49.0. Its Windows runtime tests are a separate required
gate; cross-compilation and Linux tests cannot qualify its ACL or peer checks.
Run `go test -race ./...` and `go vet ./...`. A Windows build/runtime check is
separate from the Linux test results. Signing uses the operator's already
purchased Basic account `mtg-sopdet-signing` in East US. The protected October 9,
2026 inventory confirmed `mtg-lab-profile` as active Private Trust. Public identity
validation remains blocked; a Public Trust profile must precede customer distribution.

`Rehearse Quick Support private signing` is a manual, merged-`master` workflow.
It tests the verification package, signs its Windows test executable through a
dedicated profile-scoped OIDC identity, and verifies the exact approved publisher,
RFC3161 timestamp, private code-signing EKU and pinned Microsoft private root.
The root is imported only into the ephemeral runner's CurrentUser store and
removed afterward if this run added it. The seven-day artifact includes a
source/run/attempt-bound hash and signature receipt. It is a signing rehearsal,
not the portable support launcher or a patched-client release.

Infra owns the identity setup in `bifrost-infra`'s protected
`Configure Quick Support private signer` workflow. Before dispatch, the fork's
`private-artifact-signing` environment must allow only the exact `master` branch
and contain nonsecret `AZURE_SIGNING_CLIENT_ID`, `AZURE_TENANT_ID`, and
`LAB_PUBLISHER_SUBJECT` values from the approved identity/profile. The consumer
checks this policy before login. No PR signing, private key export, customer root
installation or public distribution is enabled. The existing public-trust
verification component remains unchanged.

## Cloudflare ticket consumer

The opt-in `internal/transport` package creates an ephemeral RSA-2048 recipient
for one expected session/request UUID. Only its public `kty/n/e` fields leave the
helper. It accepts the Bifrost preparation workflow's bounded, strict encrypted
receipt, validates fixed routes, context label and expiry, then decrypts the
RSA-OAEP-SHA256 ticket in memory. Successful acceptance consumes the private-key
handle so another receipt cannot reuse it. Invalid receipts permit reconciliation
with the same request/key while its original ten-minute window remains open.
Go does not guarantee zeroization of RSA private-key memory after release.

The capability can authorize only GET upgrades to the two exact HTTPS routes.
The native `Lease.Dial` adapter disables redirects and proxy configuration,
verifies TLS normally and never returns raw handshake errors or response bodies.
Callers must never log credential-bearing requests or deliberately inspect
private state.
`Lease.Close` clears the retained binary token, blocks future helper
authorization and signals all sockets opened from that lease to close. It does
not erase previously constructed headers or revoke a server lease. Session end
must still revoke the remote lease. Pointer
formatting and JSON serialization redact private helper state, but callers must
never serialize or log internal credentials deliberately.

The adapter exposes only message-based binary `Read`/`Write` on the two fixed
routes. It preserves empty RustDesk heartbeat messages, disables compression,
limits messages to 4 MiB and bounds the handshake to ten seconds. Parent-context
cancellation, lease expiry or local lease close terminates the socket; closing a
socket does not end the remote lease. It neither prepares/wakes a container nor
starts RustDesk. It cannot authorize a receiving device, record customer consent, renew a receiver grant or enforce
Windows process cleanup. Native RustDesk/launcher wiring, signed client delivery
and receiver acceptance remain required before remote control can be enabled.
Local TLS WebSocket tests verify both routes, exact binary/empty payloads,
post-handshake lifetime, redirect/TLS denial, blocked-read expiry, lease-close
teardown and rejection of text/oversized messages. They use synthetic tickets,
an ephemeral local certificate and a private test transport; the exported API
accepts no transport, URL, TLS or proxy override. Existing artifact verification,
signing and ordinary RustDesk startup are unchanged. Native CI and actual Windows
execution remain required; these Linux tests are not device acceptance.

`Socket.Bridge` consumes an already authenticated private `net.Conn`, translates
RustDesk's compact little-endian BytesCodec framing into WebSocket messages in
both directions, and closes both transports when either fails or the lease ends.
It bounds declared lengths before allocation, handles fragmented reads and short
writes, preserves empty heartbeats, and joins both copying goroutines before
returning. The existing client-only path can wrap a private Windows pipe with
`hbb_common::tcp::FramedStream::from`; no shared submodule or ordinary transport
implementation needs to change for this framing interface.

The bridge creates no pipe, listener, process or authorization policy. The
launcher must authenticate the session-owned child/pipe before calling it and
enforce owner-only Windows ACLs and process cleanup. Receiver grants and local
consent remain separate. This interface supports framed desktop traffic, not
RustDesk's raw port-forward mode; unsupported capabilities must be denied by the
receiver. Neither a random pipe name nor this bridge proves isolation. Linux
`net.Pipe`/TLS tests establish framing and teardown, not Windows pipe security or
actual RustDesk/receiver integration.

`internal/privateipc` creates a local Windows named pipe with a protected DACL
for the current logon SID, rather than the default pipe ACL. The pinned library
creates the pipe with remote-client rejection. The endpoint accepts once and
verifies the client's PID against a duplicated live child-process handle; the
client must use the corresponding `DialParent` check against its trusted live
parent handle before sending application data. Names are random, strictly
validated and never accepted as authentication. Wrong peers consume the endpoint
and fail closed; they are not retried with a broader policy.

The logon ACE grants the pipe rights needed by the library, including instance
creation. Consequently, checking the server PID on the client is mandatory:
the DACL and a random name alone do not prevent another process in the same
logon from attempting to serve another instance. Both expected process handles
must come from trusted launcher/child ownership, never a browser or IPC-supplied
PID. The private transport does not authenticate signed bootstrap claims or
record consent, and `Close` on the endpoint listener does not close a connection
already handed to `Socket.Bridge`.

Windows tests launch only their own test subprocess with a minimal environment.
They cover the protected logon DACL, private round trip, wrong client/server
identity, one-use accept and cancellation. These tests are prepared but have not
run on Windows while the repository's Actions control remains unresolved.
Launcher Job Objects, private configuration, RustDesk hooks and receiver-side
grant/consent enforcement still precede activation.

`internal/contained.StartSuspended` is the process-containment component. Its
unnamed job uses kill-on-last-close with no breakaway permission. The Windows
job-list creation attribute assigns the child during creation, avoiding the
orphan interval between creating a suspended process and later assigning a job.
Unsupported job-list creation fails closed. No handles or caller environment are
inherited; the explicit minimal environment points temporary/profile fields to
the caller's session directory. That environment is not proof that RustDesk's
configuration and ordinary IPC paths have been isolated.

The caller must first verify the release/Authenticode artifact and establish an
owner-only directory; this component does neither. It requires a context with a
hard deadline no more than 24 hours away, returns a suspended child and exposes
only duplicated query/synchronization handles for private-pipe authentication.
`Resume` is explicit and one-use. Context cancellation/expiry or `Close` closes
the job and waits boundedly for the direct child. Arguments must contain no
credentials, and bootstrap/consent still belongs on authenticated private IPC.

Prepared Windows tests query job membership before resume and check direct-child
and descendant exit on close/expiry, with a synthetic environment-leak marker.
Those tests have only been cross-compiled, not executed. Actual Windows process
tree/crash cleanup, artifact-to-launch ownership, private configuration and the
complete consent-preserving native path remain gates before activation. The
component follows [Microsoft's atomic job-assignment guidance](https://devblogs.microsoft.com/oldnewthing/20230209-00/?p=107812).

`internal/sessiondir.New` provides the directory precondition for artifact fetch
and contained launch. It uses the OS LocalAppData location, creates a fresh
directory relative to a retained parent handle, and sets its protected,
inheritable current-user DACL during that same creation call. Existing names are
never adopted. The returned directory handle denies delete sharing, so the owned
root cannot be renamed while in use. `FilePath` accepts only a local basename.
This creates storage; it does not direct RustDesk's configuration or IPC there.

After the owned process tree has stopped, `Cleanup` removes children using a
root-scoped view and deletes the empty root by its retained handle. It never
recursively deletes an absolute path. Content-removal failure retains the locked
directory for a deliberate retry and prevents new path use. Handle-release errors
remain errors on later calls. Cleanup is explicit: a launcher crash can leave
private files behind, so crash recovery/receipt reconciliation remains a gate.
An initialization failure before any artifact is written may also retain an
empty directory if the OS rejects its handle-based removal; it is never adopted
or recursively removed by guessing its name.

The module and both helper CI/signing toolchains require Go 1.26.10. Earlier
Go 1.26 releases before 1.26.9 have the Windows root-operation vulnerability
[GO-2026-6604](https://pkg.go.dev/vuln/GO-2026-6604). The source toolchain change
does not enable Actions or change its permissions. Prepared Windows tests cover
inherited file ACLs, rename denial, filename rejection, busy-file retry and an
outside junction sentinel. Cross-compilation and audit do not replace executing
these tests or proving the complete Windows launcher/receiver lifecycle.

A composed Windows fixture now launches its own test executable in the private
directory, authenticates both ends of the pipe against retained process handles,
exchanges a synthetic ping, stops the contained child and cleans the directory.
It specifically checks that the retained directory handles permit using that
directory as the child's working directory. This fixture is cross-compiled only;
Windows execution, RustDesk startup, signing and receiver consent remain unproven.

An optional, local cross-repository check executes the reviewed authority's actual
TypeScript encryption function under a Node runtime with type stripping, then
passes its ciphertext directly to the Go consumer. It uses a synthetic ticket;
only the public recipient enters Node, and the child receives no caller credentials:

```sh
BIFROST_QS_AUTHORITY_SOURCE=/absolute/path/to/services/quick-support-authority/src/ticket-envelope.ts \
  go test -race -tags quick_support_interop -run TestAuthorityWebCryptoEnvelope ./internal/transport
```

Normal `go test` does not require Node or the authority checkout. This interoperability
check is cryptographic wire-contract proof, not a live Cloudflare or Windows test.
