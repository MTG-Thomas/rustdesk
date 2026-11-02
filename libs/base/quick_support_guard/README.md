# Quick Support authorization primitive

This independently tested crate belongs to the client-only `libs/base` tree.
It is the first acceptance-spike component, **not an enabled RustDesk transport
hook, Windows launcher, or production-ready support client**.

The issuer signs strict Ed25519 JWS bootstrap, grant and lease payloads. The
controller additionally signs a length-framed grant, fresh receiver challenge,
and receiver ID with the assigned workstation key. Receiver authorization binds
the session, endpoint generation, technician, workstation and receiver, consumes
a 256-bit grant nonce once, and requires a signed lease. `Admission` separately
requires a local approval callback before control; successful cryptographic
verification does not imply customer consent.

Lease and hard expiry use monotonic deadlines. An anchored, nondecreasing wall-
time floor prevents clock rollback from accepting stale grants or extending a
lease. Lease sequences must increase, and the nonce set is bounded at 128
connections per receiver generation without evicting consumed nonces. Exhaustion
fails closed; reissuing a generation is a control-plane action.

## Integration requirements

- Pin the expected issuer URL and public key in the signed application. Never
  accept a key or issuer supplied by the customer link or local manifest.
- Initialize with `Receiver::from_bound_bootstrap`, supplying the independently
  authenticated expected session, receiver and generation. Never copy that binding
  from the token being checked. `from_bootstrap` and `new` remain low-level APIs.
  This binding is not a persistent generation replay registry or an issuer source.
- Generate each connection's challenge using the OS CSPRNG. Length validation
  alone cannot prove that a challenge is random or unique.
- Hold a single receiver state across connections to enforce one-use grants.
  Serialize access without holding a mutex over network awaits.
- Validate before any password, trusted-session, side-switch, terminal, camera,
  tunneling or other alternate authorization path. Restrict capabilities before
  dispatch. Default to desktop only until explicit policy is qualified.
- Invoke `approve_locally` only from the isolated receiving-side customer
  approval event. Prevent existing installed RustDesk IPC from reaching it.
- Call `Admission::close` before handling local rejection, customer stop or
  disconnection. It permanently closes that connection's admission, including
  after prior approval; delayed approval events and fresh grants cannot reopen
  it. Use a new admission and fresh challenge for a new connection. This latch
  does not itself close the transport or authenticate the local event.
- Check `can_control` before accepting privileged packets and on a bounded
  periodic timer; close active connections when the lease expires. Launcher
  termination alone is insufficient.
- On authenticated session end or local customer stop, call `Receiver::revoke`
  before closing transports. Revocation is terminal for that receiver generation:
  neither a fresh signed lease nor a delayed local approval can reactivate it.
  This local latch does not fetch revocations, close sockets, stop processes or
  authenticate the event; those integration hooks still require acceptance.
- Authenticate renewed leases and trusted telemetry; do not accept browser
  assertions as proof of customer approval, elevation or cleanup.
- Reject startup when signed configuration or isolated IPC is unavailable.
  Do not silently fall back to ordinary RustDesk behavior.

The separate crate now shares the desktop Rust 1.75 minimum. Its checked-in
lockfile selects Ed25519 Dalek 2.1.1 (MSRV 1.60), UUID 1.18.1 (MSRV 1.63),
zeroize 1.8.2 and base64ct 1.6.0 (MSRV 1.60). The former selected Dalek 2.2.0
required Rust 1.81; UUID 1.27.0 required 1.89; zeroize 1.9.1 and base64ct
1.8.3 required 1.85/edition 2024. No verifier or admission logic changes.
CI runs the locked authorization/control tests with Rust 1.75 and retains
Rust 1.90 for formatting, diagnostics and audit. A complete desktop dependency
graph/build still needs separate qualification when the guard is linked; this
standalone check is not application or Windows runtime acceptance.

## Verification

From this directory, use Rust 1.90:

```sh
cargo fmt --all --check
cargo +1.75.0 test --locked
cargo +1.90.0 test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo audit --file Cargo.lock
```

Current focused checks prove the public verifier and admission-state behavior.
They do not establish Authenticode trust, customer UI, Windows isolation,
elevation, launcher cleanup or live transport interoperability. No existing
RustDesk source file or runtime path has been changed in this first component.

## Source-only Worker control contract

`ControlSession` verifies the separate `rd-qs-control+jwt` envelope before
accepting its nested bootstrap or lease. Its constructor requires independently
trusted issuer/key and organization, install, session, generation and receiver
identity; none may come from the token under validation. Exact consecutive
sequences, short validity, matching nested claims and monotonic lease expiry
reject replay and reactivation. Local stop and authenticated revocation are
terminal. Grants still require workstation proof and receiver-local approval.

The JSON fixture in `tests/fixtures/receiver-control-v1.json` is emitted by the
actual workspace Worker issuer test, `exports synthetic Worker envelopes for
the native verifier contract`, in `bifrost-workspace-next`. Its seed-7 issuer,
seed-9 workstation and expired timestamps are public synthetic test material.
Keep the two repositories' fixture bytes identical; regenerate with the Worker
test before copying, rather than generating an independent Rust approximation.

This API has no application startup hook. It does not authenticate a pipe peer,
deliver a control channel, close transports or persist generation replay state
across process restart. A future caller must obtain launch identity from trusted
bootstrap, preserve the issuer's generation authority, authenticate the private
pipe peer before accepting control and gate every privileged frame on admission.
Neither a control token nor an authenticated transport implies customer consent.
No issuer key provisioning, runtime activation or device acceptance is included.

Regression surface: the existing `src/lib.rs` only adds module exports; existing
verifier/admission paths and ordinary RustDesk startup remain unchanged.

## Child connection dispatch contract

`ChildConnection` composes the control verifier and one admission into a private
connection boundary. Parent controls, workstation requests and receiver-local
approval have separate methods; peer frame bytes are never decoded as control
or UI events. Dispatch receives exactly one complete, nonempty RustDesk
BytesCodec frame with a 4 MiB payload limit. It invokes its callback only after
an active lease, verified workstation grant and local approval. The caller must
classify allowed packet capabilities before its actual privileged handler.

Control failure, grant failure, malformed/premature/expired privileged traffic,
dispatch failure, explicit rejection/stop and disconnect must close the latch.
`stop` is terminal; the owner must then close both native streams, cancel the
transport lease, terminate the contained child and finish bounded cleanup. The
Rust latch cannot by itself perform that Go/Windows teardown. No buffered packet
may be retried on a replacement connection or delivered after a consent prompt.

### Remaining integration prerequisites

| Boundary | Existing evidence | Missing before application wiring/activation |
| --- | --- | --- |
| Issuer trust and launch identity | Worker source issuer and Rust signed vectors | Signed application-pinned public trust and independently authenticated org/install/session/generation/receiver configuration; no production issuer key is provisioned |
| Parent and child process | Go privateipc pins retained process handles and checks both peers; Windows fixtures | Rust child adapter must receive trusted retained parent identity, verify its pipe server before any payload, and bind to the launcher's created child; command-line PID or pipe name alone is insufficient |
| Control delivery | Typed signed control verification with exact sequence and terminal revocation | Separate authenticated control channel; current two Go pipes carry opaque native peer traffic and must never supply bootstrap authority |
| Consent | Executable guard/dispatcher tests require a distinct receiver-local approval event | Isolated real customer UI event binding and denial/stop callbacks; transport connection or issuer grant cannot stand in for consent |
| Native application | Complete-frame gate tested with synthetic callbacks | RustDesk startup adapter, login and capability dispatch hooks, bounded expiry timer, both-route EOF and process teardown wiring; no legacy fallback |
| Generation restart | Durable issuer generation/tombstone source contract | Trusted launch/restart reconciliation before reusing a process or generation; no receiver persistent authority created here |
| Acceptance and rollback | Existing helper Windows CI and source-level tests | New-head CI, reviewed integration, signed release, then separately authorized isolated device acceptance; activation remains disabled and rejection must roll back to no running child/transport |

No RustDesk startup, UI, shared submodule or legacy runtime path is modified by
this dispatcher. The only existing production file change adds module exports.
Synthetic callbacks prove dispatch suppression, not actual Windows execution,
UI authenticity, device acceptance or an authorized real remote-control session.
