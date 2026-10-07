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
- Initialize with `Receiver::from_bootstrap`; `Receiver::new` is a low-level API
  for already authenticated settings and the test fixture.
- Generate each connection's challenge using the OS CSPRNG. Length validation
  alone cannot prove that a challenge is random or unique.
- Hold a single receiver state across connections to enforce one-use grants.
  Serialize access without holding a mutex over network awaits.
- Validate before any password, trusted-session, side-switch, terminal, camera,
  tunneling or other alternate authorization path. Restrict capabilities before
  dispatch. Default to desktop only until explicit policy is qualified.
- Invoke `approve_locally` only from the isolated receiving-side customer
  approval event. Prevent existing installed RustDesk IPC from reaching it.
- Check `can_control` before accepting privileged packets and on a bounded
  periodic timer; close active connections when the lease expires. Launcher
  termination alone is insufficient.
- Authenticate renewed leases and trusted telemetry; do not accept browser
  assertions as proof of customer approval, elevation or cleanup.
- Reject startup when signed configuration or isolated IPC is unavailable.
  Do not silently fall back to ordinary RustDesk behavior.

The separate crate uses Rust 1.90 and its own checked-in lockfile for this
spike. It does not change the ordinary RustDesk package's Rust 1.75 declaration.
A feature build's compiler and complete dependency audit must be qualified
before integrating it into the application release.

## Verification

From this directory, use Rust 1.90:

```sh
cargo fmt --all --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo audit --file Cargo.lock
```

Current focused checks prove the public verifier and admission-state behavior.
They do not establish Authenticode trust, customer UI, Windows isolation,
elevation, launcher cleanup or live transport interoperability. No existing
RustDesk source file or runtime path has been changed in this first component.
