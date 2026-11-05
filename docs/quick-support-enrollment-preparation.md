# Enrollment HTTP and key-host preparation

This source-only slice builds on main `0e024f908dc1bb9333c721aca0c493528c117b86`.
It enables no startup route, HTTP request, key creation, credential use or control.

`EnrollmentAttempt` builds the documented synchronous Provider workflow request
for `POST /api/workflows/execute`. The installation supplies the pinned workflow
UUID. The authenticated session selects the organization; the request sends no
admin-only `org_id` override or impersonation. The captured request UUID and
session/org context remain local; only the public key and request UUID enter
workflow inputs.
A completion consumes the attempt and requires the same request/session context,
technician and SHA-256 fingerprint of the public-key text. Running/error execution
envelopes cannot masquerade as the inner enrollment result. `ProviderEnrollmentHttp` uses only a configured HTTPS origin, refuses userinfo,
paths/query/fragments, disables redirects/proxies, marks its bearer header
sensitive, and bounds the entire request to 25 seconds and response to 8192 bytes.
It rechecks the supplied live session/org context before sending and after reading
the response. No existing Provider session is yet connected to this source helper.
The envelope parser requires `Success`, an exact workflow UUID, a valid execution
UUID, no error fields and a matching inner result. Platform source inspected at
`f5b2b2c009bc6b2b9ab81c0511c813b7e8049a60` supplies that schema; this is not
confirmation of the deployed upstream-compatible instance.

`ProtectedKeyStore` specifies the OS boundary rather than pretending a path is
protected. Ordinary load refuses absence and propagates corruption/access errors.
Explicit initialization preserves an existing identity, invokes an injected
initializer only after genuine absence, and returns new material only after an
atomic create-new succeeds. The transient seed is wiped on successful or failed
persistence. Failure never triggers automatic replacement, retry, enrollment or
rotation. No CSPRNG call is connected. Tests use fixed synthetic seeds only.

`ProviderEnrollmentHttp::enroll_existing` is the source setup coordinator: it
loads the existing protected identity, captures the retained request and current
technician/session context, awaits the bounded HTTP helper while retaining the
store borrow, then constructs the existing native signer only after the receipt
matches. Missing/denied storage cannot invoke initialization or HTTP. Explicit
initialization remains a separate operation. The UI host must retain the request
ID before submission and reconcile uncertainty; the coordinator does not invent
or replace IDs on error.

The Windows `WorkstationStore` source implements that boundary using an already
protected owner-only inheritable directory. It retains non-reparse ancestor and
directory handles without delete sharing, validates key ownership/ACL/hard-link
count, and retains the key handle without write/delete sharing. Create-new opens
and verifies the private file with the explicit qualified owner/ACL before writing
bytes and calling sync_all; uncertain
writes remain for reconciliation. Loading never follows a replaced path or
regenerates corrupt data. The native fixture covers missing/broad storage,
round-trip/reopen, overwrite/write/rename refusal and truncation. It executes on
`windows-2022` through the guard `control` harness at tested head `54b726790`
(merge `94827140251bc82bf9fb0f8905f6b42d72323f0c`, run 41891294791 / job
126789085776): the fixture reports one pass, and the CI step fails when the
filter matches no test. This is isolated native fixture evidence, not full
application execution, launcher or startup qualification, or two-device pilot
acceptance.

Remaining engineering prerequisites:

- Verify deployed compatibility with the source-qualified synchronous HTTP
  execution envelope and authenticated response correlation. Bind pending
  attempts to the existing authenticated Provider session and cancel them when it
  changes. Do not forward Provider HMAC credentials to native clients, follow
  redirects with authorization or retry uncertain POSTs under a new request ID.
- Qualify the remaining Windows application host and the existing
  protected-directory setup UI. The isolated store fixture now executes, but
  access denial or malformed stored bytes must remain errors, not absence. An
  uncertain create requires reconciliation with the existing identity, never
  overwriting it.
- Wire explicit setup/UI and authenticated enrollment only after those boundaries
  are implemented and reviewed. Key rotation must invalidate previous bindings;
  end affected sessions and re-invite. Do not invent an independent receiver
  generation or clear the authority's `receiver-generation` records.

All fixtures are offline and establish source behavior only. The isolated
Windows store fixture now executes natively; full application filesystem and
startup integration, HTTP integration, launcher startup, customer consent,
device and end-to-end acceptance remain separate. PR50's tested merge candidate
`1e7aa9b9addd1ba2b496a0ffeff705a55bd54af8` is distinct from its landed merge above.
The retained cached audit still fails with 13 vulnerability entries and 29
warnings; this work changes no dependency or release gate.

The remaining authenticated-host boundary is concrete: the desktop needs a
trusted handoff of the Provider origin/workflow configuration, authenticated
technician identity, existing Provider bearer and a live session/org-context
reader. There is no such registered native handoff in the inspected source.
RustDesk account tokens and Provider HMAC secrets are not substitutes. Do not
connect this API to private startup with synthetic callbacks or infer eligibility
from a populated session struct. UI integration must also clear earlier pending
signers on logout/context change and preserve receiver-local consent separately.

An enrollment receipt is client-local evidence for one setup attempt, not
authority. Any issuer or transport path must read the active registration
server-side, including status/revocation and the exact organization, technician
and key row, and must never accept a client receipt as proof. The registration
record is keyed by organization and technician; the pilot install is treated as
single-organization, so a future multi-organization use must add that scope to
the receipt. The authority's internal issuer UUID and the receiver's HTTPS issuer
identity are distinct: define one explicit mapping and pinned Ed25519 key before
wiring, and never relax the guard's HTTPS issuer check. Until rotation exists, a
replacement key needs a new request id.

`ProviderHost` is the source-only desktop sign-in boundary. It pins the HTTPS
Provider origin and workflow UUID from release configuration, runs the platform's
existing native loopback PKCE contract (`/auth/cli/start`, localhost callback,
`/auth/cli/token`, then `/auth/me`), keeps the bearer in memory only, and exposes
an opaque per-login context that changes on every login. `Debug` never prints the
bearer. The loopback login is blocking and must run on a worker thread, not the
UI or async runtime thread. There is no token persistence or refresh yet, so an
expired session requires a new login. The setup UI, startup route and platform
confirmation that the CLI OAuth contract is the desktop contract remain
unwired; the module is retained as source-only until that reviewed slice.
Tests cover origin/workflow pinning, the PKCE challenge vector, callback
state/parameter validation, authorization-URL origin confinement, bearer
redaction and bounded token/user fields. No live OAuth, browser, Provider
credential or deployment was exercised.

## Decisions and remaining programs (2026-11-05)

- **Desktop sign-in contract:** the desktop may use the platform's existing
  native loopback PKCE contract (`/auth/cli/start`, localhost callback,
  `/auth/cli/token`, `/auth/me`) for the pilot. This introduces no separate
  native client registration; the authorization page stays platform-hosted.
  Revisit if the platform adds client identity or an allowlist.
- **Session policy:** the bearer is in memory only. The pilot has no token
  persistence and no refresh; expiry requires a new login. Protected storage and
  refresh are a later decision, not an assumed capability.
- **Issuer identity:** the session/transport authority keeps its UUID internally.
  The receiver-facing `iss` must be one explicitly pinned HTTPS URL plus a pinned
  Ed25519 public key. Do not pass the bare authority UUID as `iss`, and do not
  relax the guard's HTTPS requirement to accommodate it.
- **Registration lifecycle:** receipts require an active, non-revoked row.
  Revocation and rotation remain a separate workflow; until it exists, a
  replacement key needs a new request id.

Remaining programs, in dependency order:

1. **Setup UI and startup wiring.** Expose the sign-in/enrollment host through
   the application UI and an isolated authenticated startup path. Not started;
   this is the next source slice.
2. **Issuer, bootstrap and grant.** No reviewed issuer exists in the inspected
   authority bundle, and the production signing key requires owner custody and a
   deployment. The authority UUID to HTTPS issuer mapping above is the
   prerequisite.
3. **Dependency audit.** Open PR #52 lowers the retained cached audit from 13 to
   11 vulnerability entries and leaves 29 warnings. Its one failing check is the
   i686 Sciter lane: the updated lock requires newer Rust/edition support than
   that lane's pinned compiler (high confidence from MSRV metadata; the failing
   log was not re-read). Either re-tool/retire that lane or waive the two
   advisories; neither clears the remaining 11/29. This is an owner tradeoff and
   is not claimed as a cleared gate.
4. **Device acceptance.** The Windows technician host LT002-H8WL8H4 is
   unreachable, and no two-device consent/control/cleanup run has been recorded.
   Named devices and accounts remain owner-supplied.

## Setup surface and private launch gate (source-only, 2026-11-05)

- `quick_support_setup` exposes `status`, `sign_in`, `sign_out` and `enroll` as
  JSON strings for the Flutter FFI (`quick_support_setup_status`,
  `quick_support_setup_sign_in`, `quick_support_setup_sign_out`,
  `quick_support_setup_enroll`). The contract is fail-closed: without an
  installed release configuration it reports `unavailable`; with configuration
  but no wired sign-in worker it stays `signed_out`; enrollment refuses and never
  fabricates a fingerprint. The bearer is never serialized.
- The Flutter page and route are not added in this slice because the local
  environment has no Flutter/Dart toolchain or FRB codegen. The FFI functions are
  the reviewable UI seam; a settings page can call them without new privilege.
- A private invocation now routes through
  `quick_support_startup::private_launch()`, which always refuses until signed
  release configuration, parent verification and the issuer exist. Ordinary
  startup paths are unchanged; there is no fallback from private to ordinary.
- Offline proof: the source harness compiles the setup contract with the host and
  enrollment modules; 26 tests pass (5 setup-specific), clippy `-D warnings`
  clean. No OAuth flow, network call, credential, deployment or device was
  exercised.

### Setup page and FFI adapter (source-only, 2026-11-05)

- `flutter/lib/common/quick_support_setup.dart` parses the four FFI status
  strings into a fail-closed UI model: only documented states are accepted,
  identity appears only for `signed_in`/`enrolled`, and a fingerprint only for
  `enrolled`. Malformed or unknown input degrades to `unavailable`; it never
  fabricates identity, a fingerprint or approval. `newQuickSupportRequestId`
  produces the request id the page retains across an uncertain enrollment call.
- `flutter/lib/desktop/pages/quick_support_setup_page.dart` shows status and
  sign-in/sign-out/enroll actions. Buttons are disabled unless the reported state
  allows them. In this build sign-in reports that the worker is not wired and
  enrollment refuses, so no success state is reachable.
- The About settings tab links to the page. No route or startup behavior beyond
  that link changes.
- Generated FRB bindings are **not** hand-edited. After the pinned generator is
  available, regenerate with:
  `flutter_rust_bridge_codegen --rust-input ./src/flutter_ffi.rs --dart-output ./flutter/lib/generated_bridge.dart --c-output ./flutter/macos/Runner/bridge_generated.h --llvm-path /usr/lib/llvm-19`
  (ffigen needs the LLVM directory containing `libclang.so`), copy the header to
  `flutter/ios/Runner/bridge_generated.h`, then run `flutter pub get`, `flutter analyze` and
  `flutter test test/quick_support_setup_test.dart`.
- The Flutter/Dart toolchain is absent here, so the page, route and adapter test
  are source-reviewed only. The offline Rust harness covers the setup contract;
  Dart analysis, codegen and widget build remain verification gaps.
