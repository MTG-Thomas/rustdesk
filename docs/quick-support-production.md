# Quick Support production acceptance

Target: an attended support product for MTG staff and, after a supervised pilot,
T&M customers. It must work through the upstream-compatible Bifrost Provider
install and the existing Cloudflare Worker/Durable Object/on-demand Container.
Preserve ACA, existing resources/keys, ordinary RustDesk and unrelated work.

This is a release contract, not a statement that production acceptance is complete.
Every acceptance receipt must identify source SHA, artifact digest, configuration,
environment, test actors, result and cleanup. Do not equate merge, compilation,
synthetic Windows execution, deployment and device acceptance.

## Evidence at client master 445f7127

| Boundary | Proven | Still required |
| --- | --- | --- |
| Receiver verifier | Worker-generated synthetic vectors; issuer/session/install/generation/workstation binding; replay, expiry and terminal revocation tests | Real pinned issuer and authenticated expected launch identity |
| Windows launcher | Signed-download verification, pinned private directory, restricted inherited handle, suspended/atomic Job Object containment and cleanup fixtures | Releasable application composition and signed receiver artifact |
| Native interoperability | PR34/35 Windows Go/Rust private pipes, workstation proof, separate synthetic consent, renewal/revocation, process/directory teardown | Actual application login, real consent UI and two-device acceptance |
| Receiver I/O | Real Windows pending-read cancellation and stalled partial-frame expiry | Independent control-priority scheduling throughout the application lifecycle |
| Desktop startup | Private invocation refuses ordinary startup | Authenticated, isolated application entry; no fallback |
| Cloudflare/Provider runtime | Historical transport/deployment receipts exist separately | Current readback, qualified issuer deployment and final integrated acceptance |

PR35 Windows job 125685375140 exercised the required interoperability fixture
and both cancellation/expiry tests. The synthetic parent/config oracle and
consent implementation do not establish production trust or customer approval.

The full client `Cargo.lock` also needs remediation: an offline baseline against
RustSec database commit `263a4d951a0867d4bddc29dddd6d59427c78f9a7` (November 2)
reports 29 vulnerability entries and 46 warning entries. A preliminary
Windows-target tree with `--no-default-features --features quick-support-child`
contains 16 of those vulnerability entries and 30 warnings. This tree includes
host/build dependencies; it is not proof that every finding is device-exploitable
or that it matches the final signed release's feature set. Map the exact release
producer/target/features, remediate affected chains and refresh the database
before release. The clean guard/server audits do not qualify this client graph.

## Application integration sequence

1. **Authenticate and isolate before initialization.** Validate the release and
   retained parent, independently signed launch configuration and expected
   install/session/generation/receiver. Pin the private directory; fix the
   configuration, home, log and IPC roots before any ordinary settings are read.
   Reject late initialization and never load cached passwords/trusted sessions
   or reuse an installed RustDesk connection-manager channel.
2. **Run a real native connection.** Keep identity/key-exchange and BytesCodec
   processing in the existing native stream. Bind the workstation proof and
   grant to exactly one child connection and challenge. Authenticated control
   remains on its separate channel. Neither a pipe connection nor a native
   password/trusted-device/recent-session path can grant Quick Support authority.
3. **Obtain actual receiver consent.** Present authenticated technician/support
   identity, organization, requested capabilities and session lifetime. Use an
   isolated receiver-local callback bound to that connection. Denial, window
   dismissal, customer stop and delayed callbacks must remain terminal. Display
   a persistent session indicator and an accessible stop action while active.
4. **Enforce admission on the application path.** Classify decrypted native
   messages before privileged handlers. Process control/revocation and expiry
   independently of blocked reads, a pending UI prompt and a slow peer. An
   approved transport does not authorize a different login mode or capability.
5. **End and prove cleanup.** Latch revocation first, discard buffered input,
   close controls and both native routes, stop the child/Job Object and remove
   private state. Verify the runtime's idle-stop behavior and key continuity.
   Cleanup failure is visible and cannot be reported as success or resumed.

Source integration findings:

- `src/core_main.rs` currently returns before global initialization for the
  private invocation. Keep that refusal until the authenticated host is complete.
- `hbb_common::FramedStream::from` already accepts a generic asynchronous
  read/write transport. A new loopback TCP listener or replacement of the shared
  stream abstraction is not necessary merely to attach a private pipe.
- Inspect/decrypt in the native connection before capability classification.
  Ciphertext at the outer pipe is not a protobuf message to classify.
- `Connection::on_message`, `ipc::Data::Authorize` and
  `send_logon_response_and_keep_alive` are separate authorization paths. The
  Quick Support admission must cover all of them, including cached/recent and
  alternate login paths. Generic installed IPC is not an isolated consent source.
- `Config::path` uses `directories_next::ProjectDirs`, whose Windows
  implementation uses Known Folder APIs. The launcher's `APPDATA` environment
  override alone does not isolate it. Address this before connecting startup.

## Pilot capability policy

The first pilot is attended desktop viewing/control for identified internal
technicians and identified internal Windows machines. Clipboard, file transfer,
camera, microphone/voice, terminal, tunneling, elevation, remote restart, privacy
mode/blocking local input, unattended installation and persistent access remain
unavailable until separately scoped and qualified. Reject attempts to select
those modes, including mixed login options and post-login messages.

Do not silently expand capabilities on reconnect. New connections need fresh
proof and consent. The customer can always stop. No session/screen recording or
automatic billing is implied by this release.

## Release and operational gates

- **Identity and provenance:** reviewed source, successful applicable checks,
  dependency/security coverage, reproducible producer receipts and exact signed
  artifact digests. Use the approved publisher/trust lane. Synthetic keys and
  fixture signatures cannot enter application trust. Rotation must preserve
  revocation and a recoverable rollback; no trust-store/security bypass.
- **Provider/tenant boundary:** assigned technician role and workstation proof
  verified by authority; cross-install, cross-customer, wrong-session and stale
  generation requests denied at issuer, transport and receiver. Customer links
  grant no administrative role or persistent credential.
- **Audit and support operations:** correlate organization/install/session,
  generation, receiver, technician and workstation with consent, control start,
  rejection, stop/revoke/expiry and cleanup outcomes. Keep tokens, keys, screen
  contents and keystrokes out of logs. Set access/retention before customer use.
  T&M duration may use authenticated start/end evidence; it is not consent or
  an automatic charge. Document failure handling and escalation.
- **Cost/resource bounds:** use existing Workers Paid; no new subscription or
  fixed capacity. Verify current instance/concurrency, session/time, byte/frame
  and idle bounds; reject admission beyond them. Prove overlapping leases do not
  stop an active session, and the last release/expiry stops idle compute. Billing
  read denial remains an uncertainty, never a zero-cost guarantee. No silent
  resource expansion when a limit is reached.
- **Rollback:** close admission and revoke active generations before rollback;
  ensure old signed clients cannot resurrect retired sessions. Keep the previous
  known-good artifact/configuration and verify disabled-state readback. Preserve
  ACA and unrelated infrastructure throughout.

## Acceptance before rollout

| Stage | Required proof | Exit condition |
| --- | --- | --- |
| Application source | Actual startup/stream/login/consent/capability hooks; synthetic malformed/replay/cross-scope/expiry/cleanup regressions; feature-off behavior | Normal reviewed CI on the exact composed head |
| Signed release rehearsal | Publisher/trust verification, artifact digest and producer/source binding; tampered/mismatched artifact denial | Reviewed release receipt; no fabricated signatures |
| Internal two-device session | Real technician authentication and visible customer approval; actual desktop control; rejection/stop/expiry/revocation; disconnect, clock rollback, restart and cleanup | Both operators confirm behavior, exact device/artifact receipts and cleanup |
| Team pilot | Supervised normal use and outage exercises, capacity/idle metering observations, usable consent/stop UX, audit and rollback runbook | Recorded operational review and no unresolved acceptance failures |
| T&M customer rollout | Customer/privacy/retention/support policy, tenant isolation and customer-facing instructions, bounded staged enablement | All acceptance evidence complete; staged enablement within the owner's authorized scope |

The real-device stage requires exact internal devices/accounts to be named and
available. Existing signing workflow approvals, human-only identity verification
and actual customer consent cannot be synthesized. Prepare source, tests and
release evidence while those steps are unavailable; do not replace them with
synthetic acceptance or bypass normal approval/security controls.

### Native login protocol plumbing (source only)

The optional desktop client now has in-memory workstation login material and a
separate `LoginRequest.quick_support_auth` field (18) for the grant and
challenge-bound workstation signature. The supplied signer creates no keys here.
The adapter refuses alternate-service requests, wrong receivers, short legacy
challenges and signer failures; it clears password, device trust, OS login and
legacy option fields instead of sending two authorization paths.

Ordinary native connections explicitly close any login containing this field
before password authorization. A separate source-only native host factory now
verifies retained parent/configuration and the initial signed control envelope,
binds its receiver to the internally allocated connection ID, and routes native
login through grant verification and receiver-local consent. It uses a dedicated
parent control reader, expiry checks, capability-filtered service output and a
final authorization check at the queued input sink. Consent holds no guard lock,
so parent revocation can cancel the modal dialog. Teardown cancels and joins the
parent reader. Private startup remains refused; no route invokes this factory.
This is not a working production control session or device acceptance.

Local proof: two synthetic workstation tests; the existing verifier/control/
profile/startup suite; and the native adapter test compiled against newly
generated message types. Existing desktop CI additionally runs the adapter test
with the opt-in feature. Full application build results and Windows runtime
results must be recorded separately. The next integration is the concrete Windows overlapped native-pipe conversion,
independently authenticated signed startup/profile configuration, fresh receiver
challenge production, and an always-visible receiver-local Stop surface. The
native host API must consume exactly the verified pipe handles, use the same
monotonic cancellation flag and bounded parent reader, and run only after private
profile installation. No default trust, credentials or production keys are added.

Regression surface: the client gains an optional in-memory field and opt-in
login hook; ordinary clients keep the existing message construction. The
protobuf adds an unused optional field. The server's only feature-off
behavior change is refusing that field, preventing unsupported authorization
fallback. Feature-on hooks attach only a registered private connection: ordinary
connections retain the old authentication and input paths. The private factory
uses explicit two-bit capability denial (all slots except keyboard/input), a
4 MiB authorized frame bound and no installed Connection Manager IPC. Safe video
decoder/quality/cursor options remain available; privacy, input blocking, file,
clipboard, audio and terminal capabilities are refused. No shared function
signatures, infrastructure permissions, signing material or startup policy change.

Additional local receiver proof uses the existing signed synthetic issuer fixture
and a deterministic workstation proof from its existing test identity. It covers
exact connection-ID binding, proof removal before native retention, required
consent, revocation during the prompt, replay, expiry, malformed/oversized/truncated
control, EOF, queued-input denial after revoke, desktop capability bits and safe
video options. The four native login/receiver tests compile against the generated
protocol and pass. This isolated source test does not execute the whole desktop,
real OS input, Windows visual consent or real device sessions. Full desktop
build/runtime CI remains required. A heavy local desktop build was deferred
because other owners' Docker test stacks were active on the shared host.
