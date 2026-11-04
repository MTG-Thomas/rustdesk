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
