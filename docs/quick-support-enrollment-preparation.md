# Enrollment HTTP and key-host preparation

This source-only slice builds on main `0e024f908dc1bb9333c721aca0c493528c117b86`.
It enables no startup route, HTTP request, key creation, credential use or control.

`EnrollmentAttempt` builds the documented synchronous Provider workflow request
for `POST /api/workflows/execute`. The installation supplies the pinned workflow
and organization UUIDs. The captured request UUID and authenticated-session
context remain local; only the public key and request UUID enter workflow inputs.
A completion consumes the attempt and requires the same request/session context,
technician and SHA-256 fingerprint of the public-key text. Running/error execution
envelopes cannot masquerade as the inner enrollment result. The HTTP executor
must authenticate and qualify the terminal execution before passing that result;
this adapter does not authenticate a response by itself.

`ProtectedKeyStore` specifies the OS boundary rather than pretending a path is
protected. Ordinary load refuses absence and propagates corruption/access errors.
Explicit initialization preserves an existing identity, invokes an injected
initializer only after genuine absence, and returns new material only after an
atomic create-new succeeds. Failure never triggers automatic replacement, retry,
enrollment or rotation. No production filesystem implementation or CSPRNG call
is connected. Tests load fixed synthetic seeds only.

Remaining engineering prerequisites:

- Qualify the actual upstream-compatible synchronous HTTP execution envelope,
  completion/failure states and authenticated response correlation. Bind pending
  attempts to the existing authenticated Provider session and cancel them when it
  changes. Do not forward Provider HMAC credentials to native clients, follow
  redirects with authorization or retry uncertain POSTs under a new request ID.
- Implement and qualify the Windows owner-only key host using retained handles,
  non-reparse paths and protected owner ACLs throughout read/create operations.
  Access denial or malformed stored bytes must remain errors, not absence. Avoid
  a path-check/open race or broad inherited ACLs. An uncertain create requires
  reconciliation with the existing identity, never overwriting it.
- Wire explicit setup/UI and authenticated enrollment only after those boundaries
  are implemented and reviewed. Key rotation must invalidate previous bindings;
  end affected sessions and re-invite. Do not invent an independent receiver
  generation or clear the authority's `receiver-generation` records.

All fixtures are offline and establish source behavior only. Native Windows
filesystem, HTTP integration, launcher startup, customer consent, device and
end-to-end acceptance remain separate. PR50's tested merge candidate
`1e7aa9b9addd1ba2b496a0ffeff705a55bd54af8` is distinct from its landed merge above.
The retained cached audit still fails with 13 vulnerability entries and 29
warnings; this work changes no dependency or release gate.
