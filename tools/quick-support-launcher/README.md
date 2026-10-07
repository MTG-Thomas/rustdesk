# Portable Quick Support launcher components

This is the unmanaged-Windows launcher under construction, not a distributable
launcher executable. Its artifact download component never executes a client.
The signed release manifest must authenticate the URL, exact origin, byte count,
SHA-256 and publisher certificate before a download is requested. Redirects,
plaintext HTTP, embedded credentials and a missing Authenticode verifier fail
closed. Files are created exclusively in a caller-owned private directory.
Failed downloads are removed; pre-existing files are never overwritten.

Windows signature verification invokes protected system PowerShell with a
constant, noninteractive script and an explicit system security module. It
requires Windows `Valid` Authenticode, the expected publisher certificate and a
timestamp. Environment fields carry file/publisher values; they are not script
interpolation. No OS output is forwarded. This Windows integration is source-
implemented and cross-compiled; runtime trust proof remains outstanding.

Remaining launcher gates include signed release-manifest verification, owner-
only Windows ACLs, isolated RustDesk configuration and IPC, private credential
handoff, session-owned Job Objects, lease renewal, expiry/crash teardown, and
separate consent-preserving elevation. Do not substitute ordinary RustDesk
startup for those gates or advertise this package as customer-ready.

This module uses the Go standard library with no third-party dependencies.
Run `go test -race ./...` and `go vet ./...`. A Windows build/runtime check is
separate from the Linux test results. Signing uses the operator's already
purchased Basic plan after its actual account and publisher are identified.
