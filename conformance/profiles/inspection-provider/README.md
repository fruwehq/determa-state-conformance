# Optional native inspection provider profile (unreleased 0.3)

`provider-01-exact-closure` is conditional on a host advertising a configured,
independently verified native `inspect_guard` capability. It does not add a native
provider to mandatory core inspection. The core case 125 continues to require
structural inspection and, when advertised, bounded CEL semantic inspection.

The executable fixture sources are `provider/test_provider.py` and
`provider/test_provider.rs`. `provider-closure.json` records each raw source byte
digest. The provider reference `content_digest` is SHA-256 over the domain bytes
`determa-test-inspection-provider-closure-1\0`, then for each source path in the
fixed Python, Rust order: an eight-byte big-endian path byte length, UTF-8 path
bytes, an eight-byte big-endian source byte length, and raw source bytes. The
`source_digest` binds the exact canonical bytes of `provider-closure.json`. The
validator independently recomputes both digests and the guard binding under the
validated bundle fingerprint. Its positive outcome cannot be substituted under a
changed source closure, dependency list, or provider reference.

A claiming implementation must load or inject its executable fixture through its
public provider registration route, verify the installed descriptor and byte closure,
allowlist the exact provider, and prove the configured instance healthy. It must
verify the separate `inspect_guard` path against its host policy and actual loaded
code, including an immutable snapshot, deterministic two-step schedule, no provider
state change, zero external calls, and zero ordinary `evaluate` calls. A declaration
of `pure` or `semantically_introspectable` is only a claim. The fixture contains no
public `verified` switch. Run every vector through the production
`inspect_candidate` call with its six literal request members and compare the raw
outcome plus unchanged aggregate bytes and call counters. The unsafe provider must
fail closed before ordinary evaluation. A budget of one step exhausts at the guard
pointer; two steps permit the safe provider's true result.
The `mixed` event puts a CEL guard before an unsafe native guard. Semantic
inspection must refuse the whole request before evaluating that CEL guard.

This profile's seven vectors are always validated as source/schema fixtures in CI.
Runtime pass accounting is separate: a host may omit the profile only when it does
not advertise a configured native safe inspection capability. Any final release
claiming the provider capability must execute all seven vectors; schema validation
alone does not establish that claim. Generate or verify fixtures with
`python scripts/generate_inspection_provider_profile.py [--check]`.
