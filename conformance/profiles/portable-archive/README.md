# Portable archive profile (§22)

`archive-01-complete-snapshot` carries the pinned, complete normative raw vectors:
9 export and 43 import-stage cases. They include the four-root snapshot, normalized
definitions, migration descriptor, owned ready/deferred queues, receipts, faults,
pending and terminal intents, compact tombstone, optional helper participant, and
conditional required native host journal. The source is the explicitly pinned
`examples/archives/` directory of the specification; the generator verifies exact
source bytes. `test.yaml` names every case. No result is inferred from a case name.

An implementation declaring `portable_archive` runs
`scripts/run_portable_archive_profile.py --spec-root SPEC -- ADAPTER`. The adapter
reads one JSON request from stdin and writes one JSON response to stdout. Export
input has `operation`, `request`, and `source_capture`; stage input has `operation`,
`request`, `input_archive`, and `configured_import`. The input omits `case_id`,
`expected_result`, `expected_archive`, `expected_staged_archive`, and other oracle
fields. The adapter calls the production export or stage operation. It returns exactly
`result`, `archive`, `staged_archive`, `before`, `after`, and `calls`. `archive` is the
exported archive or null; `staged_archive` is the staged archive or null. The runner
compares complete canonical results and archives.

`before` and `after` are actual host observations with exactly `active_scopes`,
`authority_grants`, `credentials`, `checkpoints`, `host_journals`,
`participant_storage`, and `staged_archives`. The first three are lists of
host-owned identities. The next three are complete captured storage observations
so a failed export or stage cannot silently mutate source data. `staged_archives`
is a list of objects with exact
`staging_identity` and `archive`. A successful stage appends one inert archive;
refusals and exports leave this observation unchanged. `calls` has exact integer
counts for `core_create`, `core_admit`, `core_step`, `core_migration`, `worker_claim`,
`effect_dispatch`, `timer_poll`, `clock_read`, `authority_grant`, and
`credentials_create`. All are zero for these vectors. The adapter must observe the
actual host, rather than manufacture these counts from expected results.

Source inventory and import trusted policy are test-host inputs. An implementation
must establish source consistency and trusted configured requiredness independently
of the archive. The JSON source assertion alone is not proof of authoritative
storage. A valid digest is content identity, not activation, authority, or worker
permission. This profile certifies only the advertised archive export/stage surface;
standalone takeover, relocation, clone, and activation belong to later recovery work.

The repository validator verifies pinned schema bytes, archive/member/nested hashes,
closure, fixture schemas, positive stage bytes, inert observations, and every declared
case ID. That source check does not certify an implementation. The production driver
must be run by the implementation or host CI. The optional §19 journal gate is
conditional on a source claiming `durable_native_results`; this fixture supplies
typed evidence and trusted inventory, while an implementation must validate its
actual native provider and storage capture.

Regenerate and check with an explicit specification checkout:

```sh
python scripts/generate_portable_archive_profile.py --spec-root SPEC
python scripts/generate_portable_archive_profile.py --spec-root SPEC --check
python scripts/validate_conformance.py --spec-root SPEC
python scripts/test_portable_archive_validator.py --spec-root SPEC
```
