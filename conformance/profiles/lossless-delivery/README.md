# Lossless delivery profile

This optional profile exercises SPEC §21 and binds only implementations that claim
lossless delivery. The first-version driver supplies each positive vector's
`operation`, `request`, `before`, and `fault_injection` to the implementation's
production delivery adapter. The adapter returns its own response; the harness
then captures the complete checkpoint, source bindings, ingress dead letters,
source acknowledgements, retained destination receipts, and provider dispatch
count. `name`, `replay_of`, `after`, and `expected_response` are withheld from the
adapter. A crash cut returns no response. Replay repeats the original caller
request and does not replace it with current checkpoint state.

For an invalid vector, the harness supplies `operation`, `candidate`, and
`before`, and compares the typed failure, acknowledgement decision, and complete
`after` store. `parse_delivery_bytes` supplies the decoded raw bytes, preserving
duplicate keys, nonfinite tokens, and invalid UTF-8. `validate_evidence` injects
one malformed response candidate into the adapter's public evidence/import gate;
it never treats an invalid candidate as the adapter's actual result. Every invalid
vector leaves source and checkpoint ownership unchanged and acknowledges nothing.

The admitted binding is host evidence outside the checkpoint. Its first commit
must be atomic with the complete mailbox envelope and §17 acceptance receipt.
The crash-after-commit vector retains that binding without a source
acknowledgement; redelivery returns it and acknowledges only under the current
host guard when authoritative fencing is claimed. A `source_owned` result keeps
the source item available. A durable ingress dead letter retains original
content and a digest-bound terminal receipt before acknowledgement. Deferral and
recall retain the original acceptance receipt; terminal processing uses a
distinct event-terminal receipt. The full core step value and emitted intents
are pinned in `native-emission-core-step-result-v1.json` and the real native
outbox checkpoint. Outbound `confirmed` proves destination responsibility only.
Business completion needs its own declared input result. A pending `ambiguous`
effect keeps the original effect identity and complete intent; a durable
dead-letter destination supplies a separate retained receipt.

The `normative_examples` member retains all five exact SPEC delivery examples
as provenance. Their synthetic outbound effect is not a runnable machine
trajectory; runnable outbound vectors instead use the valid format-1
`outbox-machine.yaml`, its actual core emission, and exact §17 checkpoint
snapshots. `machine.yaml` is the real portable deferral machine. The validator
checks those source snapshots, source/content and evidence digests, receipt
kinds, mailbox ownership, outbox locations, retained complete intents, and
destination receipt links independently of the generator. A destination
adapter must also prove the configured durable acceptance or dead-letter
contract; a receipt object alone does not establish remote durability.

The 14 positive SPEC response cases map to same-named runnable vectors, except
`unequal_source_identity_conflict` and the two replay cases, which are already
included among the seven first ingress vectors. The 11 invalid response/request
cases and nine invalid evidence-link cases appear by exact SPEC name in
`invalid_vectors`. Three additional raw JSON probes cover duplicate keys,
nonfinite numbers, and invalid UTF-8. Four typed transport probes cover map
order, nonfinite binary64, negative zero, and noncanonical integer spelling.
Additional vectors check that an equal retained source replay under a stale
epoch returns the exact §18 guard failure without source acknowledgement, that
a failed two-item batch remains entirely source-owned, and that source-ordered
pressure does not overtake an earlier unresolved item.

Five integration vectors bind the merged 43-vector §19 effect profile to the
merged §18 `worker_sqlite` native authority scenario. They pin a real confirmed
outbox record whose business invocation is still `unclaimed`, a host-owned
result admission with one live mailbox entry and acceptance receipt, interrupted
admission recovery with no second provider call, stale-epoch replay rejected
before acknowledgement, and an ambiguous invocation whose retry is refused
without destination deduplication proof. Each integration vector resolves the
exact merged checkpoint and journal, complete caller request, and direct effect
runner expectation. `source_item: null` and an empty source acknowledgement list
are assertions: §19 result admission is host-owned recovery work, not a broker
item. A confirmed outbound transfer grants no provider retry or business success.

Rebuild with `python scripts/generate_lossless_delivery_profile.py` and check
with `--check` using the repository validation environment. Run
`scripts/test_lossless_delivery_validator.py` for adversarial reseeding and
tampering probes. The repository validator counts 52 delivery vectors: 47
delivery operations and invalid inputs plus five merged §18/§19 integration
vectors. The standalone §21 profile does not itself assert the native capability.
Machine `format: 1`, delivery schema version `1`,
and package version `0.3.0` are distinct version domains.

For a full operational claim, run
`python scripts/run_lossless_delivery_profile.py --spec-root <pinned-spec> --adapter '<production-adapter-command>' --authority-adapter '<same-installation-authority-command>'`.
The runner first executes all 43 §19 vectors through the same production
adapter command. That runner invokes the §18 configured worker topology native
proof and checks the loaded handler, destination, authority, and participant
closure. The §21 runner then compares strict raw child JSON and the complete
observed store after every invocation, withholding expected responses and case
names. `--base-only` runs the weaker standalone delivery claim without claiming
§18 or §19. A passed source/schema check alone is fixture validation; configured
destinations and hosts must actually prove durability and native transactions.
