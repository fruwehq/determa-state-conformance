# Lossless delivery profile

This optional profile exercises SPEC §21 at immutable specification commit
`77c0a2e60cd0771a6d44ae170a079ddd51d7d9f0` and binds only implementations that claim
lossless delivery. The driver seeds a durable test transport with each original
source item and a separate controlled host store with the complete before state.
The adapter installs both through its public production source and store provider
paths. Their portable JSON commands are test instrumentation; they do not define
a production database schema or language API. The adapter fetches original
content from the source provider and commits host changes through the configured
store provider in one native transaction with its provider-generated proof.
For outbound delivery the adapter receives an effect identity and test route,
then passes the complete committed intent to the installed destination provider.
The expected provider result is withheld. The runner independently inspects the
provider's persisted fetch, acknowledgement, and destination call journal and
reads the controlled host store independently of adapter output.
`name`, `replay_of`, `after`, and `expected_response` are withheld from the adapter.
A crash cut returns no response. The controlled store records the before/after
commit cut and kills the adapter process. The runner reads the real committed
state and proof from a new store process. Replay resumes that same store with
the original caller request.

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
Additional vectors check that confirmed and dead-letter terminal effects replay
their retained decisions without another destination call, and that an equal
retained source replay under a stale
epoch returns the exact §18 guard failure without source acknowledgement, that
a failed two-item batch remains entirely source-owned, and that source-ordered
pressure does not overtake an earlier unresolved item.
The ordered-pressure vector is an internal hypothetical common-rule premise.
It is withheld from the public adapter and cannot certify a configured
`source_ordered` transport claim. This profile publishes an empty configured
transport claim set. A positive public claim requires a separate operational
transport proof for concurrent workers, retry gaps, durable dead letters, and
recovery under the exact installed source configuration and provider closure.

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

Six core observability vectors reuse executable core 117/118 operation inputs,
prior aggregate states, machine sources, and exact result artifacts. They bind a
deferred-capacity terminal fault, retained internal emissions, cancellation and
completion lifecycle dispositions, chained emissions, and an explicit
`migration_disposed` reason. The runner invokes the base operation and compares
the entire result and empty broker acknowledgement list. Faults and lifecycle
disposals therefore cannot disappear behind a generic handled response.

Rebuild with `python scripts/generate_lossless_delivery_profile.py` and check
with `--check` using the repository validation environment. Run
`scripts/test_lossless_delivery_validator.py` for adversarial reseeding and
tampering probes. The repository validator counts 60 delivery vectors: 49
delivery operations and invalid inputs, six core result observations, and five merged §18/§19 integration
vectors. The standalone §21 profile does not itself assert the native capability.
Machine `format: 1`, delivery schema version `1`,
and package version `0.3.0` are distinct version domains.

For a full operational claim, run
`python scripts/run_lossless_delivery_profile.py --spec-root <pinned-spec> --adapter '<production-adapter-command>' --authority-adapter '<same-installation-authority-command>'`.
The runner first executes all 43 §19 vectors through the same production
adapter command. That runner invokes the §18 configured worker topology native
proof and checks the loaded handler, destination, authority, and participant
closure. The §21 configured report and each native operation bind the exact
authority and effect report digests, test transport and host store closures,
source and destination configuration digests, and host storage configuration
digest. The §21 runner compares strict raw child JSON, native transaction
evidence, and its own fresh-process read of the complete persisted host store after
every invocation. The crash-after-commit replay uses the crashed operation's
persisted session; the precommit crash retains source ownership. The runner
reads the test transport independently and requires source fetches,
acknowledgements bound to the committed checkpoint and transfer digest, and
destination calls carrying complete intents with retained acceptance or dead
letter receipts. At acknowledgement time the transport reads the controlled
host store directly and refuses and records an early ack attempt unless the
exact source binding or dead letter is already committed. The five bound §19
operations require the full §19 native observation and the same controlled
store's transaction identity, plus host-owned
result admission with no broker acknowledgement. It refuses a `source_ordered`
configured report without a dedicated operational transport proof and runs 59
public delivery vectors in the full profile (54 with `--base-only`); the
additional ordered-pressure common premise stays internal. `--base-only` runs
the weaker standalone delivery claim without claiming §18 or §19. A passed
source/schema check alone is fixture validation. `--proof-summary-output` writes
canonical same-run JSON containing the checked provider closures, configuration
digests, actual host commit proofs, crash cuts, destination calls, and §18/§19
proof receipts. This operational result applies to the exact injected store and
transport installation. A builtin SQLite or PostgreSQL host requires its own
native proof under that installation before claiming the same guarantee.
The controlled provider journal is driver-owned test evidence: an adapter must
use the provider through its public `ExecutionStore` installation and must not
write the provider's SQLite files directly. The runner's trust boundary assumes
the test provider and its journal are protected from such out-of-band writes.
