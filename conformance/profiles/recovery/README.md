# Recovery profile (§24)

`recovery-01-scope-lifecycle` pins all 39 ordinary and 3 early normative
recovery cases from the merged specification. The source validator checks both
complete archives, closed version-1 schemas, all request and record digests,
checkpoint and participant continuity, the trusted stage receipt, transfer
proofs, and exact case inventory. The local transfer archive retains the same
real definitions, migrated checkpoint, queues, deferred events, counters,
receipts, effects, intents, outbox, and helper participant as the merged §22
archive. The base core needs no authority coordinator or background service.

Six additional cases use a generated two-root archive from the merged §17 and
§22 lifecycle helpers. One root owns a spawned child with a deferred event and
an attempted ambiguous effect; the other has two nested component runtimes.
The resolver checks both complete machine definitions and checkpoint bytes.

An implementation claims this optional profile only after running
`scripts/run_recovery_profile.py --spec-root SPEC -- ADAPTER` against its real
configured host. The child receives the complete request, archive, inert stage
receipt, prior lifecycle requests when relevant, and trusted local proof inputs. It
receives no case ID, expected result, or expected after state. It must invoke
every setup request through the production recovery operation, return its full
response, then invoke the tested operation and report its literal complete caller response
and record, and independently observe durable before/after storage, calls, and
mutation paths. Each invocation uses isolated host storage. A successful
takeover or clone requires its own fresh logical scope and external namespace;
strict restore is quarantined. Refusals and read-only guards leave all observed
storage unchanged. Unknown external work remains ambiguous and cannot be
automatically redispatched.

The production runner currently exercises 38 standalone and refusal cases;
the 10 local transfer cases remain source-validated only. Their successful result may be
advertised only after the same configured host independently passes the §18
authority, §19 effect, and §21 delivery production profiles for its exact
installation, topology, provider closure, authority token, and required
participants. The timer profile applies only when a timer participant is
declared. Issue #80's delivery implementation is still a dependency for the
hosted claim. Cross-authority safe relocation is unavailable without separately
proved continuity. Static fixture success is never a production certificate.

Once §21 is merged, a host advertising the local single-authority topology runs
`scripts/run_hosted_recovery_profile.py --spec-root SPEC --adapter HOST
--authority-adapter AUTHORITY`. This gate requires the same actual configured
installation to pass the §18/§19/§21 native runner, binds its full reports and
loaded recovery closure/configuration to the §24 report, then executes all 42
normative and 6 two-root requests. The ten local cases require durable transfer
proofs, a frozen full inventory, known native transaction fate, retired source,
single-use grant, imported checkpoint/participant bytes, and unchanged state on
refusal. The hosted runner fails closed while the merged §21 runner is absent.
No host may report `safe_relocation` from the static fixture or by copying a
requested profile claim. The standalone runner never certifies local transfer.

Run local source checks with:

```sh
python scripts/generate_recovery_profile.py --spec-root SPEC --check
python scripts/test_recovery_validator.py --spec-root SPEC
python scripts/validate_conformance.py --spec-root SPEC
```
