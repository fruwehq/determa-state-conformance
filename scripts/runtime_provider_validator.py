"""Independent closure, provenance, schema, and relation checks for provider vectors."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from ruamel.yaml import YAML

from generate_version1_vectors import bundle_fingerprint_document, canonical, digest, typed_value

CASE_REL = Path("conformance/profiles/runtime-provider/provider-01-exact-source")
EXAMPLES = (
    "action-output.json", "compilation-manifest-v1.json", "compiled-machine.json",
    "guard-descriptor-v1.json", "invalid-action-output.json",
    "invalid-guard-output-type.json", "invalid-missing-correlation-action-output.json",
    "invalid-provider-digest.json",
    "language-source-v1.json", "mixed-cel-native.yaml",
    "multiple-send-action-output.json", "multiple-send-identities.json",
    "invalid-multiple-send-identities.json", "inert-provider-metadata.yaml",
)
SOURCES = ("provider/test_provider.py", "provider/test_provider.rs")
REQUIRED = frozenset((
    "load_exact_weak_opt_in", "load_missing_dependency", "load_changed_dependency",
    "load_untrusted_closure", "load_changed_source_bytes", "load_strong_host_refuses_weak",
    "cel_first_skips_native", "native_false_no_actions", "native_action_proposals",
    "invalid_action_output_rolls_back", "native_io_then_action_failure",
    "native_io_then_cas_conflict", "inspect_unsafe_refused", "inspect_structural_no_call",
    "inspect_safe_bounded", "inspect_safe_fuel_exhausted", "inspect_mixed_refused_before_cel",
    "restore_without_compiler", "restore_runtime_without_compiler", "restore_missing_runtime", "compile_exact_source",
    "compile_missing_compiler", "compile_bad_region_source",
    "restore_changed_runtime", "restore_untrusted_runtime", "compile_changed_compiler",
    "compile_untrusted_compiler", "compile_manifest_fingerprint_mismatch",
    "compile_source_digest_mismatch", "compile_limit_exceeded",
    "compile_invalid_metadata_slot", "compile_invalid_variable_value_slot", "compile_weak_without_manifest",
    "native_repeated_sends_have_distinct_ids", "native_repeated_sends_commit_and_replay", "native_mixed_sends_have_separate_ordinals", "load_inert_provider_metadata",
    "native_root_assignment_before_final", "ordinary_root_assignment_before_final",
    "native_local_write_destroyed_by_event", "native_local_write_destroyed_after_choice",
    "native_snapshot_preserves_complete_queue_envelope",
    "native_initial_local_write_destroyed_by_final", "ordinary_initial_destroyed_write_rejected_at_load",
))


class RuntimeProviderValidationError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeProviderValidationError(message)


def _validate(schema: dict, document: object, registry: Registry, label: str) -> None:
    errors = list(Draft202012Validator(schema, registry=registry).iter_errors(document))
    if errors:
        raise RuntimeProviderValidationError(f"{label}: {errors[0].message}")


def _schemas(spec_root: Path, root: Path) -> tuple[dict, Registry]:
    names = (
        "machine.schema.json", "provider-reference-v1.schema.json",
        "runtime-provider-descriptor-v1.schema.json", "runtime-action-output-v1.schema.json",
        "language-source-v1.schema.json", "compilation-manifest-v1.schema.json",
    )
    resources = []
    schemas = {}
    for name in names:
        schema = json.loads((spec_root / "schema" / name).read_text())
        schemas[name] = schema
        resource = Resource.from_contents(schema)
        resources.append((name, resource))
        resources.append((schema["$id"], resource))
    schema = json.loads((root / "scripts/schemas/runtime-provider-vectors.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    return {**schemas, "vectors": schema}, Registry().with_resources(resources)


def validate_positive_semantics(machine: dict, output: dict) -> None:
    """Check the format-1 rules that the structural schemas cannot express."""
    root = machine["machines"][0]["root"]
    states = root["states"]
    reachable = {root["initial"]["transition_to"]}
    frontier = list(reachable)
    while frontier:
        state = states[frontier.pop()]
        for branches in state.get("on_events", {}).values():
            for branch in branches if isinstance(branches, list) else [branches]:
                target = branch.get("transition_to")
                if target and target not in reachable:
                    reachable.add(target)
                    frontier.append(target)
    _require(set(states) == reachable, "positive machine has an unreachable state")
    for state in states.values():
        for branches in state.get("on_events", {}).values():
            for branch in branches if isinstance(branches, list) else [branches]:
                for action in branch.get("action", []):
                    if "send" in action and action["send"].get("to") == {"external": True}:
                        _require(action["send"].get("correlation_id") == "'provider-correlation'",
                                 "external machine send lacks a nonempty CEL correlation")
    for action in output["actions"]:
        if "send" in action and action["send"].get("to") == {"external": True}:
            _require(action["send"].get("correlation_id") == ["string", "provider-correlation"],
                     "external provider proposal lacks a nonempty typed correlation")


def validate_native_emission_identities(record: dict) -> None:
    """Recompute identities from declared operands, independently of the generator."""
    _require(set(record) == {"definition", "root_instance_id", "emitting_runtime_id", "cause_id", "step_sequence", "action_document_pointer", "output_file", "external_emissions"}, "native identity vector shape changed")
    ids = []
    for ordinal, emission in enumerate(record["external_emissions"]):
        _require(set(emission) == {"effect_id", "emission_index", "sequence"}, "native emission shape changed")
        _require(emission["emission_index"] == str(ordinal) and emission["sequence"] == str(ordinal), "native slot ordinal reset")
        expected = digest(["determa-effect-identity-1", "1", record["definition"], record["root_instance_id"],
                           record["emitting_runtime_id"], record["cause_id"], record["step_sequence"],
                           record["action_document_pointer"], emission["emission_index"]])
        _require(emission["effect_id"] == expected, "native effect identity differs from its slot operands")
        ids.append(emission["effect_id"])
    _require(len(ids) == 2 and len(set(ids)) == 2, "native repeated sends lost distinct identities")


def validate_profile(spec_root: Path, repository_root: Path) -> int:
    case = repository_root / CASE_REL
    schemas, registry = _schemas(spec_root, repository_root)
    manifest = json.loads((case / "vectors.generated.json").read_text())
    _validate(schemas["vectors"], manifest, registry, "vectors")
    names = [vector["name"] for vector in manifest["vectors"]]
    _require(len(names) == len(set(names)) and set(names) == REQUIRED, "vector coverage changed")
    _require(tuple(manifest["source_files"]) == SOURCES, "source list changed")
    examples = tuple("norm-" + (name[:-5] + ".source" if name.endswith(".yaml") else name)
                     for name in EXAMPLES)
    _require(tuple(manifest["normative_examples"]) == examples, "normative example list changed")
    for original, copied in zip(EXAMPLES, examples):
        _require((case / copied).read_bytes() == (spec_root / "examples/providers" / original).read_bytes(),
                 f"normative source changed: {original}")
    original_machine = YAML(typ="safe").load((case / "norm-mixed-cel-native.source").read_text())
    _validate(schemas["machine.schema.json"], original_machine, registry, "normative mixed machine")
    original_guard = json.loads((case / "norm-guard-descriptor-v1.json").read_text())
    _validate(schemas["runtime-provider-descriptor-v1.schema.json"], original_guard,
              registry, "normative guard descriptor")
    for name in ("norm-invalid-guard-output-type.json", "norm-invalid-provider-digest.json"):
        invalid = json.loads((case / name).read_text())
        _require(bool(list(Draft202012Validator(schemas["machine.schema.json"],
                                             registry=registry).iter_errors(invalid))),
                 f"{name}: normative structural negative became valid")
    original_source = json.loads((case / "norm-language-source-v1.json").read_text())
    original_manifest = json.loads((case / "norm-compilation-manifest-v1.json").read_text())
    original_compiled = json.loads((case / "norm-compiled-machine.json").read_text())
    _validate(schemas["language-source-v1.schema.json"], original_source,
              registry, "normative source")
    _validate(schemas["compilation-manifest-v1.schema.json"], original_manifest,
              registry, "normative manifest")
    _validate(schemas["machine.schema.json"], original_compiled, registry, "normative compiled machine")
    _require(original_source["artifact_digest"] == digest([
        "determa.language_source", "1", typed_value(original_source["content"])]),
        "normative source digest changed")
    _require(original_manifest["artifact_digest"] == digest([
        "determa.compilation_manifest", "1", typed_value(original_manifest["content"])]),
        "normative manifest digest changed")
    _require(original_manifest["content"]["source_artifact_digest"] ==
             original_source["artifact_digest"] and
             original_manifest["content"]["generated_validated_bundle_fingerprint"] ==
             bundle_fingerprint_document(original_compiled),
             "normative compiler provenance changed")

    hasher = hashlib.sha256(b"determa-test-runtime-provider-closure-1\0")
    files = []
    for name in SOURCES:
        body = (case / name).read_bytes()
        path = name.encode()
        hasher.update(len(path).to_bytes(8, "big"))
        hasher.update(path)
        hasher.update(len(body).to_bytes(8, "big"))
        hasher.update(body)
        files.append({"path": name, "sha256": "sha256:" + hashlib.sha256(body).hexdigest()})
    closure_bytes = (case / "provider-closure.json").read_bytes()
    _require(closure_bytes == canonical({"format": "determa.test_runtime_provider_closure",
                                        "version": 1, "files": files}), "source closure changed")
    closure_digest = "sha256:" + hasher.hexdigest()
    source_digest = "sha256:" + hashlib.sha256(closure_bytes).hexdigest()

    machine = YAML(typ="safe").load((case / "machine.yaml").read_text())
    safe_machine = YAML(typ="safe").load((case / "machine-safe.yaml").read_text())
    branch = machine["machines"][0]["root"]["states"]["pending"]["on_events"]["submit"][1]
    guard = branch["guard"]["provider"]
    actions = branch["action"][0]["provider_actions"]
    dependency = guard["dependencies"][0]
    for kind, binding in (("guard", guard), ("actions", actions)):
        _require(binding["provider_reference"]["content_digest"] == closure_digest,
                 f"{kind} executing closure changed")
        _require(binding["source_digest"] == source_digest, f"{kind} source digest changed")
        _require(binding["dependencies"] == [dependency] and
                 dependency["content_digest"] == closure_digest, "transitive closure changed")
        _require(binding["capabilities"]["external_io_capable"] is True and
                 binding["capabilities"]["pure"] is False, "weak provider policy changed")
        descriptor = json.loads((case / f"{kind}-descriptor.json").read_text())
        _require(descriptor == {"kind": kind, "binding": binding}, f"{kind} descriptor changed")
        _validate(schemas["runtime-provider-descriptor-v1.schema.json"], descriptor,
                  registry, f"{kind} descriptor")
    _require(dependency["identifier"] == "example.native-common", "dependency identity changed")
    safe_branch = safe_machine["machines"][0]["root"]["states"]["pending"]["on_events"]["submit"]
    _require(isinstance(safe_branch, dict) and set(safe_branch) == {"guard", "action"},
             "safe inspection must encounter its provider first")
    for kind, binding in (("guard", safe_branch["guard"]["provider"]),
                          ("actions", safe_branch["action"][0]["provider_actions"])):
        _require(binding["provider_reference"]["content_digest"] == closure_digest and
                 binding["source_digest"] == source_digest and
                 binding["dependencies"] == [dependency] and
                 binding["capabilities"]["semantically_introspectable"] is True and
                 binding["capabilities"]["external_io_capable"] is False,
                 f"safe {kind} closure or capability changed")
        _require(json.loads((case / f"safe-{kind}-descriptor.json").read_text()) ==
                 {"kind": kind, "binding": binding}, f"safe {kind} descriptor changed")
    _validate(schemas["machine.schema.json"], safe_machine, registry, "safe machine")

    source = json.loads((case / "source-package.json").read_text())
    compiler = source["content"]["regions"][0]["provider_reference"]
    _validate(schemas["language-source-v1.schema.json"], source, registry, "source package")
    _require(source["artifact_digest"] == digest(["determa.language_source", "1",
                                                   typed_value(source["content"])]),
             "source package digest changed")
    _require(source["content"]["dependencies"] == [dependency], "compiler dependency changed")
    _require(compiler["content_digest"] == closure_digest and
             compiler["identifier"] == "example.guard-compiler", "compiler identity changed")
    regions = source["content"]["regions"]
    _require(len(regions) == 1 and regions[0]["kind"] == "guard" and
             regions[0]["locator"] == "/machines/0/root/states/pending/on_events/submit/guard" and
             regions[0]["source"] == "event.payload.approved", "source region changed")
    compiled = json.loads((case / "norm-compiled-machine.json").read_text())
    manifest_document = json.loads((case / "source-manifest.json").read_text())
    _validate(schemas["compilation-manifest-v1.schema.json"], manifest_document,
              registry, "compilation manifest")
    content = manifest_document["content"]
    _require(manifest_document["artifact_digest"] == digest([
        "determa.compilation_manifest", "1", typed_value(content)]), "manifest digest changed")
    _require(content["source_artifact_digest"] == source["artifact_digest"] and
             content["compiler_providers"] == [compiler, dependency] and
             content["generated_validated_bundle_fingerprint"] == bundle_fingerprint_document(compiled),
             "compiler provenance changed")
    _validate(schemas["machine.schema.json"], compiled, registry, "compiled machine")
    valid_output = json.loads((case / "norm-action-output.json").read_text())
    invalid_output = json.loads((case / "norm-invalid-action-output.json").read_text())
    _validate(schemas["runtime-action-output-v1.schema.json"], valid_output, registry, "action output")
    validate_positive_semantics(machine, valid_output)
    validate_positive_semantics(safe_machine, valid_output)
    missing_correlation = json.loads((case / "norm-invalid-missing-correlation-action-output.json").read_text())
    _validate(schemas["runtime-action-output-v1.schema.json"], missing_correlation,
              registry, "semantic negative action output")
    try:
        validate_positive_semantics(machine, missing_correlation)
    except RuntimeProviderValidationError:
        pass
    else:
        raise RuntimeProviderValidationError("missing-correlation normative negative became valid")
    _require(bool(list(Draft202012Validator(schemas["runtime-action-output-v1.schema.json"],
                                         registry=registry).iter_errors(invalid_output))),
             "invalid action example became valid")

    multiple_output = json.loads((case / "norm-multiple-send-action-output.json").read_text())
    _validate(schemas["runtime-action-output-v1.schema.json"], multiple_output, registry, "multiple native sends")
    validate_positive_semantics(machine, multiple_output)
    _require(multiple_output["actions"][1] == multiple_output["actions"][2], "repeated-send fixture no longer repeats a send")
    validate_native_emission_identities(json.loads((case / "norm-multiple-send-identities.json").read_text()))
    try:
        validate_native_emission_identities(json.loads((case / "norm-invalid-multiple-send-identities.json").read_text()))
    except RuntimeProviderValidationError:
        pass
    else:
        raise RuntimeProviderValidationError("duplicate native identity negative became valid")
    inert = YAML(typ="safe").load((case / "machine-inert.yaml").read_text())
    _validate(schemas["machine.schema.json"], inert, registry, "inert provider metadata")
    _require((case / "machine-inert.yaml").read_bytes() == (spec_root / "examples/providers/inert-provider-metadata.yaml").read_bytes(), "inert provider machine differs from specification")
    for vector in manifest["vectors"]:
        request = vector["request"]
        expected = vector["expected"]
        compiler_calls = expected["calls"]["compile_region"]
        _require(compiler_calls == (1 if vector["name"] in {
            "compile_exact_source", "compile_bad_region_source",
            "compile_manifest_fingerprint_mismatch", "compile_weak_without_manifest"} else 0),
            f"{vector['name']}: compiler invocation accounting changed")
        if vector["name"] in {"compile_invalid_metadata_slot", "compile_invalid_variable_value_slot"}:
            _require(request["arguments"].get("without_manifest") is True and
                     request["arguments"].get("invalid_slot") ==
                     ("metadata_guard" if vector["name"] == "compile_invalid_metadata_slot" else "variable_action") and
                     expected["stages"] == ["validate_source"] and
                     expected["result"] == "rejected" and expected["code"] == "language_compilation_failed",
                     "inert source locator was not rejected before compiler resolution")
        if vector["name"] == "compile_weak_without_manifest":
            value = expected["value"]
            _require(request["arguments"].get("without_manifest") is True and
                     request["arguments"].get("weak_compiler") is True and
                     expected["effective_capabilities"] == {
                         "deterministic": False, "pure": False, "portable": False,
                         "semantically_introspectable": False, "process_contained": False,
                         "external_io_capable": True} and
                     value["source_artifact_digest"] == source["artifact_digest"] and
                     value["compiler_providers"] == content["compiler_providers"] and
                     value["generated_validated_bundle_fingerprint"] == content["generated_validated_bundle_fingerprint"] and
                     value["generated_runtime_capabilities"] == content["source_capabilities"] and
                     value["restored_runtime_capabilities"] == content["source_capabilities"] and
                     value["restore_compiler_calls"] == 0,
                     "weak source compilation lost provenance or weakened generated CEL restoration")
        installed = request["installed"]
        setup = request["setup"]
        if request["operation"] in {"step", "host_commit", "inspect", "create"}:
            _require(isinstance(setup, dict), "execution request omitted setup")
            selected = YAML(typ="safe").load((case / request["bundle"]).read_text())
            creation = setup["create_request"]
            target = digest(["determa-root-runtime-identity-1", "1",
                             bundle_fingerprint_document(selected), selected["namespace"],
                             creation["machine_id"], creation["machine_version"],
                             creation["root_instance_id"]])
            envelope = setup["envelope"]
            _require(setup["target_runtime_id"] == target and
                     envelope["target"] == {"root": {"root_instance_id": creation["root_instance_id"],
                                                     "root_runtime_id": target}} and
                     (setup["provider_snapshot"].get("event") == envelope if request["operation"] != "create" else "event" not in setup["provider_snapshot"]) and
                     setup["provider_snapshot"]["variables"] ==
                     ["map", [["accepted", ["boolean", False]]]],
                     f"{vector['name']}: execution snapshot or target changed")
            _require(envelope["payload"] == ["map", [["approved", ["boolean",
                     request["arguments"].get("approved", False)]]]],
                     f"{vector['name']}: typed provider payload changed")
        else:
            _require(setup is None, "non-execution operation has setup")
        if request["operation"] == "restore":
            selected = original_compiled if request["bundle"] == "norm-compiled-machine.json" else machine
            _require(request["arguments"].get("definition_fingerprint") ==
                     bundle_fingerprint_document(selected), "restoration definition changed")
            compiler_ref = compiler
            installed_ids = {ref["identifier"] for ref in installed["providers"]}
            if vector["name"] in {"restore_without_compiler", "restore_runtime_without_compiler"}:
                _require(compiler_ref["identifier"] not in installed_ids,
                         "restoration unexpectedly installed compiler")
            if vector["name"] == "restore_missing_runtime":
                _require(compiler_ref["identifier"] in installed_ids and
                         guard["provider_reference"]["identifier"] not in installed_ids,
                         "missing runtime case did not retain only compiler closure")
        _require(installed["source_digest"] == source_digest, "installed source digest changed")
        identities = [(ref["identifier"], ref["version"], ref["content_digest"])
                      for ref in installed["providers"]]
        _require(len(identities) == len(set(identities)), "duplicate installed identity")
        _require(expected["calls"]["external"] == expected["irreversible_side_effects"],
                 f"{vector['name']}: external side-effect accounting changed")
        _require(len(expected["external_effects"]) == expected["irreversible_side_effects"],
                 f"{vector['name']}: external evidence changed")
        if setup is not None:
            _require(expected["state_after"] is not None and
                     (expected["state_before"] is None if request["operation"] == "create"
                      else expected["state_before"] is not None),
                     f"{vector['name']}: state observation missing")
            if not expected["determa_state_committed"] and request["operation"] != "create":
                _require(expected["state_after"] == expected["state_before"],
                         f"{vector['name']}: uncommitted state changed")
        if expected["result"] in {"rejected", "faulted", "uncommitted"}:
            _require(not expected["determa_state_committed"],
                     f"{vector['name']}: failed operation committed")
        if vector["name"].startswith("load_") and expected["result"] == "rejected":
            _require(not any(expected["calls"].values()), "rejected load invoked provider")
    captured = next(vector for vector in manifest["vectors"] if vector["name"] == "native_snapshot_preserves_complete_queue_envelope")
    for key in ("guard_snapshot", "action_snapshot"):
        _require(captured["expected"]["value"][key] == captured["request"]["setup"]["provider_snapshot"], "native snapshot lost complete source/cause envelope or typed variables")
    _require(captured["request"]["setup"]["envelope"]["cause_id"] == captured["request"]["setup"]["envelope"]["event_id"] and captured["request"]["setup"]["envelope"]["source"] == {"host": True}, "snapshot vector lost valid host delivery provenance")
    repeated = next(vector for vector in manifest["vectors"] if vector["name"] == "native_repeated_sends_have_distinct_ids")
    setup = repeated["request"]["setup"]
    slot = "/machines/0/root/states/pending/on_events/submit/1/action/0"
    identities = repeated["expected"]["value"]["emission_identities"]
    _require(len(identities) == 3, "native operational output lost a send")
    for position, identity in enumerate(identities):
        pointer = slot if position < 2 else "/machines/0/root/states/pending/on_events/submit/1/action/1/send"
        ordinal = position if position < 2 else 0
        expected_id = digest(["determa-effect-identity-1", "1", [machine["namespace"], "order", "1"],
                              setup["create_request"]["root_instance_id"], setup["target_runtime_id"],
                              setup["envelope"]["cause_id"], "1", pointer, str(ordinal)])
        _require(identity == {"effect_id": expected_id, "emission_index": str(ordinal), "sequence": str(position)}, "native operational identity/receipt index changed")
    replay = next(vector for vector in manifest["vectors"] if vector["name"] == "native_repeated_sends_commit_and_replay")
    _require(replay["request"]["arguments"].get("replay") is True and
             replay["request"]["arguments"].get("cas_conflict") is False and
             replay["request"]["arguments"]["maximum_attempts"] == 1 and
             replay["expected"]["value"]["emission_identities"] == identities and
             replay["expected"]["value"]["checkpoint_revision"] == "2" and
             replay["expected"]["value"]["retained_effect_references"] == [{"kind": "external_outbox", "effect_id": item["effect_id"], "emission_index": item["emission_index"]} for item in identities] and
             replay["expected"]["value"]["pending_outbox_entries"] == [{"intent": {"effect_id": item["effect_id"], "sequence": item["sequence"], "event": "accepted", "payload": ["map", []], "correlation_id": "provider-correlation"}, "state_revision": "2", "delivery_state": {"status": "not_attempted"}} for item in identities] and
             all(replay["expected"]["value"][key] is True for key in
                 ("replay_receipt_equal", "replay_checkpoint_unchanged", "replay_provider_calls_unchanged")),
             "durable native commit/replay evidence changed")
    mixed = next(vector for vector in manifest["vectors"] if vector["name"] == "native_mixed_sends_have_separate_ordinals")
    mixed_setup = mixed["request"]["setup"]
    mixed_machine = YAML(typ="safe").load((case / mixed["request"]["bundle"]).read_text())
    mixed_ids = mixed["expected"]["value"]["emission_identities"]
    _require(len(mixed_ids) == 5 and mixed["request"]["arguments"].get("mixed_send") is True,
             "mixed send coverage changed")
    for position, kind, ordinal in ((0, "external", 0), (1, "internal", 0), (2, "external", 1), (3, "internal", 1), (4, "external", 0)):
        locator = slot if position < 4 else slot.replace("action/0", "action/1/send")
        identity = mixed_ids[position]
        common = [mixed_setup["create_request"]["root_instance_id"], mixed_setup["target_runtime_id"]]
        if kind == "external":
            expected_digest = digest(["determa-effect-identity-1", "1", [mixed_machine["namespace"], "order", "1"], *common, mixed_setup["envelope"]["cause_id"], "1", locator, str(ordinal)])
            _require(identity == {"effect_id": expected_digest, "emission_index": str(ordinal), "sequence": str(position // 2)}, "mixed external ordinal/identity changed")
        else:
            expected_digest = digest(["determa-event-identity-1", "1", *common, mixed_setup["target_runtime_id"], mixed_setup["envelope"]["cause_id"], "1", locator, str(ordinal)])
            _require(identity == {"event_id": expected_digest, "emission_index": str(ordinal), "acceptance_sequence": str(ordinal + 1), "queue_sequence": str(ordinal + 1)}, "mixed internal ordinal/identity changed")
    _require(mixed["expected"]["state_after"]["ready_mailbox_length"] == 2 and mixed["expected"]["state_after"]["output_count"] == 3,
             "mixed send mailbox/output projection changed")
    io_failure = next(v for v in manifest["vectors"] if v["name"] == "native_io_then_cas_conflict")
    _require(io_failure["request"]["arguments"]["maximum_attempts"] == 1 and
             io_failure["expected"]["irreversible_side_effects"] == 1 and
             "compare_and_swap" == io_failure["expected"]["stages"][-1],
             "CAS conflict lost one-attempt irreversible evidence")
    # This check also pins complete operation inputs and oracle fields, while the
    # calculations above independently establish the exact source and provenance.
    from generate_runtime_provider_profile import render
    expected_files = render(spec_root)
    _require(set(expected_files) == {path.name for path in case.iterdir() if path.is_file()},
             "runtime provider fixture file set changed")
    for name, body in expected_files.items():
        _require((case / name).read_bytes() == body, f"generated fixture changed: {name}")
    return len(manifest["vectors"])
