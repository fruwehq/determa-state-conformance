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
    "invalid-guard-output-type.json", "invalid-provider-digest.json",
    "language-source-v1.json", "mixed-cel-native.yaml",
)
SOURCES = ("provider/test_provider.py", "provider/test_provider.rs")
REQUIRED = frozenset((
    "load_exact_weak_opt_in", "load_missing_dependency", "load_changed_dependency",
    "load_untrusted_closure", "load_changed_source_bytes", "load_strong_host_refuses_weak",
    "cel_first_skips_native", "native_false_no_actions", "native_action_proposals",
    "invalid_action_output_rolls_back", "native_io_then_action_failure",
    "native_io_then_cas_conflict", "inspect_unsafe_refused", "inspect_structural_no_call",
    "inspect_safe_bounded", "inspect_safe_fuel_exhausted", "inspect_mixed_refused_before_cel",
    "restore_without_compiler", "restore_missing_runtime", "compile_exact_source",
    "compile_missing_compiler", "compile_bad_region_source",
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
    safe_branch = safe_machine["machines"][0]["root"]["states"]["pending"]["on_events"]["submit"][1]
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
    _require(bool(list(Draft202012Validator(schemas["runtime-action-output-v1.schema.json"],
                                         registry=registry).iter_errors(invalid_output))),
             "invalid action example became valid")

    for vector in manifest["vectors"]:
        request = vector["request"]
        expected = vector["expected"]
        installed = request["installed"]
        _require(installed["source_digest"] == source_digest, "installed source digest changed")
        identities = [(ref["identifier"], ref["version"], ref["content_digest"])
                      for ref in installed["providers"]]
        _require(len(identities) == len(set(identities)), "duplicate installed identity")
        _require(expected["calls"]["external"] == expected["irreversible_side_effects"],
                 f"{vector['name']}: external side-effect accounting changed")
        if expected["result"] in {"rejected", "faulted", "uncommitted"}:
            _require(not expected["determa_state_committed"],
                     f"{vector['name']}: failed operation committed")
        if vector["name"].startswith("load_") and expected["result"] == "rejected":
            _require(not any(expected["calls"].values()), "rejected load invoked provider")
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
