#!/usr/bin/env python3
"""Adversarial swaps across otherwise valid extension negotiation vectors."""

import argparse
import copy
import json
import tempfile
from pathlib import Path

from validate_extension_negotiation import (
    ExtensionValidationError, PROFILE, validate_document,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, required=True)
    args = parser.parse_args()
    original = json.loads((PROFILE / "vectors.generated.json").read_text())
    vectors = {v["id"]: v for v in original["vectors"]}
    attacks = []
    def attack(label, change):
        document = copy.deepcopy(original)
        selected = {v["id"]: v for v in document["vectors"]}
        change(document, selected)
        attacks.append((label, document))
    attack("category", lambda d, v: v["configured_capability_satisfied"]["requirements"][0].update(category="projection", capability="lossless_projection"))
    attack("instance", lambda d, v: v["configured_capability_satisfied"]["requirements"][0].update(instance_id="other"))
    attack("version", lambda d, v: v["configured_capability_satisfied"]["requirements"][0]["provider_reference"].update(version="1.2.4"))
    attack("digest", lambda d, v: v["configured_capability_satisfied"]["requirements"][0]["provider_reference"].update(content_digest="sha256:"+"f"*64))
    attack("claim", lambda d, v: v["configured_capability_satisfied"]["configurations"][0]["configuration"].update(claims=[]))
    attack("health", lambda d, v: v["configured_capability_satisfied"]["configurations"][0]["configuration"].update(health="degraded"))
    attack("policy", lambda d, v: v["configured_capability_satisfied"]["hypothetical_verification"]["proofs"][0].update(claims=[]))
    attack("proof reference", lambda d, v: v["configured_capability_satisfied"]["hypothetical_verification"]["proofs"][0]["provider_reference"].update(version="1.2.4"))
    attack("proof configuration", lambda d, v: v["configured_capability_satisfied"]["hypothetical_verification"]["proofs"][0].update(configuration_digest="sha256:"+"f"*64))
    attack("composition policy", lambda d, v: v["composition_all_and_any"]["hypothetical_verification"]["host_guarantees"].update(deterministic=False))
    attack("composition participant", lambda d, v: v["composition_all_and_any"]["hypothetical_verification"]["proofs"][1].update(claims=[]))
    attack("missing weak profile opt in", lambda d, v: v["composition_all_and_any"]["hypothetical_verification"].update(weak_profile_opt_in=False))
    attack("uri fallback", lambda d, v: v["uri_no_privilege"].update(expected={"status":"accepted", "reports":[], "effective":{}}))
    attack("version fallback", lambda d, v: v["changed_exact_version"].update(expected={"status":"accepted", "reports":[], "effective":{}}))
    attack("missing case", lambda d, v: d["vectors"].remove(v["missing_provider"]))
    attack("unlisted case", lambda d, v: d["vectors"].append(copy.deepcopy(v["missing_provider"])))
    attack("mutable closure digest", lambda d, v: d["provider_closure"].update(content_digest="sha256:"+"f"*64))
    attack("core mutation", lambda d, v: v["unhealthy_instance"].update(expected_core_mutations=1))
    attack("public false claim", lambda d, v: d["public_vectors"][0]["expected"]["report"].update(claims=["durable_single_writer"]))
    attack("public self assertion", lambda d, v: d["public_vectors"][3].update(expected={"status":"accepted", "report": d["public_vectors"][3]["untrusted_candidate_report"]}))
    attack("public URI fallback", lambda d, v: d["public_vectors"][9].update(expected={"status":"accepted", "report": d["public_vectors"][0]["expected"]["report"]}))
    attack("skipped health call", lambda d, v: d["public_vectors"][0]["expected_stages"].pop(-2))
    attack("fabricated capabilities", lambda d, v: d["public_vectors"][0]["expected_stages"][-3].update(output=["durable_single_writer"]))
    attack("swapped instance report", lambda d, v: d["public_vectors"][0]["expected"]["report"].update(instance_id="other"))
    attack("descriptor source bytes", lambda d, v: d["public_vectors"][0]["registration_bytes"].append("{}"))
    for label, document in attacks:
        try:
            validate_document(document, args.spec_root, compare_generated=False)
        except ExtensionValidationError:
            continue
        raise AssertionError(f"adversarial {label} swap accepted")
    with tempfile.TemporaryDirectory() as directory:
        profile = Path(directory)
        (profile / "provider").mkdir()
        for source in (PROFILE / "provider").iterdir():
            (profile / "provider" / source.name).write_bytes(source.read_bytes())
        with (profile / "provider/test_provider.py").open("ab") as stream:
            stream.write(b"\n# changed after report\n")
        try:
            validate_document(original, args.spec_root, profile, compare_generated=False)
        except ExtensionValidationError:
            pass
        else:
            raise AssertionError("changed provider closure accepted")
    print(f"rejected {len(attacks) + 1} adversarial extension substitutions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
