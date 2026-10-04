"""Inert conformance provider. The source closure contains this file and test_provider.rs.

The harness loads this exact file through its public registration/injection path.
Host policy supplies the descriptor, configuration and topology; this file does not
claim that its own statements prove a production guarantee.
"""

import re


INSTANCE_ID = re.compile(r"^[a-z][a-z0-9.-]*$")


def validate_configuration(configuration):
    if not isinstance(configuration, dict):
        raise ValueError("invalid_extension_configuration")
    if set(configuration) != {"instance_id", "claims", "health"}:
        raise ValueError("invalid_extension_configuration")
    if type(configuration["instance_id"]) is not str or not INSTANCE_ID.fullmatch(configuration["instance_id"]):
        raise ValueError("invalid_extension_configuration")
    if type(configuration["claims"]) is not list or not all(type(claim) is str for claim in configuration["claims"]):
        raise ValueError("invalid_extension_configuration")
    if len(configuration["claims"]) != len(set(configuration["claims"])):
        raise ValueError("invalid_extension_configuration")
    if type(configuration["health"]) is not str or configuration["health"] not in ("healthy", "degraded", "unavailable", "unknown"):
        raise ValueError("invalid_extension_configuration")
    return dict(configuration)


def capabilities(configured_instance):
    return list(configured_instance["claims"])


def health(configured_instance):
    return configured_instance["health"]
