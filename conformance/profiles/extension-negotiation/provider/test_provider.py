"""Inert conformance provider. The source closure contains this file and test_provider.rs.

The harness loads this exact file through its public registration/injection path.
Host policy supplies the descriptor, configuration and topology; this file does not
claim that its own statements prove a production guarantee.
"""


def validate_configuration(configuration):
    if set(configuration) != {"instance_id", "claims", "health"}:
        raise ValueError("invalid_extension_configuration")
    if not isinstance(configuration["instance_id"], str):
        raise ValueError("invalid_extension_configuration")
    if not isinstance(configuration["claims"], list) or not all(
        isinstance(claim, str) for claim in configuration["claims"]
    ):
        raise ValueError("invalid_extension_configuration")
    if configuration["health"] not in ("healthy", "degraded", "unavailable", "unknown"):
        raise ValueError("invalid_extension_configuration")
    return dict(configuration)


def capabilities(configured_instance):
    return list(configured_instance["claims"])


def health(configured_instance):
    return configured_instance["health"]
