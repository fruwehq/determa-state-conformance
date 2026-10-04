"""Executable provider fixture. The host must bind these exact source bytes."""

class ExternalReply:
    """An SDK-style object which never crosses the engine boundary."""
    def __init__(self, approved):
        self.approved = approved


class Provider:
    def __init__(self):
        self.guard_calls = 0
        self.action_calls = 0
        self.external_calls = 0
        self.irreversible_effects = 0
        self.external_effect_log = []

    def evaluate_guard(self, snapshot, *, external_io=False, fail=False, guard_override=None):
        self.guard_calls += 1
        if external_io:
            self.external_calls += 1
            self.irreversible_effects += 1
            self.external_effect_log.append({"effect_id": "fixture-io-1", "kind": "external_write",
                                             "phase": "before_commit"})
        if fail:
            raise ValueError("guard_fault")
        approved = dict(snapshot["event"]["payload"][1])["approved"][1]
        reply = ExternalReply(approved)
        return bool(reply.approved if guard_override is None else guard_override)

    def evaluate_actions(self, snapshot, *, invalid=False, fail=False, external_io=False):
        self.action_calls += 1
        if external_io:
            self.external_calls += 1
            self.irreversible_effects += 1
            self.external_effect_log.append({"effect_id": "fixture-io-1", "kind": "external_write",
                                             "phase": "before_commit"})
        if fail:
            raise ValueError("action_fault")
        if invalid:
            return {"actions": [
                {"assign": {"variable": "accepted", "value": ["boolean", True]}},
                {"stop": {}},
            ]}
        return {"actions": [
            {"assign": {"variable": "accepted", "value": ["boolean", True]}},
            {"send": {"event": "accepted", "to": {"external": True},
                      "payload": ["map", []],
                      "correlation_id": ["string", "provider-correlation"]}},
        ]}

    def inspect_guard(self, snapshot, maximum_guard_evaluations, maximum_evaluation_steps):
        if maximum_guard_evaluations < 1 or maximum_evaluation_steps < 2:
            raise ValueError("inspection_limit_exceeded")
        approved = dict(snapshot["event"]["payload"][1])["approved"][1]
        return bool(approved), 1, 2


def compile_region(source):
    if source != "event.payload.approved":
        raise ValueError("language_compilation_failed")
    return source
