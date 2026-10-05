"""Executable provider fixture. The host must bind these exact source bytes."""

def portable_copy(value):
    if isinstance(value, (list, tuple)):
        return [portable_copy(item) for item in value]
    if hasattr(value, "items"):
        return {name: portable_copy(item) for name, item in value.items()}
    return value


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
        self.guard_snapshot = None
        self.action_snapshot = None

    def evaluate_guard(self, snapshot, *, external_io=False, fail=False, guard_override=None):
        self.guard_snapshot = portable_copy(snapshot)
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

    def evaluate_actions(self, snapshot, *, invalid=False, fail=False, external_io=False, repeat_send=False, mixed_send=False, environment_send=None):
        self.action_snapshot = portable_copy(snapshot)
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
        output = {"actions": [
            {"assign": {"variable": "accepted", "value": ["boolean", True]}},
            {"send": {"event": "accepted", "to": {"external": True},
                      "payload": ["map", []],
                      "correlation_id": ["string", "provider-correlation"]}},
        ]}
        if environment_send is not None:
            send = {"event": "env", "to": {"component": "replica"},
                    "payload": ["map", [["changed", ["map", [["limit", ["integer", "10"]]]]]]]}
            if environment_send == "self":
                send["to"] = {"self": True}
            elif environment_send == "unknown_component":
                send["to"] = {"component": "missing"}
            elif environment_send == "multiple":
                del send["to"]
                send["targets"] = [{"component": "replica"}, {"component": "replica"}]
            elif environment_send == "correlation":
                send["correlation_id"] = ["string", "forbidden"]
            elif environment_send == "empty":
                send["payload"] = ["map", [["changed", ["map", []]]]]
            elif environment_send == "unknown_variable":
                send["payload"] = ["map", [["changed", ["map", [["missing", ["integer", "10"]]]]]]]
            elif environment_send == "wrong_type":
                send["payload"] = ["map", [["changed", ["map", [["limit", ["string", "10"]]]]]]]
            output["actions"][1] = {"send": send}
            return output
        if mixed_send:
            internal = {"send": {"event": "notice", "to": {"self": True}, "payload": ["map", []]}}
            output["actions"].extend([internal, output["actions"][1].copy(), internal.copy()])
        elif repeat_send:
            output["actions"].append(output["actions"][1].copy())
        return output

    def inspect_guard(self, snapshot, maximum_guard_evaluations, maximum_evaluation_steps):
        if maximum_guard_evaluations < 1 or maximum_evaluation_steps < 2:
            raise ValueError("inspection_limit_exceeded")
        approved = dict(snapshot["event"]["payload"][1])["approved"][1]
        return bool(approved), 1, 2


def compile_region(source):
    if source != "event.payload.approved":
        raise ValueError("language_compilation_failed")
    return source
