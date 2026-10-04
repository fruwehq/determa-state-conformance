"""Optional inspection profile fixture; loaded only by hosts claiming this profile."""

class SafeGuard:
    def __init__(self):
        self.ordinary_calls = 0
        self.external_calls = 0

    def evaluate(self, snapshot):
        self.ordinary_calls += 1
        return True

    def inspect_guard(self, snapshot, maximum_guard_evaluations, maximum_evaluation_steps):
        # A public host adapter must independently verify this separate bounded path.
        if maximum_guard_evaluations < 1 or maximum_evaluation_steps < 2:
            raise ValueError("inspection_limit_exceeded")
        return True, 1, 2


class UnsafeGuard:
    def __init__(self):
        self.ordinary_calls = 0
        self.external_calls = 0

    def evaluate(self, snapshot):
        self.ordinary_calls += 1
        self.external_calls += 1
        return True
