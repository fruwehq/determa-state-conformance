// Executable equivalent fixture for Rust hosts. The closure includes this file.
pub struct ExternalReply { pub approved: bool }

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    pub guard_calls: u64,
    pub action_calls: u64,
    pub external_calls: u64,
    pub irreversible_effects: u64,
    pub external_effect_log: Vec<&'static str>,
}

impl Provider {
    pub fn evaluate_guard(&mut self, approved: bool, override_value: Option<bool>, external_io: bool, fail: bool)
        -> Result<bool, &'static str> {
        self.guard_calls += 1;
        if external_io { self.external_calls += 1; self.irreversible_effects += 1; self.external_effect_log.push("fixture-io-1:external_write:before_commit"); }
        if fail { return Err("guard_fault"); }
        Ok(override_value.unwrap_or(ExternalReply { approved }.approved))
    }
    pub fn evaluate_actions(&mut self, invalid: bool, fail: bool, external_io: bool)
        -> Result<String, &'static str> {
        self.action_calls += 1;
        if external_io { self.external_calls += 1; self.irreversible_effects += 1; self.external_effect_log.push("fixture-io-1:external_write:before_commit"); }
        if fail { return Err("action_fault"); }
        if invalid { return Ok("{\"actions\":[{\"assign\":{\"variable\":\"accepted\",\"value\":[\"boolean\",true]}},{\"stop\":{}}]}".into()); }
        Ok("{\"actions\":[{\"assign\":{\"variable\":\"accepted\",\"value\":[\"boolean\",true]}},{\"send\":{\"event\":\"accepted\",\"to\":{\"external\":true},\"payload\":[\"map\",[]],\"correlation_id\":[\"string\",\"provider-correlation\"]}}]}".into())
    }
    pub fn inspect_guard(&self, approved: bool, guards: u64, steps: u64)
        -> Result<(bool,u64,u64), &'static str> {
        if guards < 1 || steps < 2 { return Err("inspection_limit_exceeded"); }
        Ok((approved,1,2))
    }
}

pub fn compile_region(source: &str) -> Result<&str, &'static str> {
    if source != "event.payload.approved" { return Err("language_compilation_failed"); }
    Ok(source)
}
