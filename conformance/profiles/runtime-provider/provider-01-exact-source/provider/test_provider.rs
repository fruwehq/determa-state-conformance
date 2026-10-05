// Executable equivalent fixture for Rust hosts. The closure includes this file.
pub struct ExternalReply { pub approved: bool }

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    pub guard_calls: u64,
    pub action_calls: u64,
    pub external_calls: u64,
    pub irreversible_effects: u64,
    pub external_effect_log: Vec<&'static str>,
    pub guard_snapshot: Option<String>,
    pub action_snapshot: Option<String>,
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
    pub fn evaluate_actions_repeated(&mut self, invalid: bool, fail: bool, external_io: bool, repeat_send: bool)
        -> Result<String, &'static str> {
        let output = self.evaluate_actions(invalid, fail, external_io)?;
        if !repeat_send || invalid { return Ok(output); }
        let send = r#"{"send":{"event":"accepted","to":{"external":true},"payload":["map",[]],"correlation_id":["string","provider-correlation"]}}"#;
        Ok(format!(r#"{{"actions":[{{"assign":{{"variable":"accepted","value":["boolean",true]}}}},{send},{send}]}}"#))
    }
    pub fn evaluate_actions_mixed(&mut self, invalid: bool, fail: bool, external_io: bool, mixed_send: bool)
        -> Result<String, &'static str> {
        let output = self.evaluate_actions(invalid, fail, external_io)?;
        if !mixed_send || invalid { return Ok(output); }
        let external = r#"{"send":{"event":"accepted","to":{"external":true},"payload":["map",[]],"correlation_id":["string","provider-correlation"]}}"#;
        let internal = r#"{"send":{"event":"notice","to":{"self":true},"payload":["map",[]]}}"#;
        Ok(format!(r#"{{"actions":[{{"assign":{{"variable":"accepted","value":["boolean",true]}}}},{external},{internal},{external},{internal}]}}"#))
    }
    pub fn evaluate_actions_environment(&mut self, mode: &str) -> Result<String, &'static str> {
        self.evaluate_actions(false, false, false)?;
        let target = match mode {
            "self" => r#""to":{"self":true}"#,
            "unknown_component" => r#""to":{"component":"missing"}"#,
            "multiple" => r#""targets":[{"component":"replica"},{"component":"replica"}]"#,
            _ => r#""to":{"component":"replica"}"#,
        };
        let changed = match mode {
            "empty" => "[]",
            "unknown_variable" => r#"[["missing",["integer","10"]]]"#,
            "wrong_type" => r#"[["limit",["string","10"]]]"#,
            _ => r#"[["limit",["integer","10"]]]"#,
        };
        let correlation = if mode == "correlation" { r#", "correlation_id":["string","forbidden"]"# } else { "" };
        Ok(r#"{"actions":[{"assign":{"variable":"accepted","value":["boolean",true]}},{"send":{"event":"env",TARGET,"payload":["map",[["changed",["map",CHANGED]]]]CORRELATION}}]}"#
            .replace("TARGET", target).replace("CHANGED", changed).replace("CORRELATION", correlation))
    }
    pub fn evaluate_guard_snapshot(&mut self, snapshot: &str, approved: bool, override_value: Option<bool>, external_io: bool, fail: bool)
        -> Result<bool, &'static str> {
        self.guard_snapshot = Some(snapshot.into());
        self.evaluate_guard(approved, override_value, external_io, fail)
    }
    pub fn evaluate_actions_snapshot(&mut self, snapshot: &str, invalid: bool, fail: bool, external_io: bool, repeat_send: bool)
        -> Result<String, &'static str> {
        self.action_snapshot = Some(snapshot.into());
        self.evaluate_actions_repeated(invalid, fail, external_io, repeat_send)
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
