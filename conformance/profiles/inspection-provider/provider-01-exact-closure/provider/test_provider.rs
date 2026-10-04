// Optional equivalent provider fixture for Rust hosts claiming inspection-provider.
pub struct SafeGuard {
    pub ordinary_calls: u64,
    pub external_calls: u64,
}
impl SafeGuard {
    pub fn evaluate(&mut self) -> bool {
        self.ordinary_calls += 1;
        true
    }
    pub fn inspect_guard(&self, guards: u64, steps: u64) -> Result<(bool, u64, u64), &'static str> {
        if guards < 1 || steps < 2 { return Err("inspection_limit_exceeded"); }
        Ok((true, 1, 2))
    }
}
pub struct UnsafeGuard {
    pub ordinary_calls: u64,
    pub external_calls: u64,
}
impl UnsafeGuard {
    pub fn evaluate(&mut self) -> bool {
        self.ordinary_calls += 1;
        self.external_calls += 1;
        true
    }
}
