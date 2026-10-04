// Native result object is deliberately not part of the portable boundary.
struct NativeReply {
    reference: String,
    accepted: bool,
}

pub fn invoke<F>(scope: &str, effect_id: &str, payload: &str, mut call: F) -> (String, String)
where
    F: FnMut(&str, &str, &str) -> (String, bool),
{
    let (reference, accepted) = call(scope, effect_id, payload);
    let reply = NativeReply { reference, accepted };
    if reply.accepted {
        ("succeeded".into(), reply.reference)
    } else {
        ("ambiguous".into(), "provider_acceptance_unknown".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_call_returns_only_portable_report_fields() {
        let (kind, reference) = invoke("scope", "effect", "payload", |s, e, p| {
            assert_eq!((s, e, p), ("scope", "effect", "payload"));
            ("receipt-1".into(), true)
        });
        assert_eq!((kind.as_str(), reference.as_str()), ("succeeded", "receipt-1"));
    }
}
