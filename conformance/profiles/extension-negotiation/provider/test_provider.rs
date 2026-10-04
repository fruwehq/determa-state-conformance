//! Inert extension negotiation provider, paired with test_provider.py in one closure.
//! The host supplies configuration and verifies each claim against test policy.

#[derive(Clone)]
pub struct Configuration {
    pub instance_id: String,
    pub claims: Vec<String>,
    pub health: String,
}

pub fn validate_configuration(configuration: &Configuration) -> Result<Configuration, &'static str> {
    let mut instance_bytes = configuration.instance_id.bytes();
    let first_valid = instance_bytes.next().is_some_and(|byte| byte.is_ascii_lowercase());
    let rest_valid = instance_bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-');
    if !first_valid || !rest_valid
        || configuration.claims.iter().enumerate().any(|(index, claim)| configuration.claims[..index].contains(claim))
        || configuration.claims.iter().any(|claim| claim != "durable_single_writer")
        || !matches!(configuration.health.as_str(), "healthy" | "degraded" | "unavailable" | "unknown")
    {
        return Err("invalid_extension_configuration");
    }
    Ok(configuration.clone())
}

pub fn capabilities(configured_instance: &Configuration) -> Vec<String> {
    configured_instance.claims.clone()
}

pub fn health(configured_instance: &Configuration) -> String {
    configured_instance.health.clone()
}
