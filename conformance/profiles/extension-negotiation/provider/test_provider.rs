//! Inert extension negotiation provider, paired with test_provider.py in one closure.
//! The host supplies configuration and verifies each claim against test policy.

#[derive(Clone)]
pub struct Configuration {
    pub instance_id: String,
    pub claims: Vec<String>,
    pub health: String,
}

pub fn validate_configuration(configuration: &Configuration) -> Result<Configuration, &'static str> {
    if configuration.instance_id.is_empty()
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
