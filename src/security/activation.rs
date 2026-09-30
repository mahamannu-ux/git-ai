//! Memory-only Task6 monitor activation.
//!
//! A fresh daemon starts off. Only a short-lived value returned by the
//! authenticated TrackAI endpoint can select monitor mode. Any missing,
//! malformed, expired, or failed refresh returns the cache to off.

use crate::api::client::ApiContext;
use crate::error::GitAiError;
use crate::metrics::delivery::{MetricDeliveryHealthBinding, MetricDeliveryRuntime};
use crate::security::MonitorMode;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{OnceLock, RwLock};

const ACTIVATION_SCHEMA: &str = "trackai.security-activation/0.1";
const MAX_LEASE_SECONDS: i64 = 300;
const MAX_CLOCK_SKEW_SECONDS: i64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ActivationMode {
    Off,
    Monitor,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SecurityActivationWire {
    schema_version: String,
    mode: ActivationMode,
    version: u64,
    issued_at: String,
    refresh_after: String,
    expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityActivationLease {
    mode: ActivationMode,
    version: u64,
    issued_at: DateTime<Utc>,
    refresh_after: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl SecurityActivationLease {
    fn from_json(raw: &str) -> Result<Self, GitAiError> {
        let wire: SecurityActivationWire =
            serde_json::from_str(raw).map_err(|_| invalid_activation())?;
        if wire.schema_version != ACTIVATION_SCHEMA
            || (wire.mode == ActivationMode::Monitor && wire.version == 0)
        {
            return Err(invalid_activation());
        }
        let issued_at = parse_timestamp(&wire.issued_at)?;
        let refresh_after = parse_timestamp(&wire.refresh_after)?;
        let expires_at = parse_timestamp(&wire.expires_at)?;
        let lifetime = expires_at.signed_duration_since(issued_at).num_seconds();
        if refresh_after < issued_at
            || refresh_after > expires_at
            || lifetime <= 0
            || lifetime > MAX_LEASE_SECONDS
        {
            return Err(invalid_activation());
        }
        Ok(Self {
            mode: wire.mode,
            version: wire.version,
            issued_at,
            refresh_after,
            expires_at,
        })
    }

    fn is_fresh_at(&self, now: i64) -> bool {
        self.issued_at.timestamp() <= now + MAX_CLOCK_SKEW_SECONDS
            && self.expires_at.timestamp() > now
    }

    pub fn version(&self) -> u64 {
        self.version
    }
}

#[derive(Debug, Default)]
pub struct SecurityActivationCache {
    lease: Option<SecurityActivationLease>,
}

impl SecurityActivationCache {
    pub fn mode_at(&self, now: i64) -> MonitorMode {
        match self.lease.as_ref() {
            Some(lease) if lease.is_fresh_at(now) && lease.mode == ActivationMode::Monitor => {
                MonitorMode::Monitor
            }
            _ => MonitorMode::Off,
        }
    }

    pub fn replace_from_json(&mut self, raw: &str, now: i64) -> Result<(), GitAiError> {
        let lease = SecurityActivationLease::from_json(raw)?;
        self.replace(lease, now)
    }

    fn replace(&mut self, lease: SecurityActivationLease, now: i64) -> Result<(), GitAiError> {
        if !lease.is_fresh_at(now) {
            self.lease = None;
            return Err(invalid_activation());
        }
        self.lease = Some(lease);
        Ok(())
    }

    fn clear(&mut self) {
        self.lease = None;
    }

    fn refresh_due_at(&self, now: i64) -> bool {
        self.lease
            .as_ref()
            .is_none_or(|lease| !lease.is_fresh_at(now) || lease.refresh_after.timestamp() <= now)
    }
}

type ActivationRouteKey = (String, String, String);

#[derive(Debug, Default)]
pub struct SecurityActivationRegistry {
    routes: BTreeMap<ActivationRouteKey, SecurityActivationCache>,
    repositories: BTreeMap<String, ActivationRouteKey>,
}

impl SecurityActivationRegistry {
    pub fn mode_for(&self, binding: &MetricDeliveryHealthBinding, now: i64) -> MonitorMode {
        self.routes
            .get(&activation_route_key(binding))
            .map_or(MonitorMode::Off, |cache| cache.mode_at(now))
    }

    pub fn mode_for_repository(&self, repository_url: &str, now: i64) -> MonitorMode {
        let Ok(repository_url) = crate::repo_url::normalize_repo_url(repository_url) else {
            return MonitorMode::Off;
        };
        self.repositories
            .get(&repository_url)
            .and_then(|key| self.routes.get(key))
            .map_or(MonitorMode::Off, |cache| cache.mode_at(now))
    }

    pub fn replace_repository_bindings(
        &mut self,
        bindings: impl IntoIterator<Item = (String, MetricDeliveryHealthBinding)>,
    ) {
        self.repositories = bindings
            .into_iter()
            .filter_map(|(repository_url, binding)| {
                crate::repo_url::normalize_repo_url(&repository_url)
                    .ok()
                    .map(|repository_url| (repository_url, activation_route_key(&binding)))
            })
            .collect();
    }

    pub fn refresh_due_for(&self, binding: &MetricDeliveryHealthBinding, now: i64) -> bool {
        self.routes
            .get(&activation_route_key(binding))
            .is_none_or(|cache| cache.refresh_due_at(now))
    }

    pub fn replace_from_json(
        &mut self,
        binding: &MetricDeliveryHealthBinding,
        raw: &str,
        now: i64,
    ) -> Result<(), GitAiError> {
        let key = activation_route_key(binding);
        let cache = self.routes.entry(key).or_default();
        cache.clear();
        cache.replace_from_json(raw, now)
    }

    pub fn retain_routes<'a>(
        &mut self,
        bindings: impl IntoIterator<Item = &'a MetricDeliveryHealthBinding>,
    ) {
        let retained = bindings
            .into_iter()
            .map(activation_route_key)
            .collect::<BTreeSet<_>>();
        self.routes.retain(|key, _| retained.contains(key));
        self.repositories.retain(|_, key| retained.contains(key));
    }

    pub fn prepare_refresh(
        &mut self,
        bindings: impl IntoIterator<Item = MetricDeliveryHealthBinding>,
        now: i64,
    ) -> Vec<MetricDeliveryHealthBinding> {
        let bindings = bindings.into_iter().collect::<Vec<_>>();
        self.retain_routes(bindings.iter());
        let due = bindings
            .into_iter()
            .filter(|binding| self.refresh_due_for(binding, now))
            .collect::<Vec<_>>();
        for binding in &due {
            self.routes.remove(&activation_route_key(binding));
        }
        due
    }

    fn replace(
        &mut self,
        binding: &MetricDeliveryHealthBinding,
        lease: SecurityActivationLease,
        now: i64,
    ) -> Result<(), GitAiError> {
        let cache = self
            .routes
            .entry(activation_route_key(binding))
            .or_default();
        cache.replace(lease, now)
    }

    fn clear(&mut self) {
        self.routes.clear();
        self.repositories.clear();
    }
}

static CONFIGURED_SECURITY_ACTIVATIONS: OnceLock<RwLock<SecurityActivationRegistry>> =
    OnceLock::new();

fn configured_security_activations() -> &'static RwLock<SecurityActivationRegistry> {
    CONFIGURED_SECURITY_ACTIVATIONS
        .get_or_init(|| RwLock::new(SecurityActivationRegistry::default()))
}

pub fn configured_security_monitor_mode(
    binding: &MetricDeliveryHealthBinding,
    now: i64,
) -> MonitorMode {
    configured_security_activations()
        .read()
        .map_or(MonitorMode::Off, |registry| registry.mode_for(binding, now))
}

pub fn refresh_configured_security_activations() {
    let registry = configured_security_activations();
    match MetricDeliveryRuntime::load_optional_default() {
        Ok(Some(runtime)) => {
            refresh_security_activations(registry, &runtime, Utc::now().timestamp());
        }
        Ok(None) | Err(_) => {
            if let Ok(mut registry) = registry.write() {
                registry.clear();
            }
        }
    }
}

fn activation_route_key(binding: &MetricDeliveryHealthBinding) -> ActivationRouteKey {
    (
        binding.tenant_id.clone(),
        binding.api_base_url.clone(),
        binding.credential_key_id.clone(),
    )
}

pub fn fetch_security_activation(
    context: &ApiContext,
) -> Result<SecurityActivationLease, GitAiError> {
    let response = context.get("/worker/security/activation")?;
    if response.status_code != 200 {
        return Err(GitAiError::Generic(format!(
            "security activation returned HTTP {}",
            response.status_code
        )));
    }
    let body = response.as_str().map_err(|_| invalid_activation())?;
    SecurityActivationLease::from_json(body)
}

pub fn refresh_security_activation_with<Fetch>(
    cache: &mut SecurityActivationCache,
    now: i64,
    fetch: Fetch,
) -> Result<(), GitAiError>
where
    Fetch: FnOnce() -> Result<SecurityActivationLease, GitAiError>,
{
    cache.clear();
    let lease = fetch()?;
    cache.replace(lease, now)
}

pub fn refresh_security_activations(
    registry: &RwLock<SecurityActivationRegistry>,
    runtime: &MetricDeliveryRuntime,
    now: i64,
) {
    let bindings = runtime.health_bindings();
    let due = match registry.write() {
        Ok(mut registry) => registry.prepare_refresh(bindings, now),
        Err(_) => return,
    };

    for binding in due {
        let Ok(credential) = runtime.credential_for_health_binding(&binding) else {
            continue;
        };
        let context = ApiContext {
            base_url: binding.api_base_url.clone(),
            auth_token: None,
            api_key: Some(credential.to_string()),
            author_identity: None,
            timeout_secs: Some(5),
        };
        let Ok(lease) = fetch_security_activation(&context) else {
            continue;
        };
        if let Ok(mut registry) = registry.write() {
            let _ = registry.replace(&binding, lease, now);
        }
    }
}

fn parse_timestamp(raw: &str) -> Result<DateTime<Utc>, GitAiError> {
    DateTime::parse_from_rfc3339(raw)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| invalid_activation())
}

fn invalid_activation() -> GitAiError {
    GitAiError::Generic("security activation response was invalid".to_string())
}
