//! Memory-only Task6 monitor activation.
//!
//! A fresh daemon starts off. Only a short-lived value returned by the
//! authenticated TrackAI endpoint can select monitor mode. Any missing,
//! malformed, expired, or failed refresh returns the cache to off.

use crate::api::client::ApiContext;
use crate::daemon::control_api::{ControlRequest, ControlResponse, SecurityFindingCandidate};
use crate::error::GitAiError;
use crate::metrics::delivery::{
    EvidenceDeliveryBinding, MetricDeliveryHealthBinding, MetricDeliveryRuntime,
};
use crate::security::delivery_queue::SecurityFindingQueue;
use crate::security::{
    ExecutionContext, FindingOperatingSystem, FindingUploadContext, MonitorMode, SafeFinding,
    SecurityFindingUploadBatch, ShellDialect, evaluate_command,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};
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

pub fn configured_security_monitor_mode_for_repository(
    repository_url: &str,
    now: i64,
) -> MonitorMode {
    configured_security_activations()
        .read()
        .map_or(MonitorMode::Off, |registry| {
            registry.mode_for_repository(repository_url, now)
        })
}

pub fn query_daemon_security_monitor_mode(repository_url: &str) -> MonitorMode {
    query_daemon_security_monitor_mode_with(repository_url, |request| {
        crate::daemon::telemetry_handle::send_via_daemon(&request)
    })
}

pub fn query_daemon_security_monitor_mode_with<Send>(
    repository_url: &str,
    send: Send,
) -> MonitorMode
where
    Send: FnOnce(ControlRequest) -> Result<ControlResponse, String>,
{
    let request = ControlRequest::SecurityActivationQuery {
        repository_url: repository_url.to_string(),
    };
    let Ok(response) = send(request) else {
        return MonitorMode::Off;
    };
    if !response.ok {
        return MonitorMode::Off;
    }
    match response
        .data
        .as_ref()
        .and_then(|data| data.get("mode"))
        .and_then(|mode| mode.as_str())
    {
        Some("monitor") => MonitorMode::Monitor,
        _ => MonitorMode::Off,
    }
}

pub fn evaluate_activated_command_with<Query>(
    repository_url: &str,
    session_id: &str,
    source_event_id: &str,
    command: &str,
    occurred_at: i64,
    query_mode: Query,
) -> Option<ControlRequest>
where
    Query: FnOnce(&str) -> MonitorMode,
{
    let repository_url = crate::repo_url::normalize_repo_url(repository_url).ok()?;
    if !bounded_identity(session_id) || !bounded_identity(source_event_id) {
        return None;
    }
    let mode = query_mode(&repository_url);
    let finding = evaluate_command(
        mode,
        host_shell_dialect(),
        ExecutionContext::ParsedCommand,
        command,
    )
    .finding?;
    let occurred_at = DateTime::<Utc>::from_timestamp(occurred_at, 0)?
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    Some(ControlRequest::SubmitSecurityFinding {
        candidate: SecurityFindingCandidate {
            repository_url,
            session_id: session_id.to_string(),
            source_event_id: source_event_id.to_string(),
            rule_id: finding.rule_id.to_string(),
            rule_version: finding.rule_version.to_string(),
            severity: finding.severity.to_string(),
            operating_system: host_operating_system().to_string(),
            occurred_at,
        },
    })
}

fn bounded_identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
}

fn host_shell_dialect() -> ShellDialect {
    #[cfg(windows)]
    {
        ShellDialect::Unavailable
    }
    #[cfg(not(windows))]
    {
        ShellDialect::Posix
    }
}

fn host_operating_system() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(target_os = "linux")]
    {
        "linux"
    }
    #[cfg(windows)]
    {
        "windows"
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        "unavailable"
    }
}

pub fn project_security_finding_candidate(
    candidate: &SecurityFindingCandidate,
    binding: &EvidenceDeliveryBinding,
) -> Result<SecurityFindingUploadBatch, GitAiError> {
    let candidate_repository = crate::repo_url::normalize_repo_url(&candidate.repository_url)
        .map_err(|_| invalid_candidate())?;
    if candidate_repository != binding.repository_url
        || !bounded_identity(&candidate.session_id)
        || !bounded_identity(&candidate.source_event_id)
    {
        return Err(invalid_candidate());
    }
    let finding = approved_safe_finding(candidate).ok_or_else(invalid_candidate)?;
    let operating_system = match candidate.operating_system.as_str() {
        "macos" => FindingOperatingSystem::Macos,
        "linux" => FindingOperatingSystem::Linux,
        "windows" => FindingOperatingSystem::Windows,
        "wsl" => FindingOperatingSystem::Wsl,
        _ => return Err(invalid_candidate()),
    };
    let occurred_at = DateTime::parse_from_rfc3339(&candidate.occurred_at)
        .map_err(|_| invalid_candidate())?
        .with_timezone(&Utc)
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let stable_id = stable_candidate_id(candidate, &candidate_repository);

    SecurityFindingUploadBatch::from_safe_finding(
        finding,
        FindingUploadContext {
            finding_id: format!("task6-f-{stable_id}"),
            delivery_id: format!("task6-d-{stable_id}"),
            repository_id: binding.repository_id.clone(),
            session_id: candidate.session_id.clone(),
            source_event_id: candidate.source_event_id.clone(),
            correlation_id: None,
            operating_system,
            occurred_at,
            client_version: env!("CARGO_PKG_VERSION").to_string(),
            rule_pack_version: "task6-rules/0.1".to_string(),
        },
    )
    .map_err(|_| invalid_candidate())
}

pub fn admit_security_finding_candidate_with<Mode, Resolve, Enqueue>(
    candidate: &SecurityFindingCandidate,
    now: u64,
    mode_for_repository: Mode,
    resolve_binding: Resolve,
    enqueue: Enqueue,
) -> Result<(), GitAiError>
where
    Mode: FnOnce(&str, i64) -> MonitorMode,
    Resolve: FnOnce(&str) -> Result<EvidenceDeliveryBinding, GitAiError>,
    Enqueue: FnOnce(
        &SecurityFindingUploadBatch,
        &EvidenceDeliveryBinding,
        u64,
    ) -> Result<(), GitAiError>,
{
    if mode_for_repository(&candidate.repository_url, now as i64) != MonitorMode::Monitor {
        return Err(GitAiError::Generic(
            "security monitoring is not active".to_string(),
        ));
    }
    let binding = resolve_binding(&candidate.repository_url)?;
    let batch = project_security_finding_candidate(candidate, &binding)?;
    enqueue(&batch, &binding, now)
}

pub fn enqueue_configured_security_finding(
    candidate: &SecurityFindingCandidate,
    now: u64,
) -> Result<(), GitAiError> {
    if configured_security_monitor_mode_for_repository(&candidate.repository_url, now as i64)
        != MonitorMode::Monitor
    {
        return Err(GitAiError::Generic(
            "security monitoring is not active".to_string(),
        ));
    }
    let runtime = MetricDeliveryRuntime::load_optional_default()
        .map_err(|_| {
            GitAiError::Generic("security delivery configuration unavailable".to_string())
        })?
        .ok_or_else(|| {
            GitAiError::Generic("security delivery configuration unavailable".to_string())
        })?;
    let binding = runtime
        .bind_evidence_repository(&candidate.repository_url)
        .map_err(|_| GitAiError::Generic("security repository binding unavailable".to_string()))?;
    let batch = project_security_finding_candidate(candidate, &binding)?;
    let daemon_config = crate::daemon::DaemonConfig::from_env_or_default_paths()?;
    std::fs::create_dir_all(&daemon_config.internal_dir)?;
    let queue_path = daemon_config.internal_dir.join("security-findings.db");
    let mut queue = SecurityFindingQueue::open_at_path(&queue_path)?;
    queue.enqueue(&batch, &binding, now).map(|_| ())
}

fn approved_safe_finding(candidate: &SecurityFindingCandidate) -> Option<SafeFinding> {
    match (
        candidate.rule_id.as_str(),
        candidate.rule_version.as_str(),
        candidate.severity.as_str(),
    ) {
        ("trackai.exec.destructive_recursive_delete", "1.5", "critical") => Some(SafeFinding {
            rule_id: "trackai.exec.destructive_recursive_delete",
            rule_version: "1.5",
            severity: "critical",
            alert_title: "Large deletion requested",
            effect: "monitor",
            phase: "requested",
        }),
        ("trackai.exec.download_pipe_shell", "1.4", "high") => Some(SafeFinding {
            rule_id: "trackai.exec.download_pipe_shell",
            rule_version: "1.4",
            severity: "high",
            alert_title: "Downloaded content requested for immediate execution",
            effect: "monitor",
            phase: "requested",
        }),
        ("trackai.exec.reverse_shell", "1.3", "high") => Some(SafeFinding {
            rule_id: "trackai.exec.reverse_shell",
            rule_version: "1.3",
            severity: "high",
            alert_title: "Remote command channel requested",
            effect: "monitor",
            phase: "requested",
        }),
        _ => None,
    }
}

fn stable_candidate_id(candidate: &SecurityFindingCandidate, repository_url: &str) -> String {
    let mut digest = Sha256::new();
    for value in [
        repository_url,
        candidate.session_id.as_str(),
        candidate.source_event_id.as_str(),
        candidate.rule_id.as_str(),
        candidate.rule_version.as_str(),
        candidate.occurred_at.as_str(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    format!("{:x}", digest.finalize())[..32].to_string()
}

fn invalid_candidate() -> GitAiError {
    GitAiError::Generic("security finding candidate was invalid".to_string())
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
    let repository_bindings = runtime.security_activation_bindings();
    let due = match registry.write() {
        Ok(mut registry) => {
            registry.replace_repository_bindings(repository_bindings);
            registry.prepare_refresh(bindings, now)
        }
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
