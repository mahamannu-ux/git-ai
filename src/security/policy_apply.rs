//! Fetch, verify, stage and acknowledge signed Endpoint security policy.

use crate::error::GitAiError;
use crate::security::lease_state::{
    AcceptedLease, DurableSecurityState, LeaseMode, LeaseStateStore, PersistedAcknowledgement,
};
use crate::security::records::SecurityDataSettings;
use crate::trust::documents::decode_base64_strict;
use crate::trust::{
    ArtifactPurpose, DsseEnvelope, PLATFORM_SCOPE, TrustState, TrustStatus, TrustVerdict,
    VerifyTrustedInput, verify_trusted,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

pub const LEASE_PAYLOAD_TYPE: &str = "application/vnd.trackai.security-activation-lease+json";
pub const BUNDLE_PAYLOAD_TYPE: &str = "application/vnd.trackai.security-rule-bundle+json";
pub const SECURITY_STATE_DIR: &str = "security";
const MAX_SIGNED_BYTES: usize = 4 * 1024 * 1024 + 1024;
const PINNED_ROOT_KEYIDS: &[&str] = &[];
const SOURCE_AGENTS: &[&str] = &[
    "claude-code",
    "cowork",
    "codex",
    "gemini-cli",
    "cursor",
    "windsurf",
    "copilot",
    "vscode",
    "opencode",
    "openclaw",
    "antigravity",
    "factory",
    "grok",
    "devin-cli",
    "hermes",
    "kimi-code",
    "pi",
    "qwen-code",
    "cline",
    "amp",
    "auggie",
    "kiro",
    "goose",
    "kilo",
    "openhands",
    "crush",
    "junie",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RefusalCode {
    SignatureRejected,
    VerificationUnavailable,
    LeaseExpired,
    MachineMismatch,
    TenantMismatch,
    EpochRegression,
    BundleDigestMismatch,
    RulesCheckFailed,
    UnsupportedSchema,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    Applied {
        lease_id: String,
        epoch: Option<u64>,
    },
    Refused {
        lease_id: Option<String>,
        code: RefusalCode,
    },
    NoChange,
    Retry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyIdentity {
    pub tenant_id: String,
    /// Optional only on first use. A verified credential-bound lease pins it durably.
    pub machine_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

pub trait PolicyHttp: Send + Sync {
    fn get(&self, path: &str) -> Result<HttpResponse, GitAiError>;
    fn post_json(&self, path: &str, body: &Value) -> Result<HttpResponse, GitAiError>;
}

struct ManagedPolicyHttp {
    base_url: String,
    credential: String,
}

impl PolicyHttp for ManagedPolicyHttp {
    fn get(&self, path: &str) -> Result<HttpResponse, GitAiError> {
        let url = format!("{}{}", self.base_url.trim_end_matches('/'), path);
        let (_agent, request) = crate::api::client::ApiContext::http_get(&url, Some(30));
        let response = request
            .header("X-API-Key", &self.credential)
            .call()
            .map_err(|error| {
                GitAiError::Generic(format!("security policy fetch failed: {error}"))
            })?;
        response_bytes(response)
    }

    fn post_json(&self, path: &str, body: &Value) -> Result<HttpResponse, GitAiError> {
        let url = format!("{}{}", self.base_url.trim_end_matches('/'), path);
        let body = serde_json::to_string(body)?;
        let (_agent, request) = crate::api::client::ApiContext::http_post(&url, Some(30));
        let response = request
            .header("Content-Type", "application/json")
            .header("X-API-Key", &self.credential)
            .send(&body)
            .map_err(|error| {
                GitAiError::Generic(format!("security acknowledgement failed: {error}"))
            })?;
        response_bytes(response)
    }
}

fn response_bytes(response: ureq::http::Response<ureq::Body>) -> Result<HttpResponse, GitAiError> {
    let status = response.status().as_u16();
    let mut body = response.into_body();
    let body = body.read_to_vec().map_err(|error| {
        GitAiError::Generic(format!("security policy response failed: {error}"))
    })?;
    Ok(HttpResponse { status, body })
}

/// Refresh at most hourly, or immediately when fleet v3 names a new lease.
pub fn refresh_configured_security_policy(
    now: DateTime<Utc>,
) -> Result<RefreshOutcome, GitAiError> {
    static REFRESH: Mutex<(i64, Option<String>)> = Mutex::new((0, None));
    let Some(runtime) = crate::metrics::delivery::MetricDeliveryRuntime::load_optional_default()
        .map_err(|error| GitAiError::Generic(error.to_string()))?
    else {
        return Ok(RefreshOutcome::NoChange);
    };
    let binding = runtime
        .fleet_binding()
        .map_err(|error| GitAiError::Generic(error.to_string()))?;
    let credential = runtime
        .credential_for_health_binding(&binding)
        .map_err(|error| GitAiError::Generic(error.to_string()))?;
    let hint = crate::fleet::default_state_path()
        .and_then(|path| crate::fleet::load_state(&path).ok())
        .and_then(|state| state.active)
        .and_then(|active| active.envelope.security_lease().cloned());
    let hint_id = hint.as_ref().map(|lease| lease.lease_id.clone());
    {
        let guard = REFRESH
            .lock()
            .map_err(|_| GitAiError::Generic("security refresh lock poisoned".into()))?;
        if guard.1 == hint_id && now.timestamp() < guard.0 {
            return Ok(RefreshOutcome::NoChange);
        }
    }
    let state_dir = crate::config::internal_dir_path()
        .ok_or_else(|| GitAiError::Generic("security state directory unavailable".into()))?
        .join(SECURITY_STATE_DIR);
    let http = ManagedPolicyHttp {
        base_url: binding.api_base_url,
        credential,
    };
    let verifier = FileTrustVerifier::new(state_dir.clone());
    #[cfg(debug_assertions)]
    let checker = NumbatRulesChecker::debug_with_path_fallback();
    #[cfg(not(debug_assertions))]
    let checker = NumbatRulesChecker::installed();
    let outcome = PolicyApplier {
        state_dir,
        identity: PolicyIdentity {
            tenant_id: binding.tenant_id,
            machine_id: None,
        },
        state: crate::security::activation::configured_lease_context(),
        http: &http,
        verifier: &verifier,
        checker: &checker,
        lease_hint: hint,
    }
    .refresh(now)?;
    let retry_seconds = if outcome == RefreshOutcome::Retry {
        60
    } else {
        3_600
    };
    *REFRESH
        .lock()
        .map_err(|_| GitAiError::Generic("security refresh lock poisoned".into()))? =
        (now.timestamp().saturating_add(retry_seconds), hint_id);
    Ok(outcome)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulesCheck {
    Passed,
    Failed,
    Unavailable,
}

pub trait RulesChecker: Send + Sync {
    fn check(&self, agent_dirs: &[PathBuf]) -> RulesCheck;
}

pub struct NumbatRulesChecker {
    binary: Option<PathBuf>,
}

impl NumbatRulesChecker {
    pub fn installed() -> Self {
        let binary = dirs::home_dir()
            .map(|home| home.join(".git-ai/bin/numbat"))
            .filter(|path| path.is_file());
        Self { binary }
    }

    #[cfg(debug_assertions)]
    pub fn debug_with_path_fallback() -> Self {
        let installed = Self::installed();
        if installed.binary.is_some() {
            return installed;
        }
        let available = Command::new("numbat")
            .arg("version")
            .output()
            .ok()
            .is_some_and(|output| output.status.success());
        Self {
            binary: available.then(|| PathBuf::from("numbat")),
        }
    }
}

impl RulesChecker for NumbatRulesChecker {
    fn check(&self, agent_dirs: &[PathBuf]) -> RulesCheck {
        let Some(binary) = &self.binary else {
            return RulesCheck::Unavailable;
        };
        for directory in agent_dirs {
            let status = Command::new(binary)
                .args(["rules", "check", "--no-builtin-rules", "--rules-dir"])
                .arg(directory)
                .status();
            if !status.is_ok_and(|status| status.success()) {
                return RulesCheck::Failed;
            }
        }
        RulesCheck::Passed
    }
}

pub trait PolicyTrustVerifier: Send + Sync {
    fn verify(&self, input: PolicyVerifyInput<'_>) -> TrustVerdict;
}

pub struct PolicyVerifyInput<'a> {
    pub envelope: &'a DsseEnvelope,
    pub payload: &'a [u8],
    pub payload_type: &'a str,
    pub purpose: ArtifactPurpose,
    pub signed_at: &'a str,
    pub now: DateTime<Utc>,
    pub persisted: &'a DurableSecurityState,
}

pub struct FileTrustVerifier {
    state_dir: PathBuf,
}

impl FileTrustVerifier {
    pub fn new(state_dir: PathBuf) -> Self {
        Self { state_dir }
    }

    fn load_documents(path: &Path) -> Vec<DsseEnvelope> {
        let Ok(bytes) = fs::read(path) else {
            return Vec::new();
        };
        serde_json::from_slice::<Vec<DsseEnvelope>>(&bytes)
            .or_else(|_| serde_json::from_slice::<DsseEnvelope>(&bytes).map(|one| vec![one]))
            .unwrap_or_default()
    }

    fn pins(&self) -> Vec<String> {
        let mut pins = PINNED_ROOT_KEYIDS
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>();
        #[cfg(debug_assertions)]
        if pins.is_empty() {
            pins = fs::read(self.state_dir.join("dev-pins.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or_default();
        }
        pins
    }
}

impl PolicyTrustVerifier for FileTrustVerifier {
    fn verify(&self, input: PolicyVerifyInput<'_>) -> TrustVerdict {
        let trust_dir = self.state_dir.join("trust");
        let root_documents = Self::load_documents(&trust_dir.join("root.json"));
        let mut keyset_documents = BTreeMap::new();
        if let Ok(entries) = fs::read_dir(&trust_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if let Some(scope) = name
                    .strip_prefix("keyset-")
                    .and_then(|v| v.strip_suffix(".json"))
                {
                    keyset_documents.insert(scope.to_string(), Self::load_documents(&entry.path()));
                }
            }
        }
        verify_trusted(&VerifyTrustedInput {
            payload_type: input.payload_type.to_string(),
            payload: input.payload.to_vec(),
            envelope: input.envelope.clone(),
            purpose: input.purpose,
            audience: PLATFORM_SCOPE.to_string(),
            signed_at: input.signed_at.to_string(),
            time_evidence: None,
            state: TrustState {
                pinned_root_keyids: self.pins(),
                pinned_root_threshold: None,
                root_documents,
                keyset_documents,
                customer_pins: None,
                last_trusted: input.persisted.last_trusted.clone(),
                now: input
                    .now
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                trusted_time_floor: input.persisted.trusted_time_floor.clone(),
                clock_skew_ms: None,
                production: true,
                allow_unpinned_root: None,
            },
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeasePayload {
    schema_version: String,
    tenant_id: String,
    machine_id: String,
    lease_id: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    mode: LeaseMode,
    agents: Vec<String>,
    bundle_digest: String,
    data_settings: SecurityDataSettings,
    day_one_scan: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundlePayload {
    schema_version: String,
    tenant_id: String,
    bundle_version: u64,
    epoch: u64,
    issued_at: DateTime<Utc>,
    numbat_pin: String,
    compiler_version: String,
    agents: BTreeMap<String, AgentBundle>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentBundle {
    files: Vec<RuleFile>,
    enabled_rule_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    path: String,
    sha256: String,
    content_b64: String,
}

pub struct PolicyApplier<'a> {
    pub state_dir: PathBuf,
    pub identity: PolicyIdentity,
    pub state: &'a LeaseStateStore,
    pub http: &'a dyn PolicyHttp,
    pub verifier: &'a dyn PolicyTrustVerifier,
    pub checker: &'a dyn RulesChecker,
    pub lease_hint: Option<crate::fleet::SecurityLeaseReference>,
}

impl PolicyApplier<'_> {
    pub fn refresh(&self, now: DateTime<Utc>) -> Result<RefreshOutcome, GitAiError> {
        self.retry_acknowledgements()?;
        let response = match self.http.get("/worker/security/v2/lease") {
            Ok(value) => value,
            Err(_) => return Ok(RefreshOutcome::Retry),
        };
        if response.status == 404 || response.status >= 500 {
            let lease_not_issued = response.status == 404
                && serde_json::from_slice::<Value>(&response.body)
                    .ok()
                    .and_then(|body| body.get("code").and_then(Value::as_str).map(str::to_owned))
                    .as_deref()
                    == Some("SECURITY_V2_LEASE_NOT_ISSUED");
            return Ok(if lease_not_issued {
                RefreshOutcome::NoChange
            } else {
                RefreshOutcome::Retry
            });
        }
        if response.status != 200 {
            return Ok(RefreshOutcome::Retry);
        }
        let envelope: DsseEnvelope = match serde_json::from_slice(&response.body) {
            Ok(value) => value,
            Err(_) => return self.refuse_unparsed(RefusalCode::SignatureRejected, now),
        };
        let payload = match decode_base64_strict(&envelope.payload, MAX_SIGNED_BYTES) {
            Some(value) => value,
            None => return self.refuse_unparsed(RefusalCode::SignatureRejected, now),
        };
        let signed_at = serde_json::from_slice::<Value>(&payload)
            .ok()
            .and_then(|value| {
                value
                    .get("issued_at")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
        let Some(signed_at) = signed_at else {
            return self.refuse_unparsed(RefusalCode::SignatureRejected, now);
        };
        let before = self.state.snapshot();
        let verdict = self.verifier.verify(PolicyVerifyInput {
            envelope: &envelope,
            payload: &payload,
            payload_type: LEASE_PAYLOAD_TYPE,
            purpose: ArtifactPurpose::ActivationLease,
            signed_at: &signed_at,
            now,
            persisted: &before,
        });
        if verdict.status != TrustStatus::Verified {
            let code = if verdict.status == TrustStatus::Unavailable {
                RefusalCode::VerificationUnavailable
            } else {
                RefusalCode::SignatureRejected
            };
            return self.refuse_unparsed(code, now);
        }
        let lease: LeasePayload = match serde_json::from_slice(&payload) {
            Ok(value) => value,
            Err(_) => return self.refuse_unparsed(RefusalCode::UnsupportedSchema, now),
        };
        if lease.schema_version != "trackai.security-activation-lease/2" {
            return self.refuse(&lease, RefusalCode::UnsupportedSchema, now);
        }
        if !valid_lease(&lease) {
            return self.refuse(&lease, RefusalCode::UnsupportedSchema, now);
        }
        if lease.tenant_id != self.identity.tenant_id {
            return self.refuse(&lease, RefusalCode::TenantMismatch, now);
        }
        let enrolled_machine = self
            .identity
            .machine_id
            .as_ref()
            .or(before.enrolled_machine_id.as_ref());
        if enrolled_machine.is_some_and(|machine_id| lease.machine_id != *machine_id) {
            return self.refuse(&lease, RefusalCode::MachineMismatch, now);
        }
        if !(lease.issued_at <= now && now < lease.expires_at) {
            return self.refuse(&lease, RefusalCode::LeaseExpired, now);
        }
        if let Some(newest) = before
            .accepted_leases
            .iter()
            .max_by_key(|entry| entry.issued_at)
        {
            if newest.signed_bytes == response.body {
                return Ok(RefreshOutcome::NoChange);
            }
            if lease.issued_at < newest.issued_at {
                return Ok(RefreshOutcome::NoChange);
            }
        }
        if lease.mode == LeaseMode::Off {
            return self.accept(lease, response.body, None, verdict, now);
        }
        if before.applied_digest.as_deref() == Some(&lease.bundle_digest) {
            return self.accept(lease, response.body, before.applied_epoch, verdict, now);
        }
        let bundle_response = match self.http.get(&format!(
            "/worker/security/v2/bundles/{}",
            lease.bundle_digest
        )) {
            Ok(value) if value.status == 200 => value,
            _ => return Ok(RefreshOutcome::Retry),
        };
        let bundle_envelope: DsseEnvelope = match serde_json::from_slice(&bundle_response.body) {
            Ok(value) => value,
            Err(_) => return self.refuse(&lease, RefusalCode::SignatureRejected, now),
        };
        let bundle_bytes = match decode_base64_strict(&bundle_envelope.payload, MAX_SIGNED_BYTES) {
            Some(value) => value,
            None => return self.refuse(&lease, RefusalCode::SignatureRejected, now),
        };
        if hex_digest(&bundle_bytes) != lease.bundle_digest {
            return self.refuse(&lease, RefusalCode::BundleDigestMismatch, now);
        }
        let bundle_signed_at = serde_json::from_slice::<Value>(&bundle_bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("issued_at")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
        let Some(bundle_signed_at) = bundle_signed_at else {
            return self.refuse(&lease, RefusalCode::SignatureRejected, now);
        };
        let bundle_verdict = self.verifier.verify(PolicyVerifyInput {
            envelope: &bundle_envelope,
            payload: &bundle_bytes,
            payload_type: BUNDLE_PAYLOAD_TYPE,
            purpose: ArtifactPurpose::PolicyBundle,
            signed_at: &bundle_signed_at,
            now,
            persisted: &before,
        });
        if bundle_verdict.status != TrustStatus::Verified {
            let code = if bundle_verdict.status == TrustStatus::Unavailable {
                RefusalCode::VerificationUnavailable
            } else {
                RefusalCode::SignatureRejected
            };
            return self.refuse(&lease, code, now);
        }
        let bundle: BundlePayload = match serde_json::from_slice(&bundle_bytes) {
            Ok(value) => value,
            Err(_) => return self.refuse(&lease, RefusalCode::UnsupportedSchema, now),
        };
        if bundle.schema_version != "trackai.security-rule-bundle/1"
            || bundle.numbat_pin != "20a5a52"
            || !valid_bundle(&bundle)
        {
            return self.refuse(&lease, RefusalCode::UnsupportedSchema, now);
        }
        if bundle.tenant_id != self.identity.tenant_id {
            return self.refuse(&lease, RefusalCode::TenantMismatch, now);
        }
        if before
            .applied_epoch
            .is_some_and(|epoch| bundle.epoch < epoch)
        {
            return self.refuse(&lease, RefusalCode::EpochRegression, now);
        }
        let staged = match self.stage_bundle(&bundle, &lease.bundle_digest) {
            Ok(value) => value,
            Err(_) => return self.refuse(&lease, RefusalCode::BundleDigestMismatch, now),
        };
        match self.checker.check(&staged.agent_dirs) {
            RulesCheck::Unavailable => {
                let _ = fs::remove_dir_all(&staged.version_dir);
                return Ok(RefreshOutcome::Retry);
            }
            RulesCheck::Failed => {
                let _ = fs::remove_dir_all(&staged.version_dir);
                return self.refuse(&lease, RefusalCode::RulesCheckFailed, now);
            }
            RulesCheck::Passed => {}
        }
        self.switch_current(&staged.version_dir)?;
        self.prune_rules(&staged.version_dir)?;
        self.accept(
            lease,
            response.body,
            Some(bundle.epoch),
            bundle_verdict,
            now,
        )
    }

    fn stage_bundle(
        &self,
        bundle: &BundlePayload,
        digest: &str,
    ) -> Result<StagedRules, GitAiError> {
        let rules = self.state_dir.join("rules");
        fs::create_dir_all(&rules)?;
        let version_dir = rules.join(format!("{}-{}", bundle.epoch, &digest[..12]));
        if version_dir.exists() {
            fs::remove_dir_all(&version_dir)?;
        }
        let mut agent_dirs = Vec::new();
        let mut paths = HashSet::new();
        for (agent, manifest) in &bundle.agents {
            if !safe_component(agent) || manifest.files.is_empty() {
                return Err(invalid_bundle());
            }
            let agent_dir = version_dir.join(agent);
            for file in &manifest.files {
                if !safe_relative_path(&file.path)
                    || !paths.insert((agent.clone(), file.path.clone()))
                {
                    return Err(invalid_bundle());
                }
                let bytes =
                    decode_base64_strict(&file.content_b64, 262_144).ok_or_else(invalid_bundle)?;
                if hex_digest(&bytes) != file.sha256 {
                    return Err(invalid_bundle());
                }
                let path = agent_dir.join(&file.path);
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(path, bytes)?;
            }
            agent_dirs.push(agent_dir);
        }
        Ok(StagedRules {
            version_dir,
            agent_dirs,
        })
    }

    fn switch_current(&self, version_dir: &Path) -> Result<(), GitAiError> {
        let rules = self.state_dir.join("rules");
        let pending = rules.join("current.next");
        let current = rules.join("current");
        let _ = fs::remove_file(&pending);
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            version_dir.file_name().ok_or_else(invalid_bundle)?,
            &pending,
        )?;
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(version_dir, &pending)?;
        fs::rename(pending, current)?;
        Ok(())
    }

    fn prune_rules(&self, keep: &Path) -> Result<(), GitAiError> {
        let rules = self.state_dir.join("rules");
        let previous_digest = self.state.snapshot().applied_digest;
        for entry in fs::read_dir(&rules)? {
            let entry = entry?;
            let path = entry.path();
            if matches!(entry.file_name().to_str(), Some("current" | "current.next")) {
                continue;
            }
            if !path.is_dir() || path == keep {
                continue;
            }
            let retain_previous = previous_digest.as_ref().is_some_and(|digest| {
                digest
                    .get(..12)
                    .is_some_and(|prefix| entry.file_name().to_string_lossy().ends_with(prefix))
            });
            if !retain_previous {
                fs::remove_dir_all(path)?;
            }
        }
        Ok(())
    }

    fn accept(
        &self,
        lease: LeasePayload,
        signed_bytes: Vec<u8>,
        epoch: Option<u64>,
        verdict: TrustVerdict,
        now: DateTime<Utc>,
    ) -> Result<RefreshOutcome, GitAiError> {
        let mut state = self.state.snapshot();
        state
            .enrolled_tenant_id
            .get_or_insert_with(|| lease.tenant_id.clone());
        state
            .enrolled_machine_id
            .get_or_insert_with(|| lease.machine_id.clone());
        state.accepted_leases.push(AcceptedLease {
            lease_id: lease.lease_id.clone(),
            bundle_digest: lease.bundle_digest.clone(),
            issued_at: lease.issued_at,
            expires_at: lease.expires_at,
            data_settings: lease.data_settings,
            mode: lease.mode,
            agents: lease.agents,
            day_one_scan: lease.day_one_scan,
            signed_bytes,
        });
        if let Some(epoch) = epoch {
            state.applied_epoch = Some(epoch);
            state.applied_digest = Some(lease.bundle_digest.clone());
        }
        advance_trust(&mut state, verdict);
        let body = acknowledgement(&lease.lease_id, &lease.bundle_digest, None);
        state.acknowledgements.insert(
            lease.lease_id.clone(),
            PersistedAcknowledgement {
                body: body.clone(),
                sent: false,
            },
        );
        self.state.replace(state, now)?;
        self.send_ack(&lease.lease_id, &body, now)?;
        Ok(RefreshOutcome::Applied {
            lease_id: lease.lease_id,
            epoch,
        })
    }

    fn refuse(
        &self,
        lease: &LeasePayload,
        code: RefusalCode,
        now: DateTime<Utc>,
    ) -> Result<RefreshOutcome, GitAiError> {
        self.refuse_hint(Some(&lease.lease_id), Some(&lease.bundle_digest), code, now)
    }

    fn refuse_unparsed(
        &self,
        code: RefusalCode,
        now: DateTime<Utc>,
    ) -> Result<RefreshOutcome, GitAiError> {
        let hint = self
            .lease_hint
            .as_ref()
            .filter(|hint| !hint.lease_id.is_empty() && valid_digest(&hint.bundle_digest));
        self.refuse_hint(
            hint.map(|value| value.lease_id.as_str()),
            hint.map(|value| value.bundle_digest.as_str()),
            code,
            now,
        )
    }

    fn refuse_hint(
        &self,
        lease_id: Option<&str>,
        digest: Option<&str>,
        code: RefusalCode,
        now: DateTime<Utc>,
    ) -> Result<RefreshOutcome, GitAiError> {
        if let (Some(lease_id), Some(digest)) = (lease_id, digest) {
            let body = acknowledgement(lease_id, digest, Some(code));
            let mut state = self.state.snapshot();
            state
                .acknowledgements
                .entry(lease_id.to_string())
                .or_insert(PersistedAcknowledgement {
                    body: body.clone(),
                    sent: false,
                });
            self.state.replace(state, now)?;
            self.send_ack(lease_id, &body, now)?;
        }
        Ok(RefreshOutcome::Refused {
            lease_id: lease_id.map(str::to_owned),
            code,
        })
    }

    fn send_ack(&self, lease_id: &str, body: &Value, now: DateTime<Utc>) -> Result<(), GitAiError> {
        if self
            .state
            .snapshot()
            .acknowledgements
            .get(lease_id)
            .is_some_and(|ack| ack.sent)
        {
            return Ok(());
        }
        let Ok(response) = self
            .http
            .post_json("/worker/security/v2/acknowledgements", body)
        else {
            return Ok(());
        };
        if (200..300).contains(&response.status) {
            let mut state = self.state.snapshot();
            if let Some(ack) = state.acknowledgements.get_mut(lease_id) {
                ack.sent = true;
            }
            self.state.replace(state, now)?;
        }
        Ok(())
    }

    fn retry_acknowledgements(&self) -> Result<(), GitAiError> {
        let pending = self
            .state
            .snapshot()
            .acknowledgements
            .into_iter()
            .filter(|(_, ack)| !ack.sent)
            .collect::<Vec<_>>();
        for (lease_id, ack) in pending {
            self.send_ack(&lease_id, &ack.body, Utc::now())?;
        }
        Ok(())
    }
}

struct StagedRules {
    version_dir: PathBuf,
    agent_dirs: Vec<PathBuf>,
}

fn advance_trust(state: &mut DurableSecurityState, verdict: TrustVerdict) {
    if let Some(trusted) = verdict.trusted {
        for (scope, reference) in trusted {
            let replace = state
                .last_trusted
                .get(&scope)
                .is_none_or(|current| reference.version >= current.version);
            if replace {
                state.last_trusted.insert(scope, reference);
            }
        }
    }
    if let Some(time) = verdict.trusted_time
        && state
            .trusted_time_floor
            .as_ref()
            .is_none_or(|floor| time >= *floor)
    {
        state.trusted_time_floor = Some(time);
    }
}

fn acknowledgement(lease_id: &str, digest: &str, refusal: Option<RefusalCode>) -> Value {
    match refusal {
        Some(code) => {
            json!({"schema_version":"trackai.security-acknowledgement/1","lease_id":lease_id,"bundle_digest":digest,"result":"refused","refusal_code":code})
        }
        None => {
            json!({"schema_version":"trackai.security-acknowledgement/1","lease_id":lease_id,"bundle_digest":digest,"result":"applied"})
        }
    }
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn safe_relative_path(value: &str) -> bool {
    if value.is_empty() || value.len() > 256 || Path::new(value).is_absolute() {
        return false;
    }
    Path::new(value).components().all(|component| matches!(component, Component::Normal(part) if safe_component(&part.to_string_lossy())))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_lease(lease: &LeasePayload) -> bool {
    !lease.tenant_id.is_empty()
        && lease.tenant_id.len() <= 128
        && !lease.tenant_id.chars().any(char::is_whitespace)
        && !lease.machine_id.is_empty()
        && lease.machine_id.len() <= 128
        && !lease.machine_id.chars().any(char::is_whitespace)
        && !lease.lease_id.is_empty()
        && lease.lease_id.len() <= 128
        && !lease.lease_id.chars().any(char::is_whitespace)
        && valid_digest(&lease.bundle_digest)
        && lease.agents.len() <= 64
        && lease
            .agents
            .iter()
            .all(|agent| SOURCE_AGENTS.contains(&agent.as_str()) || agent == "unknown")
        && lease.agents.iter().collect::<HashSet<_>>().len() == lease.agents.len()
        && (lease.mode == LeaseMode::Off || !lease.agents.is_empty())
        && (lease.mode != LeaseMode::Off || lease.agents.is_empty())
        && lease.expires_at > lease.issued_at
}

fn valid_bundle(bundle: &BundlePayload) -> bool {
    bundle.bundle_version > 0
        && bundle.epoch > 0
        && !bundle.compiler_version.is_empty()
        && bundle.compiler_version.len() <= 64
        && bundle.issued_at.timestamp() > 0
        && !bundle.agents.is_empty()
        && bundle.agents.len() <= 27
        && bundle.agents.iter().all(|(agent, manifest)| {
            SOURCE_AGENTS.contains(&agent.as_str())
                && !manifest.files.is_empty()
                && manifest.files.len() <= 1024
                && manifest.enabled_rule_ids.len() <= 1024
                && manifest.enabled_rule_ids.iter().all(|id| valid_rule_id(id))
                && manifest
                    .enabled_rule_ids
                    .iter()
                    .collect::<HashSet<_>>()
                    .len()
                    == manifest.enabled_rule_ids.len()
                && manifest.files.iter().all(|file| valid_digest(&file.sha256))
        })
}

fn valid_rule_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn invalid_bundle() -> GitAiError {
    GitAiError::Generic("security bundle invalid".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::activation::SecurityLeaseContext;
    use crate::trust::{TrustCode, TrustVerdict};
    use base64::Engine;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct FakeHttp {
        lease: HttpResponse,
        bundle: Option<HttpResponse>,
        posts: Mutex<Vec<Value>>,
    }

    impl PolicyHttp for FakeHttp {
        fn get(&self, path: &str) -> Result<HttpResponse, GitAiError> {
            if path.ends_with("/lease") {
                Ok(self.lease.clone())
            } else {
                self.bundle
                    .clone()
                    .ok_or_else(|| GitAiError::Generic("bundle unavailable".into()))
            }
        }

        fn post_json(&self, _path: &str, body: &Value) -> Result<HttpResponse, GitAiError> {
            self.posts.lock().unwrap().push(body.clone());
            Ok(HttpResponse {
                status: 204,
                body: Vec::new(),
            })
        }
    }

    struct FakeVerifier(Mutex<VecDeque<TrustVerdict>>);

    impl PolicyTrustVerifier for FakeVerifier {
        fn verify(&self, _: PolicyVerifyInput<'_>) -> TrustVerdict {
            self.0
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| TrustVerdict::of(TrustCode::Verified))
        }
    }

    struct FakeChecker(RulesCheck);
    impl RulesChecker for FakeChecker {
        fn check(&self, _: &[PathBuf]) -> RulesCheck {
            self.0
        }
    }

    fn envelope(payload: &[u8], payload_type: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "payloadType": payload_type,
            "payload": base64::engine::general_purpose::STANDARD.encode(payload),
            "signatures": [{"keyid": format!("sha256:{}", "a".repeat(64)), "sig": "MA=="}]
        }))
        .unwrap()
    }

    fn fixture(machine: &str, mode: &str) -> (Vec<u8>, Vec<u8>, DateTime<Utc>, String) {
        let now = Utc::now();
        let content = b"id: test\nenabled: true\n";
        let bundle = serde_json::to_vec(&json!({
            "schema_version":"trackai.security-rule-bundle/1","tenant_id":"tenant-a","bundle_version":1,"epoch":1,
            "issued_at":now.to_rfc3339(),"numbat_pin":"20a5a52","compiler_version":"task20f.1",
            "agents":{"codex":{"files":[{"path":"rule.yaml","sha256":hex_digest(content),"content_b64":base64::engine::general_purpose::STANDARD.encode(content)}],"enabled_rule_ids":["test"]}}
        })).unwrap();
        let digest = hex_digest(&bundle);
        let lease = serde_json::to_vec(&json!({
            "schema_version":"trackai.security-activation-lease/2","tenant_id":"tenant-a","machine_id":machine,"lease_id":"lease-1",
            "issued_at":(now-chrono::Duration::minutes(1)).to_rfc3339(),"expires_at":(now+chrono::Duration::hours(1)).to_rfc3339(),
            "mode":mode,"agents":if mode=="off" {json!([])} else {json!(["codex"])},"bundle_digest":digest,
            "data_settings":{"command_previews":false,"file_paths":false,"urls":false,"host_identity":false,"user_identity":false},"day_one_scan":false
        })).unwrap();
        (
            envelope(&lease, LEASE_PAYLOAD_TYPE),
            envelope(&bundle, BUNDLE_PAYLOAD_TYPE),
            now,
            digest,
        )
    }

    fn verifier(count: usize) -> FakeVerifier {
        FakeVerifier(Mutex::new(
            (0..count)
                .map(|_| TrustVerdict::of(TrustCode::Verified))
                .collect(),
        ))
    }

    #[test]
    fn happy_path_stages_acknowledges_and_restores() {
        let temp = tempfile::tempdir().unwrap();
        let (lease, bundle, now, digest) = fixture("machine-a", "monitor");
        let http = FakeHttp {
            lease: HttpResponse {
                status: 200,
                body: lease,
            },
            bundle: Some(HttpResponse {
                status: 200,
                body: bundle,
            }),
            posts: Mutex::new(Vec::new()),
        };
        let state = LeaseStateStore::load(temp.path());
        let verifier = verifier(2);
        let checker = FakeChecker(RulesCheck::Passed);
        let apply = PolicyApplier {
            state_dir: temp.path().to_path_buf(),
            identity: PolicyIdentity {
                tenant_id: "tenant-a".into(),
                machine_id: Some("machine-a".into()),
            },
            state: &state,
            http: &http,
            verifier: &verifier,
            checker: &checker,
            lease_hint: None,
        };
        assert_eq!(
            apply.refresh(now).unwrap(),
            RefreshOutcome::Applied {
                lease_id: "lease-1".into(),
                epoch: Some(1)
            }
        );
        assert_eq!(http.posts.lock().unwrap().len(), 1);
        assert_eq!(state.current().unwrap().bundle_digest, digest);
        assert!(temp.path().join("rules/current/codex/rule.yaml").exists());
        assert_eq!(
            LeaseStateStore::load(temp.path())
                .current()
                .unwrap()
                .lease_id,
            "lease-1"
        );
    }

    #[test]
    fn foreign_lease_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let (lease, _, now, _) = fixture("machine-b", "monitor");
        let http = FakeHttp {
            lease: HttpResponse {
                status: 200,
                body: lease,
            },
            bundle: None,
            posts: Mutex::new(Vec::new()),
        };
        let state = LeaseStateStore::load(temp.path());
        let verifier = verifier(1);
        let checker = FakeChecker(RulesCheck::Passed);
        let apply = PolicyApplier {
            state_dir: temp.path().into(),
            identity: PolicyIdentity {
                tenant_id: "tenant-a".into(),
                machine_id: Some("machine-a".into()),
            },
            state: &state,
            http: &http,
            verifier: &verifier,
            checker: &checker,
            lease_hint: None,
        };
        assert_eq!(
            apply.refresh(now).unwrap(),
            RefreshOutcome::Refused {
                lease_id: Some("lease-1".into()),
                code: RefusalCode::MachineMismatch
            }
        );
        assert!(state.current().is_none());
        assert_eq!(
            http.posts.lock().unwrap()[0]["refusal_code"],
            "MACHINE_MISMATCH"
        );
    }

    #[test]
    fn absent_checker_keeps_state_off_without_acknowledgement() {
        let temp = tempfile::tempdir().unwrap();
        let (lease, bundle, now, _) = fixture("machine-a", "monitor");
        let http = FakeHttp {
            lease: HttpResponse {
                status: 200,
                body: lease,
            },
            bundle: Some(HttpResponse {
                status: 200,
                body: bundle,
            }),
            posts: Mutex::new(Vec::new()),
        };
        let state = LeaseStateStore::load(temp.path());
        let verifier = verifier(2);
        let checker = FakeChecker(RulesCheck::Unavailable);
        let apply = PolicyApplier {
            state_dir: temp.path().into(),
            identity: PolicyIdentity {
                tenant_id: "tenant-a".into(),
                machine_id: Some("machine-a".into()),
            },
            state: &state,
            http: &http,
            verifier: &verifier,
            checker: &checker,
            lease_hint: None,
        };
        assert_eq!(apply.refresh(now).unwrap(), RefreshOutcome::Retry);
        assert!(state.current().is_none());
        assert!(http.posts.lock().unwrap().is_empty());
    }

    #[test]
    fn off_lease_applies_without_bundle() {
        let temp = tempfile::tempdir().unwrap();
        let (lease, _, now, _) = fixture("machine-a", "off");
        let http = FakeHttp {
            lease: HttpResponse {
                status: 200,
                body: lease,
            },
            bundle: None,
            posts: Mutex::new(Vec::new()),
        };
        let state = LeaseStateStore::load(temp.path());
        let verifier = verifier(1);
        let checker = FakeChecker(RulesCheck::Passed);
        let apply = PolicyApplier {
            state_dir: temp.path().into(),
            identity: PolicyIdentity {
                tenant_id: "tenant-a".into(),
                machine_id: Some("machine-a".into()),
            },
            state: &state,
            http: &http,
            verifier: &verifier,
            checker: &checker,
            lease_hint: None,
        };
        assert!(matches!(
            apply.refresh(now).unwrap(),
            RefreshOutcome::Applied { epoch: None, .. }
        ));
        assert!(state.current().is_none());
        assert_eq!(http.posts.lock().unwrap().len(), 1);
    }

    #[test]
    fn new_lease_reuses_already_applied_bundle_without_refetch() {
        let temp = tempfile::tempdir().unwrap();
        let (lease, _, now, digest) = fixture("machine-a", "monitor");
        let state = LeaseStateStore::from_state(
            temp.path(),
            DurableSecurityState {
                applied_epoch: Some(1),
                applied_digest: Some(digest),
                ..Default::default()
            },
        );
        let http = FakeHttp {
            lease: HttpResponse {
                status: 200,
                body: lease,
            },
            bundle: None,
            posts: Mutex::new(Vec::new()),
        };
        let verifier = verifier(1);
        let checker = FakeChecker(RulesCheck::Passed);
        let apply = PolicyApplier {
            state_dir: temp.path().into(),
            identity: PolicyIdentity {
                tenant_id: "tenant-a".into(),
                machine_id: Some("machine-a".into()),
            },
            state: &state,
            http: &http,
            verifier: &verifier,
            checker: &checker,
            lease_hint: None,
        };
        assert!(matches!(
            apply.refresh(now).unwrap(),
            RefreshOutcome::Applied { epoch: Some(1), .. }
        ));
    }

    #[test]
    fn preparse_refusal_uses_valid_fleet_hint_once() {
        let temp = tempfile::tempdir().unwrap();
        let digest = "b".repeat(64);
        let http = FakeHttp {
            lease: HttpResponse {
                status: 200,
                body: b"not-dsse".to_vec(),
            },
            bundle: None,
            posts: Mutex::new(Vec::new()),
        };
        let state = LeaseStateStore::load(temp.path());
        let verifier = verifier(0);
        let checker = FakeChecker(RulesCheck::Passed);
        let apply = PolicyApplier {
            state_dir: temp.path().into(),
            identity: PolicyIdentity {
                tenant_id: "tenant-a".into(),
                machine_id: None,
            },
            state: &state,
            http: &http,
            verifier: &verifier,
            checker: &checker,
            lease_hint: Some(crate::fleet::SecurityLeaseReference {
                lease_id: "lease-hint".into(),
                bundle_digest: digest,
                expires_at: (Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            }),
        };
        assert!(matches!(
            apply.refresh(Utc::now()).unwrap(),
            RefreshOutcome::Refused {
                code: RefusalCode::SignatureRejected,
                ..
            }
        ));
        assert_eq!(http.posts.lock().unwrap()[0]["lease_id"], "lease-hint");
    }
}
