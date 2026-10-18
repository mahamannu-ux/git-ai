//! Verified TrackAI managed-fleet configuration.

pub mod cleanup;
pub mod managed_update;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const MAX_CONFIGURATION_BYTES: usize = 256 * 1024;
pub const FLEET_STATE_FILE: &str = "state.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcknowledgementResult {
    Applied,
    RejectedInvalid,
    RejectedExpired,
    RejectedIncompatible,
    VerificationUnavailable,
    VerificationRejected,
    ActivationFailed,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityMode {
    Off,
    Monitor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationMetadata {
    pub required: bool,
    pub state: VerificationState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationState {
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryPolicy {
    pub repository_id: String,
    pub enrollment_id: String,
    pub grant_id: String,
    pub branch_patterns: Vec<String>,
    pub effective_from: String,
    pub effective_until: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecurityActivation {
    pub mode: SecurityMode,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FleetChannel {
    Latest,
    Next,
    EnterpriseLatest,
    EnterpriseNext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigurationEnvelopeV1 {
    pub schema_version: u8,
    pub configuration_id: String,
    pub epoch: u64,
    pub issued_at: String,
    pub valid_until: Option<String>,
    pub target_client_version: String,
    pub channel: FleetChannel,
    pub ring: Option<String>,
    pub repository_policies: Vec<RepositoryPolicy>,
    pub security_activation: SecurityActivation,
    pub verification: VerificationMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientCompatibility {
    pub minimum_version: String,
    pub maximum_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DesiredRelease {
    pub version: String,
    pub release_tag: String,
    pub manifest_url: String,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigurationEnvelopeV2 {
    pub schema_version: u8,
    pub configuration_id: String,
    pub epoch: u64,
    pub issued_at: String,
    pub valid_until: Option<String>,
    pub client_compatibility: ClientCompatibility,
    pub desired_release: DesiredRelease,
    pub channel: FleetChannel,
    pub ring: Option<String>,
    pub repository_policies: Vec<RepositoryPolicy>,
    pub security_activation: SecurityActivation,
    pub verification: VerificationMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecurityLeaseReference {
    pub lease_id: String,
    pub bundle_digest: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigurationEnvelopeV3 {
    pub schema_version: u8,
    pub configuration_id: String,
    pub epoch: u64,
    pub issued_at: String,
    pub valid_until: Option<String>,
    pub client_compatibility: ClientCompatibility,
    pub desired_release: DesiredRelease,
    pub channel: FleetChannel,
    pub ring: Option<String>,
    pub repository_policies: Vec<RepositoryPolicy>,
    pub security_lease: SecurityLeaseReference,
    pub verification: VerificationMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConfigurationEnvelope {
    V1(ConfigurationEnvelopeV1),
    V2(ConfigurationEnvelopeV2),
    V3(ConfigurationEnvelopeV3),
}

impl ConfigurationEnvelope {
    pub fn schema_version(&self) -> u8 {
        match self {
            Self::V1(value) => value.schema_version,
            Self::V2(value) => value.schema_version,
            Self::V3(value) => value.schema_version,
        }
    }

    pub fn configuration_id(&self) -> &str {
        match self {
            Self::V1(value) => &value.configuration_id,
            Self::V2(value) => &value.configuration_id,
            Self::V3(value) => &value.configuration_id,
        }
    }

    pub fn epoch(&self) -> u64 {
        match self {
            Self::V1(value) => value.epoch,
            Self::V2(value) => value.epoch,
            Self::V3(value) => value.epoch,
        }
    }

    fn issued_at(&self) -> &str {
        match self {
            Self::V1(value) => &value.issued_at,
            Self::V2(value) => &value.issued_at,
            Self::V3(value) => &value.issued_at,
        }
    }

    fn valid_until(&self) -> Option<&str> {
        match self {
            Self::V1(value) => value.valid_until.as_deref(),
            Self::V2(value) => value.valid_until.as_deref(),
            Self::V3(value) => value.valid_until.as_deref(),
        }
    }

    pub fn repository_policies(&self) -> &[RepositoryPolicy] {
        match self {
            Self::V1(value) => &value.repository_policies,
            Self::V2(value) => &value.repository_policies,
            Self::V3(value) => &value.repository_policies,
        }
    }

    pub fn repository_policies_mut(&mut self) -> &mut Vec<RepositoryPolicy> {
        match self {
            Self::V1(value) => &mut value.repository_policies,
            Self::V2(value) => &mut value.repository_policies,
            Self::V3(value) => &mut value.repository_policies,
        }
    }

    pub fn security_activation(&self) -> &SecurityActivation {
        match self {
            Self::V1(_) | Self::V2(_) => &OFF_SECURITY_ACTIVATION,
            Self::V3(_) => &OFF_SECURITY_ACTIVATION,
        }
    }

    pub fn security_lease(&self) -> Option<&SecurityLeaseReference> {
        match self {
            Self::V3(value) => Some(&value.security_lease),
            Self::V1(_) | Self::V2(_) => None,
        }
    }

    fn ring(&self) -> Option<&str> {
        match self {
            Self::V1(value) => value.ring.as_deref(),
            Self::V2(value) => value.ring.as_deref(),
            Self::V3(value) => value.ring.as_deref(),
        }
    }

    fn verification(&self) -> &VerificationMetadata {
        match self {
            Self::V1(value) => &value.verification,
            Self::V2(value) => &value.verification,
            Self::V3(value) => &value.verification,
        }
    }

    fn desired_release(&self) -> Option<&DesiredRelease> {
        match self {
            Self::V1(_) => None,
            Self::V2(value) => Some(&value.desired_release),
            Self::V3(value) => Some(&value.desired_release),
        }
    }
}

static OFF_SECURITY_ACTIVATION: SecurityActivation = SecurityActivation {
    mode: SecurityMode::Off,
    version: 1,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    Verified,
    Rejected,
    Unavailable,
}

pub trait ConfigurationVerifier: Send + Sync {
    fn verify(&self, exact_bytes: &[u8], metadata: &VerificationMetadata) -> VerificationResult;
}

pub struct UnavailableVerifier;

impl ConfigurationVerifier for UnavailableVerifier {
    fn verify(&self, _exact_bytes: &[u8], _metadata: &VerificationMetadata) -> VerificationResult {
        VerificationResult::Unavailable
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedConfiguration {
    pub digest: String,
    pub envelope: ConfigurationEnvelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_json: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FleetState {
    pub active: Option<VerifiedConfiguration>,
    pub previous: Option<VerifiedConfiguration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutcome {
    pub configuration_id: Option<String>,
    pub epoch: Option<u64>,
    pub result: AcknowledgementResult,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredReleaseAuthorization {
    pub configuration_id: String,
    pub epoch: u64,
    pub desired_release: DesiredRelease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseAuthorizationDenial {
    StateUnavailable,
    NotRetained,
    MissingExactJson,
    DigestMismatch,
    RejectedInvalid,
    RejectedExpired,
    RejectedIncompatible,
    EnvelopeMismatch,
    VerificationRejected,
    VerificationUnavailable,
    SchemaV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetAcknowledgement {
    pub configuration_id: String,
    pub epoch: u64,
    pub result_code: AcknowledgementResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetQueue {
    pub pending_retryable: u64,
    pub waiting_retry: u64,
    pub processing: u64,
    pub quarantined: u64,
    pub rows_with_errors: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetReport {
    pub schema_version: u8,
    pub reported_at: String,
    pub acknowledgement: Option<FleetAcknowledgement>,
    pub platform: &'static str,
    pub os_version: &'static str,
    pub architecture: &'static str,
    pub gitai_version: &'static str,
    pub service_state: &'static str,
    pub queue: FleetQueue,
    pub mdm_device_reference: Option<String>,
    pub mdm_user_reference: Option<String>,
    pub assignment_evidence: AssignmentEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssignmentEvidence {
    pub source: &'static str,
    pub observed_at: String,
}

pub trait BootstrapRepositories {
    fn contains_repository_id(&self, repository_id: &str) -> bool;
    fn repository_count(&self) -> usize;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigurationResponse<'a> {
    NoChange,
    Candidate(&'a [u8]),
    Unavailable,
}

pub fn classify_configuration_response(status: u16, body: &[u8]) -> ConfigurationResponse<'_> {
    match status {
        204 => ConfigurationResponse::NoChange,
        200 => ConfigurationResponse::Candidate(body),
        _ => ConfigurationResponse::Unavailable,
    }
}

pub fn process_configuration(
    raw: &[u8],
    now: DateTime<Utc>,
    client_version: &str,
    bootstrap: &dyn BootstrapRepositories,
    verifier: &dyn ConfigurationVerifier,
    state_path: &Path,
) -> ProcessOutcome {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Identity {
        configuration_id: String,
        epoch: u64,
    }
    let identity = serde_json::from_slice::<Identity>(raw)
        .ok()
        .filter(|value| valid_uuid(&value.configuration_id) && value.epoch > 0)
        .map(|value| (Some(value.configuration_id), Some(value.epoch)))
        .unwrap_or((None, None));
    let parsed = match parse_and_validate(raw, now, client_version, bootstrap) {
        Ok(value) => value,
        Err(result) => {
            return ProcessOutcome {
                configuration_id: identity.0,
                epoch: identity.1,
                result,
            };
        }
    };
    let identity = (
        Some(parsed.configuration_id().to_string()),
        Some(parsed.epoch()),
    );
    match verifier.verify(raw, parsed.verification()) {
        VerificationResult::Unavailable => ProcessOutcome {
            configuration_id: identity.0,
            epoch: identity.1,
            result: AcknowledgementResult::VerificationUnavailable,
        },
        VerificationResult::Rejected => ProcessOutcome {
            configuration_id: identity.0,
            epoch: identity.1,
            result: AcknowledgementResult::VerificationRejected,
        },
        VerificationResult::Verified => {
            let verified = VerifiedConfiguration {
                digest: hex_digest(raw),
                envelope: parsed,
                exact_json: String::from_utf8(raw.to_vec()).ok(),
            };
            let result = activate_verified(state_path, verified)
                .unwrap_or(AcknowledgementResult::ActivationFailed);
            ProcessOutcome {
                configuration_id: identity.0,
                epoch: identity.1,
                result,
            }
        }
    }
}

pub fn parse_and_validate(
    raw: &[u8],
    now: DateTime<Utc>,
    client_version: &str,
    bootstrap: &dyn BootstrapRepositories,
) -> Result<ConfigurationEnvelope, AcknowledgementResult> {
    if raw.is_empty() || raw.len() > MAX_CONFIGURATION_BYTES {
        return Err(AcknowledgementResult::RejectedInvalid);
    }
    let envelope: ConfigurationEnvelope =
        serde_json::from_slice(raw).map_err(|_| AcknowledgementResult::RejectedInvalid)?;
    if !matches!(envelope.schema_version(), 1 | 2 | 3)
        || envelope.epoch() == 0
        || !valid_uuid(envelope.configuration_id())
        || envelope
            .ring()
            .is_some_and(|ring| ring.is_empty() || ring.len() > 64)
        || !envelope.verification().required
        || envelope.repository_policies().len() > 1_000
    {
        return Err(AcknowledgementResult::RejectedInvalid);
    }
    match &envelope {
        ConfigurationEnvelope::V1(value) => {
            if value.schema_version != 1 || value.target_client_version.len() > 64 {
                return Err(AcknowledgementResult::RejectedInvalid);
            }
            if value.target_client_version != client_version {
                return Err(AcknowledgementResult::RejectedIncompatible);
            }
        }
        ConfigurationEnvelope::V2(value) => {
            if value.schema_version != 2 || !valid_desired_release(&value.desired_release) {
                return Err(AcknowledgementResult::RejectedInvalid);
            }
            let minimum = canonical_version(&value.client_compatibility.minimum_version)
                .ok_or(AcknowledgementResult::RejectedInvalid)?;
            let maximum = canonical_version(&value.client_compatibility.maximum_version)
                .ok_or(AcknowledgementResult::RejectedInvalid)?;
            let client = canonical_version(client_version)
                .ok_or(AcknowledgementResult::RejectedIncompatible)?;
            if minimum > maximum {
                return Err(AcknowledgementResult::RejectedInvalid);
            }
            if client < minimum || client > maximum {
                return Err(AcknowledgementResult::RejectedIncompatible);
            }
        }
        ConfigurationEnvelope::V3(value) => {
            if value.schema_version != 3
                || !valid_desired_release(&value.desired_release)
                || !valid_security_lease(&value.security_lease)
            {
                return Err(AcknowledgementResult::RejectedInvalid);
            }
            let minimum = canonical_version(&value.client_compatibility.minimum_version)
                .ok_or(AcknowledgementResult::RejectedInvalid)?;
            let maximum = canonical_version(&value.client_compatibility.maximum_version)
                .ok_or(AcknowledgementResult::RejectedInvalid)?;
            let client = canonical_version(client_version)
                .ok_or(AcknowledgementResult::RejectedIncompatible)?;
            if minimum > maximum {
                return Err(AcknowledgementResult::RejectedInvalid);
            }
            if client < minimum || client > maximum {
                return Err(AcknowledgementResult::RejectedIncompatible);
            }
        }
    }
    let issued_at =
        parse_time(envelope.issued_at()).ok_or(AcknowledgementResult::RejectedInvalid)?;
    if issued_at > now + chrono::Duration::minutes(5) {
        return Err(AcknowledgementResult::RejectedInvalid);
    }
    if let Some(valid_until) = envelope.valid_until() {
        let valid_until = parse_time(valid_until).ok_or(AcknowledgementResult::RejectedInvalid)?;
        if valid_until <= issued_at {
            return Err(AcknowledgementResult::RejectedInvalid);
        }
        if valid_until <= now {
            return Err(AcknowledgementResult::RejectedExpired);
        }
    }

    let mut repositories = HashSet::new();
    let mut grants = HashSet::new();
    for policy in envelope.repository_policies() {
        let mut branch_patterns = HashSet::new();
        if !valid_uuid(&policy.repository_id)
            || !valid_uuid(&policy.enrollment_id)
            || !valid_uuid(&policy.grant_id)
            || policy.branch_patterns.len() > 64
            || policy.branch_patterns.iter().any(|pattern| {
                pattern.is_empty() || pattern.len() > 255 || !branch_patterns.insert(pattern)
            })
            || !bootstrap.contains_repository_id(&policy.repository_id)
            || !repositories.insert(&policy.repository_id)
            || !grants.insert(&policy.grant_id)
        {
            return Err(AcknowledgementResult::RejectedInvalid);
        }
        let effective_from =
            parse_time(&policy.effective_from).ok_or(AcknowledgementResult::RejectedInvalid)?;
        if let Some(effective_until) = policy.effective_until.as_deref() {
            let effective_until =
                parse_time(effective_until).ok_or(AcknowledgementResult::RejectedInvalid)?;
            if effective_until <= effective_from {
                return Err(AcknowledgementResult::RejectedInvalid);
            }
        }
    }
    if bootstrap.repository_count() < envelope.repository_policies().len() {
        return Err(AcknowledgementResult::RejectedInvalid);
    }
    Ok(envelope)
}

pub fn authorize_desired_release(
    state_path: &Path,
    configuration_id: &str,
    epoch: u64,
    now: DateTime<Utc>,
    client_version: &str,
    bootstrap: &dyn BootstrapRepositories,
    verifier: &dyn ConfigurationVerifier,
) -> Result<DesiredReleaseAuthorization, ReleaseAuthorizationDenial> {
    let state = load_state(state_path).map_err(|_| ReleaseAuthorizationDenial::StateUnavailable)?;
    let retained = [state.active.as_ref(), state.previous.as_ref()]
        .into_iter()
        .flatten()
        .find(|candidate| {
            candidate.envelope.configuration_id() == configuration_id
                && candidate.envelope.epoch() == epoch
        })
        .ok_or(ReleaseAuthorizationDenial::NotRetained)?;
    let exact_json = retained
        .exact_json
        .as_deref()
        .ok_or(ReleaseAuthorizationDenial::MissingExactJson)?;
    if hex_digest(exact_json.as_bytes()) != retained.digest {
        return Err(ReleaseAuthorizationDenial::DigestMismatch);
    }
    let parsed = parse_and_validate(exact_json.as_bytes(), now, client_version, bootstrap)
        .map_err(map_authorization_validation_denial)?;
    if parsed != retained.envelope {
        return Err(ReleaseAuthorizationDenial::EnvelopeMismatch);
    }
    match verifier.verify(exact_json.as_bytes(), parsed.verification()) {
        VerificationResult::Rejected => {
            return Err(ReleaseAuthorizationDenial::VerificationRejected);
        }
        VerificationResult::Unavailable => {
            return Err(ReleaseAuthorizationDenial::VerificationUnavailable);
        }
        VerificationResult::Verified => {}
    }
    let desired_release = parsed
        .desired_release()
        .cloned()
        .ok_or(ReleaseAuthorizationDenial::SchemaV1)?;
    Ok(DesiredReleaseAuthorization {
        configuration_id: configuration_id.to_string(),
        epoch,
        desired_release,
    })
}

fn map_authorization_validation_denial(
    result: AcknowledgementResult,
) -> ReleaseAuthorizationDenial {
    match result {
        AcknowledgementResult::RejectedExpired => ReleaseAuthorizationDenial::RejectedExpired,
        AcknowledgementResult::RejectedIncompatible => {
            ReleaseAuthorizationDenial::RejectedIncompatible
        }
        _ => ReleaseAuthorizationDenial::RejectedInvalid,
    }
}

pub fn load_state(path: &Path) -> Result<FleetState, std::io::Error> {
    match fs::read(path) {
        Ok(raw) => serde_json::from_slice(&raw)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(FleetState::default()),
        Err(error) => Err(error),
    }
}

fn activate_verified(
    state_path: &Path,
    candidate: VerifiedConfiguration,
) -> Result<AcknowledgementResult, std::io::Error> {
    let current = load_state(state_path)?;
    let next = match current.active.as_ref() {
        None => FleetState {
            active: Some(candidate),
            previous: None,
        },
        Some(active)
            if candidate.envelope.epoch() == active.envelope.epoch()
                && candidate.envelope.configuration_id() == active.envelope.configuration_id()
                && candidate.digest == active.digest =>
        {
            FleetState {
                active: Some(candidate),
                previous: current.previous.clone(),
            }
        }
        Some(active) if candidate.envelope.epoch() > active.envelope.epoch() => FleetState {
            active: Some(candidate),
            previous: Some(active.clone()),
        },
        Some(active)
            if current.previous.as_ref().is_some_and(|previous| {
                previous.envelope.epoch() == candidate.envelope.epoch()
                    && previous.envelope.configuration_id() == candidate.envelope.configuration_id()
                    && previous.digest == candidate.digest
            }) =>
        {
            FleetState {
                active: Some(candidate),
                previous: Some(active.clone()),
            }
        }
        Some(_) => return Ok(AcknowledgementResult::RejectedInvalid),
    };
    atomic_write_json(state_path, &next)?;
    Ok(AcknowledgementResult::Applied)
}

pub fn default_state_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".git-ai").join("fleet").join(FLEET_STATE_FILE))
}

pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), std::io::Error> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("missing parent"))?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let write_result = (|| {
        let mut file = options.open(&temporary)?;
        serde_json::to_writer(&mut file, value).map_err(std::io::Error::other)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        #[cfg(windows)]
        restrict_windows_file(&temporary)?;
        atomic_replace(&temporary, path)?;
        #[cfg(unix)]
        OpenOptions::new().read(true).open(parent)?.sync_all()?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

#[cfg(windows)]
fn restrict_windows_file(path: &Path) -> Result<(), std::io::Error> {
    use std::os::windows::process::CommandExt;
    let username = std::env::var("USERNAME")
        .map_err(|_| std::io::Error::other("current Windows user unavailable"))?;
    let grant = format!("{username}:F");
    let output = std::process::Command::new("icacls")
        .args([
            path.as_os_str(),
            std::ffi::OsStr::new("/inheritance:r"),
            std::ffi::OsStr::new("/grant:r"),
            std::ffi::OsStr::new(&grant),
        ])
        .creation_flags(crate::utils::CREATE_NO_WINDOW)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other("restrictive Windows ACL unavailable"))
    }
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> Result<(), std::io::Error> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> Result<(), std::io::Error> {
    if !destination.exists() {
        return fs::rename(source, destination);
    }
    use std::os::windows::ffi::OsStrExt;
    let source = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn ReplaceFileW(
            replaced: *const u16,
            replacement: *const u16,
            backup: *const u16,
            flags: u32,
            exclude: *const core::ffi::c_void,
            reserved: *const core::ffi::c_void,
        ) -> i32;
    }
    // SAFETY: both paths are owned, NUL-terminated UTF-16 buffers and all optional
    // pointers are null. ReplaceFileW atomically swaps files on the same volume.
    let result = unsafe {
        ReplaceFileW(
            destination.as_ptr(),
            source.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn parse_time(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn canonical_version(value: &str) -> Option<semver::Version> {
    if value.is_empty() || value.len() > 64 {
        return None;
    }
    let parsed = semver::Version::parse(value).ok()?;
    (parsed.to_string() == value).then_some(parsed)
}

fn valid_desired_release(release: &DesiredRelease) -> bool {
    if canonical_version(&release.version).is_none()
        || release.release_tag.is_empty()
        || release.release_tag.len() > 128
        || release.release_tag.contains("..")
        || !release
            .release_tag
            .bytes()
            .enumerate()
            .all(|(index, byte)| {
                byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
            })
        || release.manifest_sha256.len() != 64
        || !release
            .manifest_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return false;
    }
    let expected = format!(
        "https://github.com/mahamannu-ux/git-ai/releases/download/{}/SHA256SUMS",
        release.release_tag
    );
    release.manifest_url == expected
        && url::Url::parse(&release.manifest_url).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str() == Some("github.com")
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
        })
}

fn valid_security_lease(lease: &SecurityLeaseReference) -> bool {
    !lease.lease_id.is_empty()
        && lease.lease_id.len() <= 128
        && !lease.lease_id.chars().any(char::is_whitespace)
        && lease.bundle_digest.len() == 64
        && lease
            .bundle_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && parse_time(&lease.expires_at).is_some()
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn hex_digest(raw: &[u8]) -> String {
    Sha256::digest(raw)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    struct Repositories(HashSet<String>);
    impl BootstrapRepositories for Repositories {
        fn contains_repository_id(&self, repository_id: &str) -> bool {
            self.0.contains(repository_id)
        }
        fn repository_count(&self) -> usize {
            self.0.len()
        }
    }
    struct Verifier(VerificationResult);
    impl ConfigurationVerifier for Verifier {
        fn verify(&self, _: &[u8], _: &VerificationMetadata) -> VerificationResult {
            self.0
        }
    }

    fn raw(epoch: u64, id: &str) -> Vec<u8> {
        format!(r#"{{"schemaVersion":1,"configurationId":"{id}","epoch":{epoch},"issuedAt":"2026-10-10T00:00:00Z","validUntil":"2026-10-12T00:00:00Z","targetClientVersion":"1.6.19","channel":"latest","ring":null,"repositoryPolicies":[{{"repositoryId":"11111111-1111-4111-8111-111111111111","enrollmentId":"22222222-2222-4222-8222-222222222222","grantId":"33333333-3333-4333-8333-333333333333","branchPatterns":["main"],"effectiveFrom":"2026-10-10T00:00:00Z","effectiveUntil":null}}],"securityActivation":{{"mode":"monitor","version":1}},"verification":{{"required":true,"state":"unavailable"}}}}"#).into_bytes()
    }

    fn v2_raw(epoch: u64, id: &str) -> Vec<u8> {
        format!(r#"{{"schemaVersion":2,"configurationId":"{id}","epoch":{epoch},"issuedAt":"2026-10-10T00:00:00Z","validUntil":"2026-10-12T00:00:00Z","clientCompatibility":{{"minimumVersion":"1.6.18","maximumVersion":"1.6.20"}},"desiredRelease":{{"version":"9.8.7","releaseTag":"v9.8.7","manifestUrl":"https://github.com/mahamannu-ux/git-ai/releases/download/v9.8.7/SHA256SUMS","manifestSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},"channel":"enterprise-latest","ring":null,"repositoryPolicies":[{{"repositoryId":"11111111-1111-4111-8111-111111111111","enrollmentId":"22222222-2222-4222-8222-222222222222","grantId":"33333333-3333-4333-8333-333333333333","branchPatterns":["main"],"effectiveFrom":"2026-10-10T00:00:00Z","effectiveUntil":null}}],"securityActivation":{{"mode":"monitor","version":1}},"verification":{{"required":true,"state":"unavailable"}}}}"#).into_bytes()
    }

    fn v3_raw(epoch: u64, id: &str) -> Vec<u8> {
        format!(r#"{{"schemaVersion":3,"configurationId":"{id}","epoch":{epoch},"issuedAt":"2026-10-10T00:00:00Z","validUntil":"2026-10-12T00:00:00Z","clientCompatibility":{{"minimumVersion":"1.6.18","maximumVersion":"1.6.20"}},"desiredRelease":{{"version":"9.8.7","releaseTag":"v9.8.7","manifestUrl":"https://github.com/mahamannu-ux/git-ai/releases/download/v9.8.7/SHA256SUMS","manifestSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},"channel":"enterprise-latest","ring":null,"repositoryPolicies":[{{"repositoryId":"11111111-1111-4111-8111-111111111111","enrollmentId":"22222222-2222-4222-8222-222222222222","grantId":"33333333-3333-4333-8333-333333333333","branchPatterns":["main"],"effectiveFrom":"2026-10-10T00:00:00Z","effectiveUntil":null}}],"securityLease":{{"leaseId":"44444444-4444-4444-8444-444444444444","bundleDigest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expiresAt":"2026-10-11T00:00:00Z"}},"verification":{{"required":true,"state":"unavailable"}}}}"#).into_bytes()
    }

    fn repositories() -> Repositories {
        Repositories(HashSet::from([
            "11111111-1111-4111-8111-111111111111".to_string()
        ]))
    }

    #[test]
    fn fleet_v3_parses_lease_hint_and_v1_v2_remain_fail_closed() {
        let now = "2026-10-10T01:00:00Z".parse().unwrap();
        let v3 = parse_and_validate(
            &v3_raw(3, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            now,
            env!("CARGO_PKG_VERSION"),
            &repositories(),
        )
        .unwrap();
        assert_eq!(v3.schema_version(), 3);
        assert_eq!(v3.security_activation().mode, SecurityMode::Off);
        assert_eq!(
            v3.security_lease().unwrap().lease_id,
            "44444444-4444-4444-8444-444444444444"
        );
        for raw in [
            raw(1, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            v2_raw(2, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        ] {
            let parsed =
                parse_and_validate(&raw, now, env!("CARGO_PKG_VERSION"), &repositories()).unwrap();
            assert!(parsed.security_lease().is_none());
        }
    }

    #[test]
    fn unavailable_and_rejected_verification_never_activate() {
        for result in [
            VerificationResult::Unavailable,
            VerificationResult::Rejected,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("fleet/state.json");
            let outcome = process_configuration(
                &raw(1, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
                "2026-10-10T01:00:00Z".parse().unwrap(),
                env!("CARGO_PKG_VERSION"),
                &repositories(),
                &Verifier(result),
                &path,
            );
            assert_ne!(outcome.result, AcknowledgementResult::Applied);
            assert!(!path.exists());
        }
    }

    #[test]
    fn forward_activation_and_exact_retained_rollback_are_atomic() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fleet/state.json");
        let now = "2026-10-10T01:00:00Z".parse().unwrap();
        let first = raw(1, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        let second = raw(2, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
        assert_eq!(
            process_configuration(
                &first,
                now,
                env!("CARGO_PKG_VERSION"),
                &repositories(),
                &Verifier(VerificationResult::Verified),
                &path
            )
            .result,
            AcknowledgementResult::Applied
        );
        assert_eq!(
            process_configuration(
                &second,
                now,
                env!("CARGO_PKG_VERSION"),
                &repositories(),
                &Verifier(VerificationResult::Verified),
                &path
            )
            .result,
            AcknowledgementResult::Applied
        );
        assert_eq!(
            process_configuration(
                &first,
                now,
                env!("CARGO_PKG_VERSION"),
                &repositories(),
                &Verifier(VerificationResult::Verified),
                &path
            )
            .result,
            AcknowledgementResult::Applied
        );
        let state = load_state(&path).unwrap();
        assert_eq!(state.active.unwrap().envelope.epoch(), 1);
        assert_eq!(state.previous.unwrap().envelope.epoch(), 2);
    }

    #[test]
    fn empty_branch_patterns_activate_as_all_branches() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fleet/state.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&raw(1, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")).unwrap();
        value["repositoryPolicies"][0]["branchPatterns"] = serde_json::json!([]);

        let outcome = process_configuration(
            &serde_json::to_vec(&value).unwrap(),
            "2026-10-10T01:00:00Z".parse().unwrap(),
            env!("CARGO_PKG_VERSION"),
            &repositories(),
            &Verifier(VerificationResult::Verified),
            &path,
        );

        assert_eq!(outcome.result, AcknowledgementResult::Applied);
        assert!(
            load_state(&path)
                .unwrap()
                .active
                .unwrap()
                .envelope
                .repository_policies()[0]
                .branch_patterns
                .is_empty()
        );

        value["repositoryPolicies"][0]["branchPatterns"] = serde_json::json!(["feature/[draft"]);
        assert!(
            parse_and_validate(
                &serde_json::to_vec(&value).unwrap(),
                "2026-10-10T01:00:00Z".parse().unwrap(),
                env!("CARGO_PKG_VERSION"),
                &repositories()
            )
            .is_ok()
        );
    }

    #[test]
    fn closed_parser_rejects_unknown_expired_incompatible_and_cross_binding() {
        let now = "2026-10-10T01:00:00Z".parse().unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&raw(1, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert_eq!(
            parse_and_validate(
                &serde_json::to_vec(&value).unwrap(),
                now,
                env!("CARGO_PKG_VERSION"),
                &repositories()
            ),
            Err(AcknowledgementResult::RejectedInvalid)
        );
        let mut value: serde_json::Value =
            serde_json::from_slice(&raw(1, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")).unwrap();
        value["targetClientVersion"] = serde_json::json!("0.0.0");
        assert_eq!(
            parse_and_validate(
                &serde_json::to_vec(&value).unwrap(),
                now,
                env!("CARGO_PKG_VERSION"),
                &repositories()
            ),
            Err(AcknowledgementResult::RejectedIncompatible)
        );
        let empty = Repositories(HashSet::new());
        assert_eq!(
            parse_and_validate(
                &raw(1, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
                now,
                env!("CARGO_PKG_VERSION"),
                &empty
            ),
            Err(AcknowledgementResult::RejectedInvalid)
        );
        let mut expired: serde_json::Value =
            serde_json::from_slice(&raw(1, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")).unwrap();
        expired["validUntil"] = serde_json::json!("2026-10-10T00:30:00Z");
        assert_eq!(
            parse_and_validate(
                &serde_json::to_vec(&expired).unwrap(),
                now,
                env!("CARGO_PKG_VERSION"),
                &repositories()
            ),
            Err(AcknowledgementResult::RejectedExpired)
        );
        assert_eq!(
            parse_and_validate(
                &vec![b'x'; MAX_CONFIGURATION_BYTES + 1],
                now,
                env!("CARGO_PKG_VERSION"),
                &repositories()
            ),
            Err(AcknowledgementResult::RejectedInvalid)
        );
        assert_eq!(
            classify_configuration_response(204, b"ignored"),
            ConfigurationResponse::NoChange
        );
        assert_eq!(
            classify_configuration_response(200, b"{}"),
            ConfigurationResponse::Candidate(b"{}")
        );
        assert_eq!(
            classify_configuration_response(503, b""),
            ConfigurationResponse::Unavailable
        );
    }

    #[test]
    fn digest_mismatch_and_atomic_write_failure_preserve_current_and_previous() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fleet/state.json");
        let now = "2026-10-10T01:00:00Z".parse().unwrap();
        let first = raw(1, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        let second = raw(2, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
        let verifier = Verifier(VerificationResult::Verified);
        assert_eq!(
            process_configuration(
                &first,
                now,
                env!("CARGO_PKG_VERSION"),
                &repositories(),
                &verifier,
                &path
            )
            .result,
            AcknowledgementResult::Applied
        );
        assert_eq!(
            process_configuration(
                &second,
                now,
                env!("CARGO_PKG_VERSION"),
                &repositories(),
                &verifier,
                &path
            )
            .result,
            AcknowledgementResult::Applied
        );
        let changed = String::from_utf8(first.clone())
            .unwrap()
            .replace("\"ring\":null", "\"ring\":\"changed\"")
            .into_bytes();
        assert_eq!(
            process_configuration(
                &changed,
                now,
                env!("CARGO_PKG_VERSION"),
                &repositories(),
                &verifier,
                &path
            )
            .result,
            AcknowledgementResult::RejectedInvalid
        );
        let staging = path.with_extension(format!("tmp-{}", std::process::id()));
        std::fs::create_dir(&staging).unwrap();
        let third = raw(3, "cccccccc-cccc-4ccc-8ccc-cccccccccccc");
        assert_eq!(
            process_configuration(
                &third,
                now,
                env!("CARGO_PKG_VERSION"),
                &repositories(),
                &verifier,
                &path
            )
            .result,
            AcknowledgementResult::ActivationFailed
        );
        let state = load_state(&path).unwrap();
        assert_eq!(state.active.unwrap().envelope.epoch(), 2);
        assert_eq!(state.previous.unwrap().envelope.epoch(), 1);
    }

    #[test]
    fn schema_v2_uses_inclusive_semver_compatibility_independent_of_desired_release() {
        let now = "2026-10-10T01:00:00Z".parse().unwrap();
        let raw = v2_raw(1, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        assert!(parse_and_validate(&raw, now, "1.6.18", &repositories()).is_ok());
        assert!(parse_and_validate(&raw, now, "1.6.20", &repositories()).is_ok());
        assert_eq!(
            parse_and_validate(&raw, now, "1.6.21", &repositories()),
            Err(AcknowledgementResult::RejectedIncompatible)
        );

        for (path, replacement) in [
            (
                "/clientCompatibility/minimumVersion",
                serde_json::json!("01.6.18"),
            ),
            (
                "/clientCompatibility/maximumVersion",
                serde_json::json!("1.6"),
            ),
            ("/desiredRelease/version", serde_json::json!("latest")),
            ("/desiredRelease/releaseTag", serde_json::json!("../v9.8.7")),
            (
                "/desiredRelease/manifestSha256",
                serde_json::json!("A".repeat(64)),
            ),
            (
                "/clientCompatibility/minimumVersion",
                serde_json::json!("1.6.21"),
            ),
        ] {
            let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            *value.pointer_mut(path).unwrap() = replacement;
            if path == "/clientCompatibility/minimumVersion"
                && value["clientCompatibility"]["minimumVersion"] == "1.6.21"
            {
                value["clientCompatibility"]["maximumVersion"] = serde_json::json!("1.6.20");
            }
            assert_eq!(
                parse_and_validate(
                    &serde_json::to_vec(&value).unwrap(),
                    now,
                    "1.6.19",
                    &repositories()
                ),
                Err(AcknowledgementResult::RejectedInvalid),
                "accepted invalid {path}"
            );
        }

        let invalid_urls = [
            "https://github.com/mahamannu-ux/git-ai/releases/latest/download/SHA256SUMS",
            "https://github.com/other/git-ai/releases/download/v9.8.7/SHA256SUMS",
            "https://github.com/mahamannu-ux/git-ai/releases/download/v9.8.6/SHA256SUMS",
            "https://github.com/mahamannu-ux/git-ai/releases/download/v9.8.7%2fother/SHA256SUMS",
            "https://user@github.com/mahamannu-ux/git-ai/releases/download/v9.8.7/SHA256SUMS",
            "https://github.com/mahamannu-ux/git-ai/releases/download/../v9.8.7/SHA256SUMS",
            "https://github.com/mahamannu-ux/git-ai/releases/download/v9.8.7/SHA256SUMS?x=1",
            "https://github.com/mahamannu-ux/git-ai/releases/download/v9.8.7/SHA256SUMS#x",
        ];
        for manifest_url in invalid_urls {
            let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            value["desiredRelease"]["manifestUrl"] = serde_json::json!(manifest_url);
            assert_eq!(
                parse_and_validate(
                    &serde_json::to_vec(&value).unwrap(),
                    now,
                    "1.6.19",
                    &repositories()
                ),
                Err(AcknowledgementResult::RejectedInvalid),
                "accepted invalid URL {manifest_url}"
            );
        }
    }

    #[test]
    fn exact_persisted_v2_bytes_are_reverified_for_active_and_retained_previous() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fleet/state.json");
        let now = "2026-10-10T01:00:00Z".parse().unwrap();
        let first = v2_raw(1, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        let second = v2_raw(2, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
        let verifier = Verifier(VerificationResult::Verified);
        for raw in [&first, &second] {
            assert_eq!(
                process_configuration(raw, now, "1.6.19", &repositories(), &verifier, &path).result,
                AcknowledgementResult::Applied
            );
        }
        let state = load_state(&path).unwrap();
        assert_eq!(
            state.active.as_ref().unwrap().exact_json.as_deref(),
            std::str::from_utf8(&second).ok()
        );
        assert_eq!(
            state.previous.as_ref().unwrap().exact_json.as_deref(),
            std::str::from_utf8(&first).ok()
        );

        let active = authorize_desired_release(
            &path,
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            2,
            now,
            "1.6.19",
            &repositories(),
            &verifier,
        )
        .unwrap();
        assert_eq!(active.desired_release.version, "9.8.7");
        let previous = authorize_desired_release(
            &path,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            1,
            now,
            "1.6.19",
            &repositories(),
            &verifier,
        )
        .unwrap();
        assert_eq!(
            previous.configuration_id,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        );
    }

    #[test]
    fn authorization_denials_preserve_active_and_previous_state() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fleet/state.json");
        let now = "2026-10-10T01:00:00Z".parse().unwrap();
        let candidate = v2_raw(1, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        process_configuration(
            &candidate,
            now,
            "1.6.19",
            &repositories(),
            &Verifier(VerificationResult::Verified),
            &path,
        );
        let original = std::fs::read(&path).unwrap();

        for verifier in [
            Verifier(VerificationResult::Unavailable),
            Verifier(VerificationResult::Rejected),
        ] {
            assert!(
                authorize_desired_release(
                    &path,
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    1,
                    now,
                    "1.6.19",
                    &repositories(),
                    &verifier,
                )
                .is_err()
            );
            assert_eq!(std::fs::read(&path).unwrap(), original);
        }

        let mut state = load_state(&path).unwrap();
        state.active.as_mut().unwrap().exact_json = None;
        atomic_write_json(&path, &state).unwrap();
        assert_eq!(
            authorize_desired_release(
                &path,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                1,
                now,
                "1.6.19",
                &repositories(),
                &Verifier(VerificationResult::Verified),
            ),
            Err(ReleaseAuthorizationDenial::MissingExactJson)
        );

        let legacy_path = temp.path().join("fleet/legacy.json");
        let legacy = VerifiedConfiguration {
            digest: hex_digest(&raw(1, "cccccccc-cccc-4ccc-8ccc-cccccccccccc")),
            envelope: parse_and_validate(
                &raw(1, "cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
                now,
                "1.6.19",
                &repositories(),
            )
            .unwrap(),
            exact_json: None,
        };
        atomic_write_json(
            &legacy_path,
            &FleetState {
                active: Some(legacy),
                previous: None,
            },
        )
        .unwrap();
        assert_eq!(
            authorize_desired_release(
                &legacy_path,
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                1,
                now,
                "1.6.19",
                &repositories(),
                &Verifier(VerificationResult::Verified),
            ),
            Err(ReleaseAuthorizationDenial::MissingExactJson)
        );
    }

    #[test]
    fn tamper_expiry_incompatibility_schema_v1_and_unretained_requests_are_denied() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fleet/state.json");
        let now = "2026-10-10T01:00:00Z".parse().unwrap();
        let candidate = v2_raw(1, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        process_configuration(
            &candidate,
            now,
            "1.6.19",
            &repositories(),
            &Verifier(VerificationResult::Verified),
            &path,
        );

        let authorize = |path: &Path, now, client_version| {
            authorize_desired_release(
                path,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                1,
                now,
                client_version,
                &repositories(),
                &Verifier(VerificationResult::Verified),
            )
        };
        assert_eq!(
            authorize(&path, "2026-10-13T01:00:00Z".parse().unwrap(), "1.6.19"),
            Err(ReleaseAuthorizationDenial::RejectedExpired)
        );
        assert_eq!(
            authorize(&path, now, "1.6.21"),
            Err(ReleaseAuthorizationDenial::RejectedIncompatible)
        );
        assert_eq!(
            authorize_desired_release(
                &path,
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                0,
                now,
                "1.6.19",
                &repositories(),
                &Verifier(VerificationResult::Verified),
            ),
            Err(ReleaseAuthorizationDenial::NotRetained)
        );

        let mut state = load_state(&path).unwrap();
        state.active.as_mut().unwrap().digest = "b".repeat(64);
        atomic_write_json(&path, &state).unwrap();
        assert_eq!(
            authorize(&path, now, "1.6.19"),
            Err(ReleaseAuthorizationDenial::DigestMismatch)
        );

        let mut state = load_state(&path).unwrap();
        let exact = state.active.as_ref().unwrap().exact_json.as_ref().unwrap();
        let changed = exact.replace("\"ring\":null", "\"ring\":\"changed\"");
        state.active.as_mut().unwrap().digest = hex_digest(changed.as_bytes());
        state.active.as_mut().unwrap().exact_json = Some(changed);
        atomic_write_json(&path, &state).unwrap();
        assert_eq!(
            authorize(&path, now, "1.6.19"),
            Err(ReleaseAuthorizationDenial::EnvelopeMismatch)
        );

        let v1_path = temp.path().join("fleet/v1.json");
        let v1 = raw(1, "dddddddd-dddd-4ddd-8ddd-dddddddddddd");
        process_configuration(
            &v1,
            now,
            "1.6.19",
            &repositories(),
            &Verifier(VerificationResult::Verified),
            &v1_path,
        );
        assert_eq!(
            authorize_desired_release(
                &v1_path,
                "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                1,
                now,
                "1.6.19",
                &repositories(),
                &Verifier(VerificationResult::Verified),
            ),
            Err(ReleaseAuthorizationDenial::SchemaV1)
        );
    }
}
