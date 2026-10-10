//! Verified TrackAI managed-fleet configuration.

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
pub struct ConfigurationEnvelope {
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
    let identity = (Some(parsed.configuration_id.clone()), Some(parsed.epoch));
    match verifier.verify(raw, &parsed.verification) {
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
    if envelope.schema_version != 1
        || envelope.epoch == 0
        || !valid_uuid(&envelope.configuration_id)
        || envelope.target_client_version.len() > 64
        || envelope
            .ring
            .as_ref()
            .is_some_and(|ring| ring.is_empty() || ring.len() > 64)
        || !envelope.verification.required
        || envelope.repository_policies.len() > 1_000
    {
        return Err(AcknowledgementResult::RejectedInvalid);
    }
    if envelope.target_client_version != client_version {
        return Err(AcknowledgementResult::RejectedIncompatible);
    }
    let issued_at =
        parse_time(&envelope.issued_at).ok_or(AcknowledgementResult::RejectedInvalid)?;
    if issued_at > now + chrono::Duration::minutes(5) {
        return Err(AcknowledgementResult::RejectedInvalid);
    }
    if let Some(valid_until) = envelope.valid_until.as_deref() {
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
    for policy in &envelope.repository_policies {
        let mut branch_patterns = HashSet::new();
        if !valid_uuid(&policy.repository_id)
            || !valid_uuid(&policy.enrollment_id)
            || !valid_uuid(&policy.grant_id)
            || policy.branch_patterns.is_empty()
            || policy.branch_patterns.len() > 64
            || policy.branch_patterns.iter().any(|pattern| {
                pattern.is_empty()
                    || pattern.len() > 255
                    || glob::Pattern::new(pattern).is_err()
                    || !branch_patterns.insert(pattern)
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
    if bootstrap.repository_count() < envelope.repository_policies.len() {
        return Err(AcknowledgementResult::RejectedInvalid);
    }
    Ok(envelope)
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
            if candidate.envelope.epoch == active.envelope.epoch
                && candidate.envelope.configuration_id == active.envelope.configuration_id
                && candidate.digest == active.digest =>
        {
            current.clone()
        }
        Some(active) if candidate.envelope.epoch > active.envelope.epoch => FleetState {
            active: Some(candidate),
            previous: Some(active.clone()),
        },
        Some(active)
            if current.previous.as_ref().is_some_and(|previous| {
                previous.envelope.epoch == candidate.envelope.epoch
                    && previous.envelope.configuration_id == candidate.envelope.configuration_id
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

    fn repositories() -> Repositories {
        Repositories(HashSet::from([
            "11111111-1111-4111-8111-111111111111".to_string()
        ]))
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
        assert_eq!(state.active.unwrap().envelope.epoch, 1);
        assert_eq!(state.previous.unwrap().envelope.epoch, 2);
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
        assert_eq!(state.active.unwrap().envelope.epoch, 2);
        assert_eq!(state.previous.unwrap().envelope.epoch, 1);
    }
}
