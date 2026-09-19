//! Tenant/repository delivery policy resolved by the asynchronous metrics worker.

use crate::metrics::attrs::attr_pos;
use crate::metrics::db::MetricDeliveryBinding;
use crate::metrics::pos_encoded::sparse_get_string;
use crate::metrics::types::MetricEvent;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::collections::HashMap;

pub const TRACKAI_DELIVERY_POLICY_FILE: &str = "trackai-delivery-policy.json";
pub const TRACKAI_CREDENTIAL_KEYRING_FILE: &str = "trackai-machine-credentials.json";
const TRACKAI_DELIVERY_POLICY_PATH_ENV: &str = "GIT_AI_TRACKAI_DELIVERY_POLICY_PATH";
const TRACKAI_CREDENTIAL_KEYRING_PATH_ENV: &str = "GIT_AI_TRACKAI_CREDENTIAL_KEYRING_PATH";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialKeyringError {
    InvalidDocument,
    UnsupportedVersion(u8),
    InvalidCredential,
    DuplicateKeyId,
}

impl std::fmt::Display for CredentialKeyringError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDocument => write!(formatter, "invalid machine credential keyring"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported machine credential keyring version: {version}"
                )
            }
            Self::InvalidCredential => write!(formatter, "invalid machine credential in keyring"),
            Self::DuplicateKeyId => write!(formatter, "duplicate machine credential key ID"),
        }
    }
}

impl std::error::Error for CredentialKeyringError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MachineCredentialKeyringDocument {
    version: u8,
    credentials: Vec<String>,
}

#[derive(Clone)]
pub struct MachineCredentialKeyring {
    credentials: HashMap<String, String>,
}

impl std::fmt::Debug for MachineCredentialKeyring {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MachineCredentialKeyring")
            .field("credential_count", &self.credentials.len())
            .finish()
    }
}

impl MachineCredentialKeyring {
    pub fn from_json(raw: &str) -> Result<Self, CredentialKeyringError> {
        let document: MachineCredentialKeyringDocument =
            serde_json::from_str(raw).map_err(|_| CredentialKeyringError::InvalidDocument)?;
        if document.version != 1 {
            return Err(CredentialKeyringError::UnsupportedVersion(document.version));
        }

        let mut credentials = HashMap::with_capacity(document.credentials.len());
        for credential in document.credentials {
            let key_id = parse_machine_credential_key_id(&credential)?;
            if credentials.insert(key_id, credential).is_some() {
                return Err(CredentialKeyringError::DuplicateKeyId);
            }
        }
        Ok(Self { credentials })
    }

    pub(crate) fn resolve(&self, key_id: &str) -> Option<&str> {
        self.credentials.get(key_id).map(String::as_str)
    }
}

fn parse_machine_credential_key_id(credential: &str) -> Result<String, CredentialKeyringError> {
    let mut parts = credential.split('.');
    let prefix = parts.next();
    let key_id = parts.next();
    let secret = parts.next();
    if prefix != Some("trk_v1") || parts.next().is_some() {
        return Err(CredentialKeyringError::InvalidCredential);
    }
    let key_id = key_id.ok_or(CredentialKeyringError::InvalidCredential)?;
    let secret = secret.ok_or(CredentialKeyringError::InvalidCredential)?;
    if !valid_base64url_component(key_id, 16) || !valid_base64url_component(secret, 43) {
        return Err(CredentialKeyringError::InvalidCredential);
    }
    Ok(key_id.to_string())
}

fn valid_base64url_component(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryPolicyError {
    InvalidDocument(String),
    UnsupportedVersion(u8),
    InvalidTenantId(String),
    InvalidBinding(String),
    DuplicateRepository { repository_url: String },
    MissingRepository,
    InvalidRepository { repository_url: String },
    RepositoryNotEnrolled { repository_url: String },
}

impl std::fmt::Display for DeliveryPolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDocument(error) => write!(formatter, "invalid delivery policy: {error}"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported delivery policy version: {version}")
            }
            Self::InvalidTenantId(_) => write!(formatter, "invalid delivery policy tenant ID"),
            Self::InvalidBinding(error) => write!(formatter, "invalid delivery binding: {error}"),
            Self::DuplicateRepository { repository_url } => {
                write!(
                    formatter,
                    "duplicate delivery policy repository: {repository_url}"
                )
            }
            Self::MissingRepository => write!(formatter, "metric event has no repository"),
            Self::InvalidRepository { repository_url } => {
                write!(
                    formatter,
                    "metric event repository is invalid: {repository_url}"
                )
            }
            Self::RepositoryNotEnrolled { repository_url } => {
                write!(
                    formatter,
                    "metric event repository is not enrolled: {repository_url}"
                )
            }
        }
    }
}

impl std::error::Error for DeliveryPolicyError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricDeliveryRuntimeError {
    Policy(DeliveryPolicyError),
    CredentialKeyring(CredentialKeyringError),
    PolicyFileUnavailable,
    CredentialFileUnavailable,
    HomeDirectoryUnavailable,
    IncompleteConfiguration,
    InsecureCredentialFilePermissions,
    InvalidBinding,
    CredentialNotFound { key_id: String },
}

impl std::fmt::Display for MetricDeliveryRuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(error) => error.fmt(formatter),
            Self::CredentialKeyring(error) => error.fmt(formatter),
            Self::PolicyFileUnavailable => write!(formatter, "delivery policy file is unavailable"),
            Self::CredentialFileUnavailable => {
                write!(formatter, "machine credential keyring file is unavailable")
            }
            Self::HomeDirectoryUnavailable => {
                write!(
                    formatter,
                    "home directory is unavailable for TrackAI delivery files"
                )
            }
            Self::IncompleteConfiguration => write!(
                formatter,
                "TrackAI delivery policy and credential keyring must be configured together"
            ),
            Self::InsecureCredentialFilePermissions => write!(
                formatter,
                "machine credential keyring must not be accessible by group or other users"
            ),
            Self::InvalidBinding => write!(formatter, "queued metric delivery binding is invalid"),
            Self::CredentialNotFound { key_id } => {
                write!(
                    formatter,
                    "machine credential key ID is unavailable: {key_id}"
                )
            }
        }
    }
}

impl std::error::Error for MetricDeliveryRuntimeError {}

impl From<DeliveryPolicyError> for MetricDeliveryRuntimeError {
    fn from(error: DeliveryPolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<CredentialKeyringError> for MetricDeliveryRuntimeError {
    fn from(error: CredentialKeyringError) -> Self {
        Self::CredentialKeyring(error)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryPolicyDocument {
    version: u8,
    repositories: Vec<DeliveryPolicyEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryPolicyEntry {
    repository_url: String,
    repository_id: Option<String>,
    tenant_id: String,
    api_base_url: String,
    credential_key_id: String,
}

#[derive(Debug, Clone)]
pub struct DeliveryPolicyCache {
    repositories: HashMap<String, DeliveryPolicyEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricDeliveryHealthBinding {
    pub tenant_id: String,
    pub api_base_url: String,
    pub credential_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceDeliveryBinding {
    pub repository_id: String,
    pub tenant_id: String,
    pub repository_url: String,
    pub api_base_url: String,
    pub credential_key_id: String,
}

impl DeliveryPolicyCache {
    pub fn from_json(raw: &str) -> Result<Self, DeliveryPolicyError> {
        let document: DeliveryPolicyDocument = serde_json::from_str(raw)
            .map_err(|error| DeliveryPolicyError::InvalidDocument(error.to_string()))?;
        if document.version != 1 {
            return Err(DeliveryPolicyError::UnsupportedVersion(document.version));
        }

        let mut repositories = HashMap::with_capacity(document.repositories.len());
        for mut entry in document.repositories {
            entry.repository_url = crate::repo_url::normalize_repo_url(&entry.repository_url)
                .map_err(|_| DeliveryPolicyError::InvalidRepository {
                    repository_url: entry.repository_url.clone(),
                })?;
            entry.api_base_url = normalize_api_base_url(&entry.api_base_url)?;
            if !valid_uuid(&entry.tenant_id) {
                return Err(DeliveryPolicyError::InvalidTenantId(entry.tenant_id));
            }
            if entry
                .repository_id
                .as_ref()
                .is_some_and(|value| !valid_uuid(value))
            {
                return Err(DeliveryPolicyError::InvalidBinding(
                    "repository ID must be a UUID".to_string(),
                ));
            }

            MetricDeliveryBinding {
                tenant_id: entry.tenant_id.clone(),
                repository_url: entry.repository_url.clone(),
                branch: None,
                api_base_url: entry.api_base_url.clone(),
                credential_key_id: entry.credential_key_id.clone(),
            }
            .validate()
            .map_err(|error| DeliveryPolicyError::InvalidBinding(error.to_string()))?;

            let repository_url = entry.repository_url.clone();
            if repositories.insert(repository_url.clone(), entry).is_some() {
                return Err(DeliveryPolicyError::DuplicateRepository { repository_url });
            }
        }
        Ok(Self { repositories })
    }

    pub fn resolve_event(
        &self,
        event: &MetricEvent,
    ) -> Result<MetricDeliveryBinding, DeliveryPolicyError> {
        let raw_repository = sparse_get_string(&event.attrs, attr_pos::REPO_URL)
            .flatten()
            .ok_or(DeliveryPolicyError::MissingRepository)?;
        let repository_url =
            crate::repo_url::normalize_repo_url(&raw_repository).map_err(|_| {
                DeliveryPolicyError::InvalidRepository {
                    repository_url: raw_repository,
                }
            })?;
        let entry = self.repositories.get(&repository_url).ok_or_else(|| {
            DeliveryPolicyError::RepositoryNotEnrolled {
                repository_url: repository_url.clone(),
            }
        })?;
        let binding = MetricDeliveryBinding {
            tenant_id: entry.tenant_id.clone(),
            repository_url,
            branch: sparse_get_string(&event.attrs, attr_pos::BRANCH).flatten(),
            api_base_url: entry.api_base_url.clone(),
            credential_key_id: entry.credential_key_id.clone(),
        };
        binding
            .validate()
            .map_err(|error| DeliveryPolicyError::InvalidBinding(error.to_string()))?;
        Ok(binding)
    }

    fn health_bindings(&self) -> Vec<MetricDeliveryHealthBinding> {
        let mut bindings = BTreeMap::new();
        for entry in self.repositories.values() {
            let key = (
                entry.tenant_id.clone(),
                entry.api_base_url.clone(),
                entry.credential_key_id.clone(),
            );
            bindings
                .entry(key.clone())
                .or_insert(MetricDeliveryHealthBinding {
                    tenant_id: key.0,
                    api_base_url: key.1,
                    credential_key_id: key.2,
                });
        }
        bindings.into_values().collect()
    }

    pub fn resolve_evidence_repository(
        &self,
        raw_repository: &str,
    ) -> Result<EvidenceDeliveryBinding, DeliveryPolicyError> {
        let repository_url = crate::repo_url::normalize_repo_url(raw_repository).map_err(|_| {
            DeliveryPolicyError::InvalidRepository {
                repository_url: raw_repository.to_string(),
            }
        })?;
        let entry = self.repositories.get(&repository_url).ok_or_else(|| {
            DeliveryPolicyError::RepositoryNotEnrolled {
                repository_url: repository_url.clone(),
            }
        })?;
        let repository_id = entry.repository_id.clone().ok_or_else(|| {
            DeliveryPolicyError::InvalidBinding(
                "repository ID is required for evidence collection".to_string(),
            )
        })?;
        Ok(EvidenceDeliveryBinding {
            repository_id,
            tenant_id: entry.tenant_id.clone(),
            repository_url,
            api_base_url: entry.api_base_url.clone(),
            credential_key_id: entry.credential_key_id.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct MetricDeliveryRuntime {
    policy: DeliveryPolicyCache,
    keyring: MachineCredentialKeyring,
}

impl MetricDeliveryRuntime {
    pub fn new(policy: DeliveryPolicyCache, keyring: MachineCredentialKeyring) -> Self {
        Self { policy, keyring }
    }

    pub fn load_from_paths(
        policy_path: &std::path::Path,
        credential_path: &std::path::Path,
    ) -> Result<Self, MetricDeliveryRuntimeError> {
        use std::io::Read;

        let policy_raw = std::fs::read_to_string(policy_path)
            .map_err(|_| MetricDeliveryRuntimeError::PolicyFileUnavailable)?;
        let mut credential_file = std::fs::File::open(credential_path)
            .map_err(|_| MetricDeliveryRuntimeError::CredentialFileUnavailable)?;
        let credential_metadata = credential_file
            .metadata()
            .map_err(|_| MetricDeliveryRuntimeError::CredentialFileUnavailable)?;
        if !credential_metadata.is_file() {
            return Err(MetricDeliveryRuntimeError::CredentialFileUnavailable);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if credential_metadata.permissions().mode() & 0o077 != 0 {
                return Err(MetricDeliveryRuntimeError::InsecureCredentialFilePermissions);
            }
        }

        let mut credential_raw = String::new();
        credential_file
            .read_to_string(&mut credential_raw)
            .map_err(|_| MetricDeliveryRuntimeError::CredentialFileUnavailable)?;
        Ok(Self::new(
            DeliveryPolicyCache::from_json(&policy_raw)?,
            MachineCredentialKeyring::from_json(&credential_raw)?,
        ))
    }

    pub fn load_optional_from_paths(
        policy_path: &std::path::Path,
        credential_path: &std::path::Path,
    ) -> Result<Option<Self>, MetricDeliveryRuntimeError> {
        let policy_exists = policy_path
            .try_exists()
            .map_err(|_| MetricDeliveryRuntimeError::PolicyFileUnavailable)?;
        let credential_exists = credential_path
            .try_exists()
            .map_err(|_| MetricDeliveryRuntimeError::CredentialFileUnavailable)?;
        match (policy_exists, credential_exists) {
            (false, false) => Ok(None),
            (true, true) => Self::load_from_paths(policy_path, credential_path).map(Some),
            _ => Err(MetricDeliveryRuntimeError::IncompleteConfiguration),
        }
    }

    pub fn load_optional_default() -> Result<Option<Self>, MetricDeliveryRuntimeError> {
        let base = dirs::home_dir()
            .ok_or(MetricDeliveryRuntimeError::HomeDirectoryUnavailable)?
            .join(".git-ai");
        let policy_path = nonempty_path_env(TRACKAI_DELIVERY_POLICY_PATH_ENV)
            .unwrap_or_else(|| base.join(TRACKAI_DELIVERY_POLICY_FILE));
        let credential_path = nonempty_path_env(TRACKAI_CREDENTIAL_KEYRING_PATH_ENV)
            .unwrap_or_else(|| base.join(TRACKAI_CREDENTIAL_KEYRING_FILE));
        Self::load_optional_from_paths(&policy_path, &credential_path)
    }

    pub fn bind_event(
        &self,
        event: &MetricEvent,
    ) -> Result<MetricDeliveryBinding, MetricDeliveryRuntimeError> {
        self.policy.resolve_event(event).map_err(Into::into)
    }

    pub fn credential_for_binding<'a>(
        &'a self,
        binding: &MetricDeliveryBinding,
    ) -> Result<&'a str, MetricDeliveryRuntimeError> {
        binding
            .validate()
            .map_err(|_| MetricDeliveryRuntimeError::InvalidBinding)?;
        self.keyring
            .resolve(&binding.credential_key_id)
            .ok_or_else(|| MetricDeliveryRuntimeError::CredentialNotFound {
                key_id: binding.credential_key_id.clone(),
            })
    }

    pub fn health_bindings(&self) -> Vec<MetricDeliveryHealthBinding> {
        self.policy.health_bindings()
    }

    pub fn bind_evidence_repository(
        &self,
        repository_url: &str,
    ) -> Result<EvidenceDeliveryBinding, MetricDeliveryRuntimeError> {
        self.policy
            .resolve_evidence_repository(repository_url)
            .map_err(Into::into)
    }

    pub fn credential_for_evidence_binding<'a>(
        &'a self,
        binding: &EvidenceDeliveryBinding,
    ) -> Result<&'a str, MetricDeliveryRuntimeError> {
        self.keyring
            .resolve(&binding.credential_key_id)
            .ok_or_else(|| MetricDeliveryRuntimeError::CredentialNotFound {
                key_id: binding.credential_key_id.clone(),
            })
    }

    pub fn credential_for_health_binding<'a>(
        &'a self,
        binding: &MetricDeliveryHealthBinding,
    ) -> Result<&'a str, MetricDeliveryRuntimeError> {
        self.keyring
            .resolve(&binding.credential_key_id)
            .ok_or_else(|| MetricDeliveryRuntimeError::CredentialNotFound {
                key_id: binding.credential_key_id.clone(),
            })
    }
}

fn nonempty_path_env(name: &str) -> Option<std::path::PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
}

fn normalize_api_base_url(raw: &str) -> Result<String, DeliveryPolicyError> {
    let parsed = url::Url::parse(raw)
        .map_err(|error| DeliveryPolicyError::InvalidBinding(error.to_string()))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(DeliveryPolicyError::InvalidBinding(
            "API base URL must be HTTP(S), without credentials, query, or fragment".to_string(),
        ));
    }
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::EventAttributes;
    use crate::metrics::pos_encoded::PosEncoded;
    use crate::metrics::types::MetricEvent;

    fn event(repo_url: Option<&str>, branch: Option<&str>) -> MetricEvent {
        let mut attrs = EventAttributes::with_version("test");
        if let Some(repo_url) = repo_url {
            attrs = attrs.repo_url(repo_url);
        }
        if let Some(branch) = branch {
            attrs = attrs.branch(branch);
        }
        MetricEvent {
            timestamp: 1,
            event_id: 1,
            values: Default::default(),
            attrs: attrs.to_sparse(),
        }
    }

    fn policy_json() -> &'static str {
        r#"{
            "version": 1,
            "repositories": [
                {
                    "repository_url": "git@github.com:example/company-a.git",
                    "repository_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "tenant_id": "11111111-1111-4111-8111-111111111111",
                    "api_base_url": "https://trackai.example.test/",
                    "credential_key_id": "company-a-key-id"
                },
                {
                    "repository_url": "https://github.com/example/company-b",
                    "repository_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    "tenant_id": "22222222-2222-4222-8222-222222222222",
                    "api_base_url": "https://trackai.example.test",
                    "credential_key_id": "company-b-key-id"
                }
            ]
        }"#
    }

    #[test]
    fn test_delivery_policy_resolves_two_tenants_and_captures_branch() {
        let policy = DeliveryPolicyCache::from_json(policy_json()).unwrap();

        let company_a = policy
            .resolve_event(&event(
                Some("https://github.com/example/company-a"),
                Some("feature/task4"),
            ))
            .unwrap();
        let company_b = policy
            .resolve_event(&event(
                Some("git@github.com:example/company-b.git"),
                Some("release"),
            ))
            .unwrap();

        assert_eq!(company_a.tenant_id, "11111111-1111-4111-8111-111111111111");
        assert_eq!(
            company_a.repository_url,
            "https://github.com/example/company-a"
        );
        assert_eq!(company_a.branch.as_deref(), Some("feature/task4"));
        assert_eq!(company_a.api_base_url, "https://trackai.example.test");
        assert_eq!(company_a.credential_key_id, "company-a-key-id");
        assert_eq!(company_b.tenant_id, "22222222-2222-4222-8222-222222222222");
        assert_eq!(company_b.credential_key_id, "company-b-key-id");
    }

    #[test]
    fn test_evidence_binding_requires_and_returns_server_repository_id() {
        let policy = DeliveryPolicyCache::from_json(policy_json()).unwrap();
        let binding = policy
            .resolve_evidence_repository("git@github.com:example/company-a.git")
            .unwrap();
        assert_eq!(
            binding.repository_id,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        );
        assert_eq!(
            binding.repository_url,
            "https://github.com/example/company-a"
        );

        let without_id = policy_json().replace(
            "\"repository_id\": \"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\",",
            "",
        );
        let policy = DeliveryPolicyCache::from_json(&without_id).unwrap();
        assert!(matches!(
            policy.resolve_evidence_repository("https://github.com/example/company-a"),
            Err(DeliveryPolicyError::InvalidBinding(_))
        ));
    }

    #[test]
    fn test_delivery_health_bindings_are_deduplicated_without_crossing_tenants() {
        let expanded = policy_json().replace(
            r#"{
                    "repository_url": "https://github.com/example/company-b","#,
            r#"{
                    "repository_url": "https://github.com/example/company-a-two",
                    "tenant_id": "11111111-1111-4111-8111-111111111111",
                    "api_base_url": "https://trackai.example.test",
                    "credential_key_id": "company-a-key-id"
                },
                {
                    "repository_url": "https://github.com/example/company-b","#,
        );
        let policy = DeliveryPolicyCache::from_json(&expanded).unwrap();
        let bindings = policy.health_bindings();
        assert_eq!(bindings.len(), 2);
        assert_eq!(
            bindings[0].tenant_id,
            "11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(bindings[0].credential_key_id, "company-a-key-id");
        assert_eq!(
            bindings[1].tenant_id,
            "22222222-2222-4222-8222-222222222222"
        );
        assert_eq!(bindings[1].credential_key_id, "company-b-key-id");
    }

    #[test]
    fn test_delivery_policy_fails_closed_for_missing_or_unknown_repository() {
        let policy = DeliveryPolicyCache::from_json(policy_json()).unwrap();

        assert!(matches!(
            policy.resolve_event(&event(None, Some("main"))),
            Err(DeliveryPolicyError::MissingRepository)
        ));
        assert!(matches!(
            policy.resolve_event(&event(
                Some("https://github.com/example/not-enrolled"),
                Some("main"),
            )),
            Err(DeliveryPolicyError::RepositoryNotEnrolled { .. })
        ));
    }

    #[test]
    fn test_delivery_policy_rejects_ambiguous_normalized_repository() {
        let duplicated = policy_json().replace(
            "https://github.com/example/company-b",
            "https://github.com/example/company-a.git",
        );

        assert!(matches!(
            DeliveryPolicyCache::from_json(&duplicated),
            Err(DeliveryPolicyError::DuplicateRepository { .. })
        ));
    }

    fn machine_token(key_id: &str, secret_byte: char) -> String {
        format!("trk_v1.{key_id}.{}", secret_byte.to_string().repeat(43))
    }

    #[test]
    fn test_machine_credential_keyring_selects_exact_key_and_redacts_debug() {
        let company_a = machine_token("company-a-key-id", 'A');
        let company_b = machine_token("company-b-key-id", 'B');
        let raw = serde_json::json!({
            "version": 1,
            "credentials": [company_a, company_b],
        })
        .to_string();

        let keyring = MachineCredentialKeyring::from_json(&raw).unwrap();

        assert_eq!(
            keyring.resolve("company-a-key-id"),
            Some(company_a.as_str())
        );
        assert_eq!(keyring.resolve("not-in-keyring-id"), None);
        let debug = format!("{keyring:?}");
        assert!(debug.contains("credential_count: 2"));
        assert!(!debug.contains(&company_a));
        assert!(!debug.contains(&company_b));
    }

    #[test]
    fn test_machine_credential_keyring_rejects_malformed_and_duplicate_keys() {
        let duplicate = machine_token("company-a-key-id", 'A');
        let duplicated_raw = serde_json::json!({
            "version": 1,
            "credentials": [duplicate, machine_token("company-a-key-id", 'B')],
        })
        .to_string();
        assert!(matches!(
            MachineCredentialKeyring::from_json(&duplicated_raw),
            Err(CredentialKeyringError::DuplicateKeyId)
        ));

        let malformed_raw = serde_json::json!({
            "version": 1,
            "credentials": ["trk_v1.not-a-valid-key.short"],
        })
        .to_string();
        assert!(matches!(
            MachineCredentialKeyring::from_json(&malformed_raw),
            Err(CredentialKeyringError::InvalidCredential)
        ));
    }

    #[test]
    fn test_queued_binding_uses_exact_rotation_key_without_global_fallback() {
        let old_token = machine_token("company-a-key-id", 'A');
        let new_token = machine_token("company-n-key-id", 'N');
        let overlap_keyring = MachineCredentialKeyring::from_json(
            &serde_json::json!({
                "version": 1,
                "credentials": [old_token, new_token],
            })
            .to_string(),
        )
        .unwrap();
        let policy = DeliveryPolicyCache::from_json(policy_json()).unwrap();
        let runtime = MetricDeliveryRuntime::new(policy, overlap_keyring);
        let queued_binding = runtime
            .bind_event(&event(
                Some("https://github.com/example/company-a"),
                Some("main"),
            ))
            .unwrap();

        assert_eq!(
            runtime.credential_for_binding(&queued_binding).unwrap(),
            machine_token("company-a-key-id", 'A')
        );

        let retired_keyring = MachineCredentialKeyring::from_json(
            &serde_json::json!({
                "version": 1,
                "credentials": [machine_token("company-n-key-id", 'N')],
            })
            .to_string(),
        )
        .unwrap();
        let retired_runtime = MetricDeliveryRuntime::new(
            DeliveryPolicyCache::from_json(policy_json()).unwrap(),
            retired_keyring,
        );
        assert!(matches!(
            retired_runtime.credential_for_binding(&queued_binding),
            Err(MetricDeliveryRuntimeError::CredentialNotFound { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn test_delivery_runtime_loads_owner_only_keyring_after_restart() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::TempDir::new().unwrap();
        let policy_path = temp.path().join("trackai-delivery-policy.json");
        let keyring_path = temp.path().join("trackai-machine-credentials.json");
        let token = machine_token("company-a-key-id", 'A');
        std::fs::write(&policy_path, policy_json()).unwrap();
        std::fs::write(
            &keyring_path,
            serde_json::json!({"version": 1, "credentials": [token]}).to_string(),
        )
        .unwrap();
        std::fs::set_permissions(&keyring_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let runtime = MetricDeliveryRuntime::load_from_paths(&policy_path, &keyring_path).unwrap();
        let binding = runtime
            .bind_event(&event(
                Some("https://github.com/example/company-a"),
                Some("main"),
            ))
            .unwrap();
        assert_eq!(runtime.credential_for_binding(&binding).unwrap(), token);
    }

    #[cfg(unix)]
    #[test]
    fn test_delivery_runtime_rejects_group_readable_keyring() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::TempDir::new().unwrap();
        let policy_path = temp.path().join("trackai-delivery-policy.json");
        let keyring_path = temp.path().join("trackai-machine-credentials.json");
        let token = machine_token("company-a-key-id", 'A');
        std::fs::write(&policy_path, policy_json()).unwrap();
        std::fs::write(
            &keyring_path,
            serde_json::json!({"version": 1, "credentials": [token]}).to_string(),
        )
        .unwrap();
        std::fs::set_permissions(&keyring_path, std::fs::Permissions::from_mode(0o640)).unwrap();

        assert!(matches!(
            MetricDeliveryRuntime::load_from_paths(&policy_path, &keyring_path),
            Err(MetricDeliveryRuntimeError::InsecureCredentialFilePermissions)
        ));
    }

    #[test]
    fn test_optional_delivery_runtime_distinguishes_disabled_from_incomplete() {
        let temp = tempfile::TempDir::new().unwrap();
        let policy_path = temp.path().join("trackai-delivery-policy.json");
        let keyring_path = temp.path().join("trackai-machine-credentials.json");

        assert!(
            MetricDeliveryRuntime::load_optional_from_paths(&policy_path, &keyring_path)
                .unwrap()
                .is_none()
        );

        std::fs::write(&policy_path, policy_json()).unwrap();
        assert!(matches!(
            MetricDeliveryRuntime::load_optional_from_paths(&policy_path, &keyring_path),
            Err(MetricDeliveryRuntimeError::IncompleteConfiguration)
        ));
    }
}
