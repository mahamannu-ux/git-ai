//! Durable, fail-closed security activation state.

use crate::error::GitAiError;
use crate::security::activation::{LeaseSnapshot, SecurityLeaseContext};
use crate::security::records::SecurityDataSettings;
use crate::trust::TrustedDocumentRef;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

pub const SECURITY_STATE_FILE: &str = "state.json";
const MAX_ACCEPTED_LEASES: usize = 20;
const LEASE_HISTORY_DAYS: i64 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseMode {
    Off,
    Monitor,
    MonitorAndPilotBlock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedLease {
    pub lease_id: String,
    pub bundle_digest: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub data_settings: SecurityDataSettings,
    pub mode: LeaseMode,
    pub agents: Vec<String>,
    pub day_one_scan: bool,
    /// The exact DSSE JSON bytes returned by the server.
    pub signed_bytes: Vec<u8>,
}

impl AcceptedLease {
    fn snapshot(&self) -> LeaseSnapshot {
        LeaseSnapshot {
            lease_id: self.lease_id.clone(),
            bundle_digest: self.bundle_digest.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            data_settings: self.data_settings.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableSecurityState {
    #[serde(default)]
    pub enrolled_tenant_id: Option<String>,
    #[serde(default)]
    pub enrolled_machine_id: Option<String>,
    #[serde(default)]
    pub accepted_leases: Vec<AcceptedLease>,
    pub applied_epoch: Option<u64>,
    pub applied_digest: Option<String>,
    #[serde(default)]
    pub acknowledgements: BTreeMap<String, PersistedAcknowledgement>,
    #[serde(default)]
    pub last_trusted: BTreeMap<String, TrustedDocumentRef>,
    pub trusted_time_floor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedAcknowledgement {
    pub body: serde_json::Value,
    pub sent: bool,
}

#[derive(Debug, Clone)]
pub struct LeaseStateStore {
    path: PathBuf,
    state: Arc<RwLock<DurableSecurityState>>,
}

impl LeaseStateStore {
    /// A missing or malformed state file deliberately restores an empty/off state.
    pub fn load(state_dir: &Path) -> Self {
        let path = state_dir.join(SECURITY_STATE_FILE);
        let state = fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self {
            path,
            state: Arc::new(RwLock::new(state)),
        }
    }

    #[cfg(test)]
    pub fn from_state(state_dir: &Path, state: DurableSecurityState) -> Self {
        Self {
            path: state_dir.join(SECURITY_STATE_FILE),
            state: Arc::new(RwLock::new(state)),
        }
    }

    pub fn snapshot(&self) -> DurableSecurityState {
        self.state
            .read()
            .map(|value| value.clone())
            .unwrap_or_default()
    }

    pub fn replace(
        &self,
        mut next: DurableSecurityState,
        now: DateTime<Utc>,
    ) -> Result<(), GitAiError> {
        next.accepted_leases
            .retain(|lease| lease.expires_at >= now - Duration::days(LEASE_HISTORY_DAYS));
        next.accepted_leases.sort_by_key(|lease| lease.issued_at);
        if next.accepted_leases.len() > MAX_ACCEPTED_LEASES {
            next.accepted_leases
                .drain(..next.accepted_leases.len() - MAX_ACCEPTED_LEASES);
        }
        self.write_atomic(&next)?;
        *self
            .state
            .write()
            .map_err(|_| GitAiError::Generic("security state lock poisoned".into()))? = next;
        Ok(())
    }

    pub fn state_path(&self) -> &Path {
        &self.path
    }

    fn write_atomic(&self, state: &DurableSecurityState) -> Result<(), GitAiError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| GitAiError::Generic("security state path is invalid".into()))?;
        fs::create_dir_all(parent)?;
        let temporary = parent.join("state.json.tmp");
        let bytes = serde_json::to_vec(state)?;
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, &self.path)?;
        if let Ok(directory) = fs::File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    }

    fn current_at(&self, now: DateTime<Utc>) -> Option<LeaseSnapshot> {
        self.state
            .read()
            .ok()?
            .accepted_leases
            .iter()
            .rev()
            .find(|lease| {
                lease.mode != LeaseMode::Off && lease.issued_at <= now && now < lease.expires_at
            })
            .map(AcceptedLease::snapshot)
    }
}

impl SecurityLeaseContext for LeaseStateStore {
    fn current(&self) -> Option<LeaseSnapshot> {
        self.current_at(Utc::now())
    }

    fn lease_at(&self, at: DateTime<Utc>) -> Option<LeaseSnapshot> {
        self.state
            .read()
            .ok()?
            .accepted_leases
            .iter()
            .rev()
            .find(|lease| {
                lease.mode != LeaseMode::Off && lease.issued_at <= at && at < lease.expires_at
            })
            .map(AcceptedLease::snapshot)
    }

    fn issued(&self, lease_id: &str) -> Option<LeaseSnapshot> {
        let cutoff = Utc::now() - Duration::days(LEASE_HISTORY_DAYS);
        self.state
            .read()
            .ok()?
            .accepted_leases
            .iter()
            .rev()
            .find(|lease| lease.lease_id == lease_id && lease.expires_at >= cutoff)
            .map(AcceptedLease::snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn lease(id: usize, issued: i64, expires: i64, mode: LeaseMode) -> AcceptedLease {
        AcceptedLease {
            lease_id: format!("lease-{id}"),
            bundle_digest: format!("{id:064x}"),
            issued_at: Utc.timestamp_opt(issued, 0).unwrap(),
            expires_at: Utc.timestamp_opt(expires, 0).unwrap(),
            data_settings: SecurityDataSettings::ALL_OFF,
            mode,
            agents: if mode == LeaseMode::Off {
                Vec::new()
            } else {
                vec!["codex".into()]
            },
            day_one_scan: false,
            signed_bytes: vec![id as u8],
        }
    }

    #[test]
    fn missing_or_corrupt_state_is_off() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path()).unwrap();
        fs::write(temp.path().join(SECURITY_STATE_FILE), b"not json").unwrap();
        let store = LeaseStateStore::load(temp.path());
        assert!(
            store
                .current_at(Utc.timestamp_opt(100, 0).unwrap())
                .is_none()
        );
    }

    #[test]
    fn persisted_context_restores_current_and_previous_lease() {
        let temp = tempfile::tempdir().unwrap();
        let store = LeaseStateStore::load(temp.path());
        let state = DurableSecurityState {
            accepted_leases: vec![
                lease(1, 10, 80, LeaseMode::Monitor),
                lease(2, 80, 200, LeaseMode::MonitorAndPilotBlock),
            ],
            ..Default::default()
        };
        store
            .replace(state, Utc.timestamp_opt(100, 0).unwrap())
            .unwrap();
        let restored = LeaseStateStore::load(temp.path());
        assert_eq!(
            restored
                .current_at(Utc.timestamp_opt(100, 0).unwrap())
                .unwrap()
                .lease_id,
            "lease-2"
        );
        assert_eq!(
            restored
                .lease_at(Utc.timestamp_opt(50, 0).unwrap())
                .unwrap()
                .lease_id,
            "lease-1"
        );
    }

    #[test]
    fn off_and_expired_leases_never_activate_and_history_is_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let store = LeaseStateStore::load(temp.path());
        let now = Utc.timestamp_opt(1_000_000, 0).unwrap();
        let mut leases = (0..25)
            .map(|id| lease(id, 999_000 + id as i64, 2_000_000, LeaseMode::Monitor))
            .collect::<Vec<_>>();
        leases.push(lease(30, 1_000_000, 2_000_000, LeaseMode::Off));
        store
            .replace(
                DurableSecurityState {
                    accepted_leases: leases,
                    ..Default::default()
                },
                now,
            )
            .unwrap();
        assert_eq!(store.snapshot().accepted_leases.len(), MAX_ACCEPTED_LEASES);
        assert_ne!(store.current_at(now).unwrap().lease_id, "lease-30");
        assert!(
            store
                .current_at(Utc.timestamp_opt(3_000_000, 0).unwrap())
                .is_none()
        );
    }
}
