//! Activation lease read interface. Task20g supplies the verified context.

pub use crate::security::records::ProjectionLease as LeaseSnapshot;
use chrono::{DateTime, Utc};
use std::sync::OnceLock;

pub trait SecurityLeaseContext: Send + Sync {
    fn current(&self) -> Option<LeaseSnapshot>;
    /// Returns the retained lease whose validity window covers `at`.
    fn lease_at(&self, at: DateTime<Utc>) -> Option<LeaseSnapshot>;
    fn issued(&self, lease_id: &str) -> Option<LeaseSnapshot>;
}

#[derive(Debug, Default)]
pub struct UnavailableLeaseContext;

impl SecurityLeaseContext for UnavailableLeaseContext {
    fn current(&self) -> Option<LeaseSnapshot> {
        None
    }

    fn lease_at(&self, _at: DateTime<Utc>) -> Option<LeaseSnapshot> {
        None
    }

    fn issued(&self, _lease_id: &str) -> Option<LeaseSnapshot> {
        None
    }
}

pub static UNAVAILABLE_LEASE_CONTEXT: UnavailableLeaseContext = UnavailableLeaseContext;

/// Process-wide durable lease context shared by policy refresh, tailing and delivery.
pub fn configured_lease_context() -> &'static crate::security::lease_state::LeaseStateStore {
    static CONTEXT: OnceLock<crate::security::lease_state::LeaseStateStore> = OnceLock::new();
    CONTEXT.get_or_init(|| {
        let state_dir = crate::config::internal_dir_path()
            .unwrap_or_else(|| std::path::PathBuf::from(".git-ai/internal"))
            .join(crate::security::policy_apply::SECURITY_STATE_DIR);
        crate::security::lease_state::LeaseStateStore::load(&state_dir)
    })
}
