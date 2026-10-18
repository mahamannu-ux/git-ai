//! Activation lease read interface. Task20g supplies the verified context.

pub use crate::security::records::ProjectionLease as LeaseSnapshot;
use chrono::{DateTime, Utc};

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
