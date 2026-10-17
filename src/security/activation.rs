//! Activation lease read interface. Task20g supplies the verified context.

pub use crate::security::records::ProjectionLease as LeaseSnapshot;

pub trait SecurityLeaseContext: Send + Sync {
    fn current(&self) -> Option<LeaseSnapshot>;
    fn issued(&self, lease_id: &str) -> Option<LeaseSnapshot>;
}

#[derive(Debug, Default)]
pub struct UnavailableLeaseContext;

impl SecurityLeaseContext for UnavailableLeaseContext {
    fn current(&self) -> Option<LeaseSnapshot> {
        None
    }

    fn issued(&self, _lease_id: &str) -> Option<LeaseSnapshot> {
        None
    }
}

pub static UNAVAILABLE_LEASE_CONTEXT: UnavailableLeaseContext = UnavailableLeaseContext;
