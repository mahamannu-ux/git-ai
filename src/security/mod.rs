//! TrackAI Endpoint security-v2 record shipping.

pub mod activation;
pub mod delivery;
pub mod delivery_queue;
pub mod records;
pub mod shipper;
pub mod tail;

/// Retained only for the legacy daemon control response. Task6 evaluation is
/// retired; production remains off until Task20g supplies a lease context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorMode {
    Off,
}
