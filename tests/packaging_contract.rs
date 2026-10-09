//! Thin driver for the Task9b package contract living under `packaging/tests/`.
//! The assertions themselves are dependency-free and live in
//! `packaging/tests/contract.rs` next to the installers they pin.

#[path = "../packaging/tests/contract.rs"]
mod contract;
