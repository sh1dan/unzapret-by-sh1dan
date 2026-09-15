//! Phase 2: bounded inspection and byte-exact pass-through. No DPI modification.
#![forbid(unsafe_code)]

#[path = "PacketCapture/mod.rs"]
pub mod capture;
#[path = "CLI/mod.rs"]
pub mod cli;
#[path = "Core/mod.rs"]
pub mod core;
#[path = "Diagnostics/mod.rs"]
pub mod diagnostics;
#[path = "Filtering/mod.rs"]
pub mod filtering;
#[path = "Service/mod.rs"]
pub mod service;
#[path = "Strategies/mod.rs"]
pub mod strategies;
