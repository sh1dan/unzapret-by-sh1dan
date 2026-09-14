use crate::core::{PacketContext, RunMode};
use crate::filtering::FilterDecision;

/// Plans are validated by the engine; strategies never send packets themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessResult {
    PassThrough,
    /// TCP payload offset, not an IP packet or TLS-record offset.
    SplitTcp { payload_offset: usize },
    WouldModify,
}

pub trait Strategy: Send + Sync {
    fn name(&self) -> &'static str;
    fn matches(&self, context: &PacketContext<'_>) -> bool;
    fn process(&self, context: &PacketContext<'_>) -> ProcessResult;
}

pub mod split_tcp;
pub use split_tcp::SplitTcp;

pub struct PassThrough;

impl Strategy for PassThrough {
    fn name(&self) -> &'static str { "pass-through" }
    fn matches(&self, _: &PacketContext<'_>) -> bool { true }
    fn process(&self, _: &PacketContext<'_>) -> ProcessResult { ProcessResult::PassThrough }
}

/// Gate shared by the future engine. This alone does not validate packet syntax.
/// Only the engine may attach a trusted filter decision after parsing/filtering.
pub fn evaluate(strategy: &dyn Strategy, context: &PacketContext<'_>, mode: RunMode)
    -> ProcessResult
{
    if context.filter != FilterDecision::Allow || !context.initial_payload {
        return ProcessResult::PassThrough;
    }
    if !strategy.matches(context) { return ProcessResult::PassThrough; }
    let result = strategy.process(context);
    if mode == RunMode::DryRun && result != ProcessResult::PassThrough {
        ProcessResult::WouldModify
    } else {
        result
    }
}

