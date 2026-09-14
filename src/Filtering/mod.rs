use crate::core::PacketContext;

pub mod list;
pub mod engine;
pub use engine::FilterEngine;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterDecision { Allow, Exclude, NoMatch, Unknown }

/// Exclusion always wins. Unknown classification never authorizes a strategy.
pub trait DestinationFilter {
    fn evaluate(&self, context: &PacketContext<'_>) -> FilterDecision;
}

/// Phase 1 default until a validated allowlist engine exists.
pub struct DenyAll;

impl DestinationFilter for DenyAll {
    fn evaluate(&self, _: &PacketContext<'_>) -> FilterDecision {
        FilterDecision::NoMatch
    }
}

