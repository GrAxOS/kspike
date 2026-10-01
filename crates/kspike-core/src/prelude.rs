//! Convenience re-exports for module authors.

pub use crate::error::{KSpikeError, Result};
pub use crate::event::{Event, EventKind, Severity};
pub use crate::evidence::EvidenceRecord;
pub use crate::humility::{KnownLimits, Limitation};
pub use crate::module::{Module, ModuleKind, ModuleMeta, ModuleVerdict};
pub use crate::signal::{Signal, SignalSource, ThreatLevel};
pub use crate::cognitive::{CognitiveConstraint, CognitiveLobe};
pub use anyhow::Context;
pub use chrono::{DateTime, Utc};
pub use serde::{Deserialize, Serialize};
pub use tracing::{debug, error, info, trace, warn};
