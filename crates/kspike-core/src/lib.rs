//! KSpike Core
//! ============
//!
//! Foundation layer for the KSpike dual-mode kernel defense framework.
//!
//! Principles:
//!   1. Epistemic humility — every module declares its own limitations.
//!   2. No silent action — every decision emits an immutable evidence record.
//!   3. Judge-gated force — offensive modules cannot fire without explicit
//!      Casper-backed authorization (see `kspike-judge`).
//!   4. Sovereignty — no telemetry, no phone-home, no hidden channels.
//!
//! This crate exposes the `Module` trait, the `EventBus`, the `EvidenceLedger`,
//! and the primitive types shared across the workspace.

pub mod module;
pub mod event;
pub mod evidence;
pub mod signal;
pub mod cognitive;
pub mod error;
pub mod humility;
pub mod prelude;

pub use module::{Module, ModuleKind, ModuleMeta, ModuleVerdict};
pub use event::{Event, EventBus, EventKind, Severity};
pub use evidence::{EvidenceLedger, EvidenceRecord, Signer};
pub use signal::{Signal, SignalSource, ThreatLevel};
pub use cognitive::{CognitiveConstraint, CognitiveLobe};
pub use error::{KSpikeError, Result};
pub use humility::{Limitation, KnownLimits};

/// Framework version — mirrors Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Framework banner — printed on CLI startup.
pub const BANNER: &str = r#"
  ╦╔═╔═╗┌─┐┬┬┌─┌─┐    dual-mode kernel defense framework
  ╠╩╗╚═╗├─┘│├┴┐├┤     Casper-governed · Sovereignty-first
  ╩ ╩╚═╝┴  ┴┴ ┴└─┘    "اعرف عدوك لتحميه من أن يؤذيك"
"#;
