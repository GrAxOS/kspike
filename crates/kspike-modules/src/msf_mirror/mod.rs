//! MSF-Mirror modules — built-in, kernel-native equivalents of
//! Metasploit's most famous offensive modules, inverted for defense.
//!
//! Every module here is:
//!   • compiled into the engine when its Cargo feature is enabled
//!   • driven by kspike-kernel taps (packet/memory/procfs)
//!   • judge-gated for any offensive effect

pub mod eternalblue;
pub mod psexec;
pub mod log4shell;
pub mod cred_canary;
pub mod shikata;
pub mod meterpreter;
pub mod kerberoast;
pub mod canary_token;

pub use eternalblue::{EternalBlueProbeDetector, SmbV1Killswitch};
pub use psexec::PsExecAbuseDetector;
pub use log4shell::Log4ShellJndiDetector;
pub use cred_canary::CredDumpCanaryDefender;
pub use shikata::ShikataPolymorphicDetector;
pub use meterpreter::MeterpreterBeaconDetector;
#[cfg(feature = "strikers")]
pub use meterpreter::MeterpreterSinkholeStriker;
pub use kerberoast::KerberoastDetector;
pub use canary_token::CanaryTokenDeception;
