//! CasperJudge — bridge from the Rust `Judge` trait to the C11 Casper Engine.
//!
//! Two modes:
//!   * default            : stub (compiles anywhere; returns `uncertain`).
//!   * feature = link_casper: actually dlopen's libcasper.so and calls
//!                            `casper_judge_evaluate(json_req, buf, buflen)`.
//!
//! The FFI surface we depend on (kept tiny):
//!
//! ```text
//! int casper_init(const char* model_path);
//! // Evaluate a judgment request encoded as JSON. Writes a JSON response
//! // into `out`. Returns the number of bytes written, or -1 on error.
//! int casper_judge_evaluate(const char* req_json,
//!                           char* out, int out_cap);
//! void casper_shutdown(void);
//! ```
//!
//! The Casper Engine lives at https://github.com/Grar00t/Casper_Engine.
//! Header & ABI documented in that repo's `casper_ffi.h` (planned).

pub mod judge;
pub mod cognitive;
pub mod ffi;

pub use judge::CasperJudge;
pub use cognitive::CasperCognitiveLobe;
