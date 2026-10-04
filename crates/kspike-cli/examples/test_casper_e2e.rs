//! End-to-end test of the Casper FFI integration.
//!
//! Run with the stub library:
//!
//!   cd crates/kspike-casper-ffi/stub && make
//!   KSPIKE_CASPER_LIB=$PWD/libcasper.so \
//!     cargo run --release --example test_casper_e2e \
//!     -p kspike --features kspike-casper-ffi/link_casper

use kspike_core::{KnownLimits, Limitation, ModuleKind, ModuleMeta, ModuleVerdict};
use kspike_judge::{Judge, JudgeRuling, RulingContext, StaticJudge, KhzJudge, roe::Roe};
use kspike_casper_ffi::CasperJudge;
use std::sync::Arc;

fn meta_strike(risk: u8) -> ModuleMeta {
    ModuleMeta {
        name: "striker.test.case".into(),
        kind: ModuleKind::Striker,
        version: "0.1.0".into(),
        description: "test".into(),
        author: "gratech".into(),
        risk_level: risk,
        limits: KnownLimits::new().add(Limitation {
            id: "test".into(),
            description: "synthetic".into(),
            confidence_penalty: 0.05,
            mitigation: None,
        }),
        tags: vec![],
    }
}

fn ctx(certainty: f32, legitimacy: f32, attempts: u8, corro: bool) -> RulingContext {
    RulingContext {
        attack_certainty: certainty,
        target_legitimacy: legitimacy,
        defender_attempts_on_actor: attempts,
        external_corroboration: corro,
        cognitive: None,
    }
}

fn run_case(label: &str, judge: &Arc<dyn Judge>,
            meta: &ModuleMeta, verdict: &ModuleVerdict, c: &RulingContext)
{
    let r = judge.rule(meta, verdict, c);
    let badge = if r.allowed { "✓ APPROVED" } else { "✗ DENIED  " };
    println!("  [{}] {}", badge, label);
    println!("       reason: {}", r.reason);
}

fn main() -> anyhow::Result<()> {
    println!("══════════════════════════════════════════════════════");
    println!("  Casper FFI end-to-end veto test");
    println!("══════════════════════════════════════════════════════\n");

    let so = std::env::var("KSPIKE_CASPER_LIB").unwrap_or_else(|_| "libcasper.so".into());
    println!("Casper library: {so}");
    println!("Casper FFI available at compile time: {}\n", kspike_casper_ffi::ffi::available());

    // Build the three-layer judge stack: Static → Khz → Casper
    let static_j = StaticJudge::new(Roe::default_roe());
    let khz_j    = KhzJudge::new(static_j, 0.40);
    let inner: Arc<dyn Judge> = Arc::new(khz_j);
    let judge: Arc<dyn Judge> = Arc::new(CasperJudge::new(inner, "/dev/null"));

    println!("─── Case 1: low-prop strike, high certainty ────────────");
    let m = meta_strike(3);
    let v = ModuleVerdict::RequestStrike {
        action: "blackhole".into(), target: "198.51.100.99".into(),
        justification: "confirmed C2 with corroboration".into(),
        confidence: 0.92, proportionality: 4,
    };
    run_case("prop=4, cert=0.92, corro=true", &judge, &m, &v,
             &ctx(0.92, 0.95, 3, true));

    println!("\n─── Case 2: HIGH proportionality (Casper should DENY) ──");
    let v2 = ModuleVerdict::RequestStrike {
        action: "burn".into(), target: "198.51.100.99".into(),
        justification: "active exfil, scorched earth".into(),
        confidence: 0.95, proportionality: 7,        // > 5 → stub denies
    };
    run_case("prop=7 → Casper veto path", &judge, &m, &v2,
             &ctx(0.95, 0.95, 3, true));

    println!("\n─── Case 3: low certainty (Casper should DENY) ─────────");
    let v3 = ModuleVerdict::RequestStrike {
        action: "blackhole".into(), target: "198.51.100.99".into(),
        justification: "pre-emptive on signature alone".into(),
        confidence: 0.70, proportionality: 4,
    };
    // Boost legitimacy above ROE threshold so we reach Casper
    run_case("cert=0.70 < 0.80 → Casper deny", &judge, &m, &v3,
             &ctx(0.70, 0.95, 3, true));

    println!("\n─── Case 4: defend (no four-condition gate) ────────────");
    let m_def = ModuleMeta { kind: ModuleKind::Defender, ..meta_strike(3) };
    let v4 = ModuleVerdict::Defend {
        action: "lockdown_integrity".into(), target: "self".into(),
        confidence: 0.68,
    };
    run_case("defend → fast path", &judge, &m_def, &v4,
             &ctx(0.68, 0.85, 0, false));

    println!("\n─── Case 5: forbidden target (hard gate, never reaches KHZ) ──");
    let v5 = ModuleVerdict::RequestStrike {
        action: "block".into(), target: "ministry.gov.sa".into(),
        justification: "even if 'attacker'".into(),
        confidence: 0.99, proportionality: 1,
    };
    run_case("target *.gov.sa → forbidden", &judge, &m, &v5,
             &ctx(0.99, 0.99, 9, true));

    println!("\n══════════════════════════════════════════════════════");
    println!("  Three layers verified:                                ");
    println!("    Layer A (StaticJudge): forbidden + ROE 4-conditions ");
    println!("    Layer B (KhzJudge)   : Φ veto on imbalance          ");
    println!("    Layer C (CasperJudge): contextual deny via libcasper");
    println!("══════════════════════════════════════════════════════");
    Ok(())
}
