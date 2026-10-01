#![cfg(feature = "link_casper")]

use kspike_casper_ffi::CasperCognitiveLobe;
use kspike_core::{
    KnownLimits, Module, ModuleKind, ModuleMeta, ModuleVerdict, Result,
    Signal, SignalSource,
};
use kspike_judge::{roe::Roe, StaticJudge};
use kspike_modules::{Engine, EngineConfig};
use std::hint::black_box;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

struct DefenseModule {
    meta: ModuleMeta,
    applied: Arc<AtomicUsize>,
}

impl DefenseModule {
    fn new(risk_level: u8, applied: Arc<AtomicUsize>) -> Self {
        Self {
            meta: ModuleMeta {
                name: "bench.defender".into(),
                kind: ModuleKind::Defender,
                version: "0.1".into(),
                description: "ORACLE runtime benchmark".into(),
                author: "bench".into(),
                risk_level,
                limits: KnownLimits::default(),
                tags: vec![],
            },
            applied,
        }
    }
}

impl Module for DefenseModule {
    fn meta(&self) -> &ModuleMeta { &self.meta }

    fn evaluate(&self, _signal: &Signal) -> Result<ModuleVerdict> {
        Ok(ModuleVerdict::Defend {
            action: "quarantine".into(),
            target: "self".into(),
            confidence: 0.95,
        })
    }

    fn apply(
        &self,
        _verdict: &ModuleVerdict,
        _authorization: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.applied.fetch_add(1, Ordering::Relaxed);
        Ok(serde_json::json!({"applied": true}))
    }
}

fn engine(risk: u8, cognitive: bool) -> Engine {
    let e = Engine::new(
        EngineConfig { ledger_path: None, dry_run: false },
        Arc::new(StaticJudge::new(Roe::default_roe())),
    );
    if cognitive {
        e.set_cognitive_lobe(Arc::new(
            CasperCognitiveLobe::new("/dev/null"),
        ));
    }
    e.register(Arc::new(DefenseModule::new(
        risk,
        Arc::new(AtomicUsize::new(0)),
    ))).unwrap();
    e
}

fn signal() -> Signal {
    Signal::new(SignalSource::Network, "bench.synthetic").confidence(0.95)
}

fn run(e: &Engine, n: usize) -> Duration {
    let s = signal();
    for _ in 0..1_000 {
        black_box(e.ingest(black_box(s.clone())).unwrap());
    }
    let t0 = Instant::now();
    for _ in 0..n {
        black_box(e.ingest(black_box(s.clone())).unwrap());
    }
    t0.elapsed()
}

fn ns_per(d: Duration, n: usize) -> f64 {
    d.as_secs_f64() * 1e9 / n as f64
}

fn main() {
    let n = std::env::var("ORACLE_BENCH_N")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(100_000);
    let lib = std::env::var("KSPIKE_CASPER_LIB")
        .expect("KSPIKE_CASPER_LIB must be set");

    let init0 = Instant::now();
    kspike_casper_ffi::ffi::init("/dev/null").expect("casper init failed");
    let init_us = init0.elapsed().as_secs_f64() * 1e6;
    let version = kspike_casper_ffi::ffi::version();
    assert_eq!(version, "casper-stub-1.0");

    let req = r#"{"verdict_kind":"defend","proportionality":0,"attack_certainty":0.95,"risk_level":1,"confidence":0.95}"#;
    for _ in 0..1_000 {
        black_box(kspike_casper_ffi::ffi::evaluate(black_box(req)).unwrap());
    }
    let f0 = Instant::now();
    for _ in 0..n {
        black_box(kspike_casper_ffi::ffi::evaluate(black_box(req)).unwrap());
    }
    let ffi_ns = ns_per(f0.elapsed(), n);

    let base = engine(1, false);
    let abstain = engine(1, true);
    let veto = engine(9, true);

    let cold0 = Instant::now();
    black_box(abstain.ingest(signal()).unwrap());
    let cold = cold0.elapsed();

    let db = run(&base, n);
    let da = run(&abstain, n);
    let dv = run(&veto, n);

    let nb = ns_per(db, n);
    let na = ns_per(da, n);
    let nv = ns_per(dv, n);

    println!("ORACLE_BENCH_N={n}");
    println!("CASPER_LIB={lib}");
    println!("CASPER_VERSION={}", kspike_casper_ffi::ffi::version());
    println!("FFI_INIT_US={init_us:.3}");
    println!("FFI_EVAL_NS={ffi_ns:.2}");
    println!("COLD_ORACLE_US={:.3}", cold.as_secs_f64() * 1e6);
    println!("BASELINE_NS_PER_INGEST={nb:.2}");
    println!("ORACLE_ABSTAIN_NS_PER_INGEST={na:.2}");
    println!("ORACLE_VETO_NS_PER_INGEST={nv:.2}");
    println!("ABSTAIN_OVERHEAD_NS={:.2}", na - nb);
    println!("VETO_OVERHEAD_NS={:.2}", nv - nb);
    println!("BASELINE_INGESTS_PER_SEC={:.0}", 1e9 / nb);
    println!("ORACLE_ABSTAIN_INGESTS_PER_SEC={:.0}", 1e9 / na);
    println!("ORACLE_VETO_INGESTS_PER_SEC={:.0}", 1e9 / nv);
}
