#![cfg(feature = "link_casper")]

use kspike_casper_ffi::CasperCognitiveLobe;
use kspike_core::{
    KnownLimits, Module, ModuleKind, ModuleMeta, ModuleVerdict, Result, Signal,
    SignalSource,
};
use kspike_judge::{roe::Roe, StaticJudge};
use kspike_modules::{Engine, EngineConfig};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct DefenseModule {
    meta: ModuleMeta,
    applied: Arc<AtomicUsize>,
}

impl DefenseModule {
    fn new(name: &str, risk_level: u8, applied: Arc<AtomicUsize>) -> Self {
        Self {
            meta: ModuleMeta {
                name: name.into(),
                kind: ModuleKind::Defender,
                version: "0.1".into(),
                description: "three-lobe link test".into(),
                author: "test".into(),
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
        self.applied.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"module": self.meta.name, "applied": true}))
    }
}
#[test]
fn sensory_cognitive_executive_authority_boundary_is_live() {
    if std::env::var_os("KSPIKE_CASPER_LIB").is_none() {
        eprintln!("KSPIKE_CASPER_LIB not set; linked test skipped");
        return;
    }

    let low_applied = Arc::new(AtomicUsize::new(0));
    let high_applied = Arc::new(AtomicUsize::new(0));

    let engine = Engine::new(
        EngineConfig { ledger_path: None, dry_run: false },
        Arc::new(StaticJudge::new(Roe::default_roe())),
    );
    engine.set_cognitive_lobe(Arc::new(CasperCognitiveLobe::new("/dev/null")));

    engine.register(Arc::new(DefenseModule::new(
        "defender.low-risk",
        1,
        low_applied.clone(),
    ))).unwrap();
    engine.register(Arc::new(DefenseModule::new(
        "defender.high-risk",
        9,
        high_applied.clone(),
    ))).unwrap();

    let signal = Signal::new(SignalSource::Network, "proof.synthetic")
        .confidence(0.95);
    let outcomes = engine.ingest(signal).unwrap();

    assert_eq!(outcomes.len(), 1);
    assert_eq!(low_applied.load(Ordering::SeqCst), 1);
    assert_eq!(high_applied.load(Ordering::SeqCst), 0);

    let stats = engine.stats();
    assert_eq!(stats.defenses, 1);
    assert_eq!(stats.denials, 1);
    assert_eq!(kspike_casper_ffi::ffi::version(), "casper-stub-1.0");
}
