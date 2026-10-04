use kspike_core::{
    CognitiveConstraint, CognitiveLobe, KnownLimits, Module, ModuleKind, ModuleMeta,
    ModuleVerdict, Result, Signal, SignalSource,
};
use kspike_judge::{roe::Roe, StaticJudge};
use kspike_modules::{Engine, EngineConfig};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct TestModule {
    meta: ModuleMeta,
    verdict: ModuleVerdict,
    applied: Arc<AtomicUsize>,
}

impl TestModule {
    fn new(kind: ModuleKind, verdict: ModuleVerdict, applied: Arc<AtomicUsize>) -> Self {
        Self {
            meta: ModuleMeta {
                name: "oracle.test.module".into(),
                kind,
                version: "0.1".into(),
                description: "test".into(),
                author: "test".into(),
                risk_level: 1,
                limits: KnownLimits::default(),
                tags: vec![],
            },
            verdict,
            applied,
        }
    }
}

impl Module for TestModule {
    fn meta(&self) -> &ModuleMeta { &self.meta }
    fn evaluate(&self, _signal: &Signal) -> Result<ModuleVerdict> {
        Ok(self.verdict.clone())
    }
    fn apply(
        &self,
        _verdict: &ModuleVerdict,
        _authorization: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.applied.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"applied": true}))
    }
}
struct FailingLobe {
    calls: Arc<AtomicUsize>,
}

impl CognitiveLobe for FailingLobe {
    fn name(&self) -> &'static str { "failing-cognitive" }
    fn constrain(
        &self,
        _signal: &Signal,
        _meta: &ModuleMeta,
        _verdict: &ModuleVerdict,
    ) -> Result<CognitiveConstraint> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(anyhow::anyhow!("cognitive runtime unavailable").into())
    }
}

fn engine() -> Engine {
    Engine::new(
        EngineConfig { ledger_path: None, dry_run: false },
        Arc::new(StaticJudge::new(Roe::default_roe())),
    )
}

fn signal() -> Signal {
    Signal::new(SignalSource::Network, "proof.synthetic").confidence(0.95)
}

#[test]
fn cognitive_runtime_failure_is_fail_closed_for_defense() {
    let applied = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let e = engine();
    e.set_cognitive_lobe(Arc::new(FailingLobe { calls: calls.clone() }));
    e.register(Arc::new(TestModule::new(
        ModuleKind::Defender,
        ModuleVerdict::Defend {
            action: "quarantine".into(),
            target: "self".into(),
            confidence: 0.95,
        },
        applied.clone(),
    ))).unwrap();

    let out = e.ingest(signal()).unwrap();
    assert!(out.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(applied.load(Ordering::SeqCst), 0);
    assert_eq!(e.stats().denials, 1);
}
#[test]
fn report_only_bypasses_cognitive_lobe() {
    let applied = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let e = engine();
    e.set_cognitive_lobe(Arc::new(FailingLobe { calls: calls.clone() }));
    e.register(Arc::new(TestModule::new(
        ModuleKind::Detector,
        ModuleVerdict::Report {
            note: "observation".into(),
            confidence: 0.5,
        },
        applied.clone(),
    ))).unwrap();

    let out = e.ingest(signal()).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(applied.load(Ordering::SeqCst), 1);
    assert_eq!(e.stats().reports, 1);
    assert_eq!(e.stats().denials, 0);
}
