//! The engine — orchestrates signals → modules → judge → evidence.

use kspike_core::prelude::*;
use kspike_core::event::EventBus;
use kspike_core::evidence::{EvidenceLedger, InMemorySigner};
use kspike_judge::{Judge, RulingContext};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::path::PathBuf;

pub struct EngineConfig {
    pub ledger_path: Option<PathBuf>,
    pub dry_run: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self { ledger_path: Some(PathBuf::from("./kspike-evidence.jsonl")), dry_run: false }
    }
}

pub struct Engine {
    cfg: EngineConfig,
    modules: RwLock<Vec<Arc<dyn Module>>>,
    judge: Arc<dyn Judge>,
    ledger: Arc<EvidenceLedger>,
    bus: EventBus,
    attempt_counter: RwLock<HashMap<String, u8>>, // actor → defender-attempt-count
    stats: RwLock<EngineStats>,
    cognitive: RwLock<Option<Arc<dyn CognitiveLobe>>>,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct EngineStats {
    pub signals: u64,
    pub defenses: u64,
    pub strikes: u64,
    pub denials: u64,
    pub reports: u64,
}

impl Engine {
    pub fn new(cfg: EngineConfig, judge: Arc<dyn Judge>) -> Self {
        let signer = Box::new(InMemorySigner::generate());
        let ledger = Arc::new(EvidenceLedger::new(signer, cfg.ledger_path.clone()));
        Self {
            cfg,
            modules: RwLock::new(Vec::new()),
            judge,
            ledger,
            bus: EventBus::new(),
            attempt_counter: RwLock::new(HashMap::new()),
            stats: RwLock::new(EngineStats::default()),
            cognitive: RwLock::new(None),
        }
    }

    pub fn register(&self, m: Arc<dyn Module>) -> Result<()> {
        m.self_test()?;
        let name = m.meta().name.clone();
        self.modules.write().unwrap().push(m);
        self.bus.publish(Event::new(Severity::Info, EventKind::ModuleLoaded { name }));
        Ok(())
    }

    pub fn bus(&self) -> &EventBus { &self.bus }
    pub fn stats(&self) -> EngineStats { self.stats.read().unwrap().clone() }

    pub fn set_cognitive_lobe(&self, lobe: Arc<dyn CognitiveLobe>) {
        *self.cognitive.write().unwrap() = Some(lobe);
    }

    pub fn clear_cognitive_lobe(&self) {
        *self.cognitive.write().unwrap() = None;
    }

    pub fn ingest(&self, signal: Signal) -> Result<Vec<serde_json::Value>> {
        {
            let mut s = self.stats.write().unwrap();
            s.signals += 1;
        }
        self.bus.publish(Event::new(Severity::Trace,
            EventKind::SignalIngested { signal_id: signal.id }));
        let _ = self.ledger.seal("signal", serde_json::to_value(&signal)?)?;

        let mods = self.modules.read().unwrap().clone();
        let mut outcomes = Vec::new();

        for m in mods.iter() {
            let meta = m.meta().clone();
            let verdict = match m.evaluate(&signal) {
                Ok(v) => v,
                Err(e) => {
                    warn!("module {} failed: {e}", meta.name);
                    continue;
                }
            };
            self.bus.publish(Event::new(Severity::Info,
                EventKind::VerdictIssued { module: meta.name.clone(),
                    verdict: format!("{:?}", verdict) }));
            let _ = self.ledger.seal("verdict", serde_json::json!({
                "module": &meta.name, "verdict": &verdict,
            }))?;

            // Cognition is non-authoritative and is consulted only for
            // proposed side effects. It can abstain or veto, never allow.
            let cognitive = if matches!(
                verdict,
                ModuleVerdict::Defend { .. } | ModuleVerdict::RequestStrike { .. }
            ) {
                self.cognitive.read().unwrap().clone().map(|lobe| {
                    match lobe.constrain(&signal, &meta, &verdict) {
                        Ok(c) => c,
                        Err(e) => CognitiveConstraint::Veto {
                            rationale: format!("{} unavailable: {e}", lobe.name()),
                            provenance: Some("fail-closed".into()),
                        },
                    }
                })
            } else {
                None
            };
            if let Some(ref c) = cognitive {
                let _ = self.ledger.seal("cognitive", serde_json::json!({
                    "module": &meta.name,
                    "constraint": c,
                }))?;
            }

            // Build context for the judge.
            let ctx = RulingContext {
                defender_attempts_on_actor: signal.actor.as_ref()
                    .and_then(|a| self.attempt_counter.read().unwrap().get(a).copied())
                    .unwrap_or(0),
                external_corroboration: matches!(signal.source, SignalSource::Peer),
                target_legitimacy: signal.raw_confidence,
                attack_certainty: meta.limits.humble(signal.raw_confidence),
                cognitive: cognitive.clone(),
            };

            let ruling = self.judge.rule(&meta, &verdict, &ctx);
            self.bus.publish(Event::new(
                if ruling.allowed { Severity::Notice } else { Severity::Warn },
                EventKind::JudgeRuling { allowed: ruling.allowed, reason: ruling.reason.clone() }
            ));
            let _ = self.ledger.seal("judge", serde_json::to_value(&ruling)?)?;

            if !ruling.allowed {
                self.stats.write().unwrap().denials += 1;
                continue;
            }

            if matches!(verdict, ModuleVerdict::Ignore) {
                // Ignore verdicts are free — no apply(), no ledger noise beyond verdict.
                continue;
            }

            if self.cfg.dry_run {
                info!("[DRY-RUN] would apply: {} :: {:?}", meta.name, verdict);
                continue;
            }

            let authz = if matches!(verdict, ModuleVerdict::RequestStrike { .. }) {
                Some(ruling.reason.as_str())
            } else { None };

            match m.apply(&verdict, authz) {
                Ok(outcome) => {
                    let (cat, sev) = match &verdict {
                        ModuleVerdict::Defend { .. }       => ("defense", Severity::Notice),
                        ModuleVerdict::RequestStrike { .. } => ("strike",  Severity::Alert),
                        ModuleVerdict::Report { .. }       => ("report",  Severity::Info),
                        ModuleVerdict::Ignore              => ("ignore",  Severity::Trace),
                    };
                    let _ = self.ledger.seal(cat, outcome.clone())?;
                    match &verdict {
                        ModuleVerdict::Defend { target, .. } => {
                            self.stats.write().unwrap().defenses += 1;
                            if let Some(a) = &signal.actor {
                                *self.attempt_counter.write().unwrap().entry(a.clone()).or_insert(0) += 1;
                            }
                            self.bus.publish(Event::new(sev,
                                EventKind::DefenseApplied { module: meta.name.clone(),
                                    target: target.clone() }));
                        }
                        ModuleVerdict::RequestStrike { target, .. } => {
                            self.stats.write().unwrap().strikes += 1;
                            self.bus.publish(Event::new(sev,
                                EventKind::StrikeFired { module: meta.name.clone(),
                                    target: target.clone(),
                                    authorized_by: ruling.reason.clone() }));
                        }
                        ModuleVerdict::Report { .. } => {
                            self.stats.write().unwrap().reports += 1;
                        }
                        _ => {}
                    }
                    outcomes.push(outcome);
                }
                Err(e) => {
                    error!("apply() failed for {}: {e}", meta.name);
                }
            }
        }
        Ok(outcomes)
    }
}
