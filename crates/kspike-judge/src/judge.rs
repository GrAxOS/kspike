//! Judge implementations.

use chrono::Utc;
use kspike_core::prelude::*;
use serde::{Deserialize, Serialize};

use crate::roe::{Posture, Roe, RoeConfig};
use kspike_khz::{KhzBalancer, balancer::BalanceRequest};
use kspike_khz::fitrah::FitrahAnchor;
use kspike_khz::operator::{Delta, HarmVector, NecessityVector};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeRuling {
    pub allowed: bool,
    pub reason: String,
    pub conditions_met: [bool; 4], // [certainty, exhaustion, legitimacy, proportion]
    pub required_dual_auth: bool,
    pub ts: chrono::DateTime<chrono::Utc>,
}

impl JudgeRuling {
    pub fn denied(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason: reason.into(),
            conditions_met: [false; 4],
            required_dual_auth: false,
            ts: Utc::now(),
        }
    }
}

pub trait Judge: Send + Sync {
    fn rule(&self, meta: &ModuleMeta, verdict: &ModuleVerdict, context: &RulingContext) -> JudgeRuling;
}

/// Context the engine provides to the judge.
#[derive(Debug, Clone, Default)]
pub struct RulingContext {
    /// How many defender attempts have already fired against this actor.
    pub defender_attempts_on_actor: u8,
    /// Whether the actor appears on any external threat feed.
    pub external_corroboration: bool,
    /// Pinned target-legitimacy confidence (0..1).
    pub target_legitimacy: f32,
    /// Attack certainty (0..1) — usually the humble-adjusted module confidence.
    pub attack_certainty: f32,
    /// Optional non-authoritative cognitive constraint. There is intentionally
    /// no positive cognitive ALLOW path; cognition may only abstain or veto.
    pub cognitive: Option<CognitiveConstraint>,
}

/// Deterministic rules-engine judge. Always runs first; CasperJudge (if any)
/// runs after and may only *tighten*, never loosen.
pub struct StaticJudge {
    pub cfg: RoeConfig,
}

impl StaticJudge {
    pub fn new(roe: Roe) -> Self {
        Self { cfg: roe.0 }
    }
}

impl Judge for StaticJudge {
    fn rule(&self, meta: &ModuleMeta, verdict: &ModuleVerdict, ctx: &RulingContext) -> JudgeRuling {
        // Non-strike paths are cheap.
        match verdict {
            ModuleVerdict::Ignore => return JudgeRuling {
                allowed: true, reason: "non-action".into(),
                conditions_met: [true; 4], required_dual_auth: false, ts: Utc::now(),
            },
            ModuleVerdict::Report { .. } => return JudgeRuling {
                allowed: true, reason: "report-only".into(),
                conditions_met: [true; 4], required_dual_auth: false, ts: Utc::now(),
            },
            ModuleVerdict::Defend { .. } => {
                if let Some(reason) = ctx.cognitive.as_ref().and_then(CognitiveConstraint::veto_reason) {
                    return JudgeRuling::denied(format!("cognitive veto: {reason}"));
                }
                if matches!(self.cfg.posture, Posture::PassiveObserver) {
                    return JudgeRuling::denied("posture=passive_observer forbids defensive action");
                }
                return JudgeRuling {
                    allowed: true,
                    reason: format!("defender authorized under posture {:?}", self.cfg.posture),
                    conditions_met: [true; 4],
                    required_dual_auth: false,
                    ts: Utc::now(),
                };
            }
            ModuleVerdict::RequestStrike { target, proportionality, confidence, justification, .. } => {
                if let Some(reason) = ctx.cognitive.as_ref().and_then(CognitiveConstraint::veto_reason) {
                    return JudgeRuling::denied(format!("cognitive veto: {reason}"));
                }
                // Posture gate.
                match self.cfg.posture {
                    Posture::PassiveObserver | Posture::DefensiveOnly => {
                        return JudgeRuling::denied(format!(
                            "posture {:?} forbids offensive action", self.cfg.posture
                        ));
                    }
                    _ => {}
                }

                // Forbidden target check (hard gate).
                let roe = Roe(self.cfg.clone());
                if roe.is_forbidden(target) {
                    return JudgeRuling::denied(format!("target '{target}' is on forbidden list"));
                }

                // Four conditions.
                let s = &self.cfg.strike;
                let c1_certainty  = ctx.attack_certainty >= s.min_attack_certainty && *confidence >= s.min_attack_certainty;
                let c2_exhaustion = matches!(self.cfg.posture, Posture::Preemptive)
                                    || ctx.defender_attempts_on_actor >= s.min_defender_attempts;
                let c3_legitimacy = ctx.target_legitimacy >= s.min_target_legitimacy
                                    && (!s.require_external_corroboration || ctx.external_corroboration);
                let c4_proportion = *proportionality <= s.max_proportionality
                                    && meta.risk_level <= 10;

                let conditions = [c1_certainty, c2_exhaustion, c3_legitimacy, c4_proportion];
                let all = conditions.iter().all(|&b| b);

                let dual = meta.risk_level > self.cfg.require_dual_authorization_above
                           || *proportionality > (self.cfg.require_dual_authorization_above);

                if !all {
                    let mut reasons = Vec::new();
                    if !c1_certainty  { reasons.push("certainty<threshold"); }
                    if !c2_exhaustion { reasons.push("defenders-not-exhausted"); }
                    if !c3_legitimacy { reasons.push("target-legitimacy<threshold"); }
                    if !c4_proportion { reasons.push("proportionality>max"); }
                    return JudgeRuling {
                        allowed: false,
                        reason: format!("ROE conditions failed: [{}] | justification-from-module: {}",
                                        reasons.join(", "), justification),
                        conditions_met: conditions,
                        required_dual_auth: dual,
                        ts: Utc::now(),
                    };
                }
                JudgeRuling {
                    allowed: !dual, // even when all 4 pass, dual-auth holds final release
                    reason: if dual {
                        "all conditions met but requires dual authorization".into()
                    } else {
                        format!("strike authorized: {}", justification)
                    },
                    conditions_met: conditions,
                    required_dual_auth: dual,
                    ts: Utc::now(),
                }
            }
        }
    }
}

/// KHZ-backed judge — wraps StaticJudge and additionally requires the
/// action to pass the Khawarizmi-Fitrah balance (Φ ≥ threshold). Even if
/// the static ROE says "yes", KHZ can veto; KHZ never loosens StaticJudge.
pub struct KhzJudge {
    pub inner: StaticJudge,
    pub balancer: KhzBalancer,
    pub phi_threshold: f32,
}

impl KhzJudge {
    pub fn new(inner: StaticJudge, phi_threshold: f32) -> Self {
        Self { inner, balancer: KhzBalancer::default(), phi_threshold }
    }

    fn build_request(meta: &ModuleMeta, verdict: &ModuleVerdict, ctx: &RulingContext) -> BalanceRequest {
        let mut harm = HarmVector::default();
        let mut need = NecessityVector::default();

        // Always: risk of the module itself = harm baseline.
        harm.add("module.risk_level", Delta::new(meta.risk_level as f32 / 10.0));

        match verdict {
            ModuleVerdict::Ignore | ModuleVerdict::Report { .. } => {
                need.add("observation.value", Delta::new(0.3));
            }
            ModuleVerdict::Defend { confidence, .. } => {
                need.add("defense.necessity", Delta::new(*confidence));
                harm.add("defense.side_effect", Delta::new(0.05));
            }
            ModuleVerdict::RequestStrike { confidence, proportionality, .. } => {
                harm.add("strike.offensive_action", Delta::new(*proportionality as f32 / 10.0));
                need.add("strike.attack_ongoing", Delta::new(ctx.attack_certainty));
                need.add("strike.target_legitimacy", Delta::new(ctx.target_legitimacy));
                need.add("strike.confidence", Delta::new(*confidence));
                if ctx.external_corroboration {
                    need.add("strike.community_corroboration", Delta::new(0.2));
                }
            }
        }

        BalanceRequest {
            label: format!("{}::{}", meta.name, verdict_label(verdict)),
            harm,
            necessity: need,
            anchor: FitrahAnchor::khawarizmi(),
            prior_phi: None,
            new_evidence: false,
        }
    }
}

fn verdict_label(v: &ModuleVerdict) -> &'static str {
    match v {
        ModuleVerdict::Ignore => "ignore",
        ModuleVerdict::Report { .. } => "report",
        ModuleVerdict::Defend { .. } => "defend",
        ModuleVerdict::RequestStrike { .. } => "strike",
    }
}

impl Judge for KhzJudge {
    fn rule(&self, meta: &ModuleMeta, verdict: &ModuleVerdict, ctx: &RulingContext) -> JudgeRuling {
        // 1) Static ROE first — must pass.
        let base = self.inner.rule(meta, verdict, ctx);
        if !base.allowed {
            return JudgeRuling {
                reason: format!("static-roe: {}", base.reason),
                ..base
            };
        }
        // 2) KHZ balance — may veto.
        let req = Self::build_request(meta, verdict, ctx);
        let ruling = self.balancer.evaluate(req);
        if ruling.phi.value() < self.phi_threshold && !ruling.full_assistance {
            return JudgeRuling {
                allowed: false,
                reason: format!(
                    "KHZ veto: Φ={:.3} < {:.3} ({})",
                    ruling.phi.value(), self.phi_threshold, ruling.rationale
                ),
                conditions_met: base.conditions_met,
                required_dual_auth: base.required_dual_auth,
                ts: Utc::now(),
            };
        }
        JudgeRuling {
            reason: format!("{} | KHZ Φ={:.3}", base.reason, ruling.phi.value()),
            ..base
        }
    }
}

/// Manual judge — every striker requires human keystroke. Useful during
/// initial deployment before operator trusts the automated ROE.
pub struct ManualJudge;

impl Judge for ManualJudge {
    fn rule(&self, _meta: &ModuleMeta, verdict: &ModuleVerdict, _ctx: &RulingContext) -> JudgeRuling {
        match verdict {
            ModuleVerdict::RequestStrike { .. } => JudgeRuling {
                allowed: false,
                reason: "ManualJudge: operator must approve out-of-band".into(),
                conditions_met: [false; 4],
                required_dual_auth: true,
                ts: Utc::now(),
            },
            _ => JudgeRuling {
                allowed: true,
                reason: "ManualJudge: non-strike auto-allowed".into(),
                conditions_met: [true; 4],
                required_dual_auth: false,
                ts: Utc::now(),
            },
        }
    }
}


#[cfg(test)]
mod oracle_tests {
    use super::*;
    use kspike_core::{CognitiveConstraint, KnownLimits};

    fn meta(kind: ModuleKind) -> ModuleMeta {
        ModuleMeta {
            name: "oracle.test".into(),
            kind,
            version: "0.1".into(),
            description: "authority-boundary test".into(),
            author: "test".into(),
            risk_level: 1,
            limits: KnownLimits::default(),
            tags: vec![],
        }
    }

    fn ctx(cognitive: Option<CognitiveConstraint>) -> RulingContext {
        RulingContext {
            defender_attempts_on_actor: 3,
            external_corroboration: true,
            target_legitimacy: 0.99,
            attack_certainty: 0.99,
            cognitive,
        }
    }

    fn veto() -> CognitiveConstraint {
        CognitiveConstraint::Veto {
            rationale: "cognitive safety veto".into(),
            provenance: Some("unit-test".into()),
        }
    }

    #[test]
    fn cognitive_veto_blocks_defense() {
        let j = StaticJudge::new(Roe::default_roe());
        let v = ModuleVerdict::Defend {
            action: "quarantine".into(),
            target: "self".into(),
            confidence: 0.99,
        };
        let r = j.rule(&meta(ModuleKind::Defender), &v, &ctx(Some(veto())));
        assert!(!r.allowed);
        assert!(r.reason.contains("cognitive veto"));
    }

    #[test]
    fn cognitive_veto_blocks_strike() {
        let j = StaticJudge::new(Roe::default_roe());
        let v = ModuleVerdict::RequestStrike {
            action: "test".into(),
            target: "198.51.100.10".into(),
            justification: "synthetic".into(),
            confidence: 0.99,
            proportionality: 1,
        };
        let r = j.rule(&meta(ModuleKind::Striker), &v, &ctx(Some(veto())));
        assert!(!r.allowed);
        assert!(r.reason.contains("cognitive veto"));
    }

    #[test]
    fn cognitive_veto_does_not_suppress_report_only() {
        let j = StaticJudge::new(Roe::default_roe());
        let v = ModuleVerdict::Report {
            note: "observation only".into(),
            confidence: 0.5,
        };
        let r = j.rule(&meta(ModuleKind::Detector), &v, &ctx(Some(veto())));
        assert!(r.allowed);
        assert_eq!(r.reason, "report-only");
    }

    #[test]
    fn abstain_cannot_grant_authority_but_does_not_veto_defense() {
        let j = StaticJudge::new(Roe::default_roe());
        let v = ModuleVerdict::Defend {
            action: "quarantine".into(),
            target: "self".into(),
            confidence: 0.99,
        };
        let c = CognitiveConstraint::Abstain { rationale: "no opinion".into() };
        let r = j.rule(&meta(ModuleKind::Defender), &v, &ctx(Some(c)));
        assert!(r.allowed);
    }
}
