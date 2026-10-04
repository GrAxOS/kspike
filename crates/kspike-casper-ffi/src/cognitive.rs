//! ORACLE cognitive-lobe adapter for the C11 Casper ABI.
//!
//! Critical invariant: a model response can never grant authority.
//! "allow" and "uncertain" both collapse to Abstain; only "deny" can Veto.

use kspike_core::{
    CognitiveConstraint, CognitiveLobe, ModuleMeta, ModuleVerdict, Result, Signal,
};
use std::sync::OnceLock;

use crate::judge::{CasperReq, CasperResp};

pub struct CasperCognitiveLobe {
    model_path: String,
    init: OnceLock<std::result::Result<(), String>>,
}

impl CasperCognitiveLobe {
    pub fn new(model_path: impl Into<String>) -> Self {
        Self {
            model_path: model_path.into(),
            init: OnceLock::new(),
        }
    }

    fn ensure_init(&self) -> anyhow::Result<()> {
        let state = self.init.get_or_init(|| {
            if !crate::ffi::available() {
                return Err("link_casper feature is off".into());
            }
            crate::ffi::init(&self.model_path).map_err(|e| e.to_string())
        });
        match state {
            Ok(()) => Ok(()),
            Err(e) => anyhow::bail!("{e}"),
        }
    }
}

fn request(meta: &ModuleMeta, verdict: &ModuleVerdict, signal: &Signal) -> CasperReq {
    let kind = match verdict {
        ModuleVerdict::Ignore => "ignore",
        ModuleVerdict::Report { .. } => "report",
        ModuleVerdict::Defend { .. } => "defend",
        ModuleVerdict::RequestStrike { .. } => "strike",
    };
    let target = match verdict {
        ModuleVerdict::Defend { target, .. } => Some(target.clone()),
        ModuleVerdict::RequestStrike { target, .. } => Some(target.clone()),
        _ => None,
    };
    let (confidence, proportionality) = match verdict {
        ModuleVerdict::Defend { confidence, .. } => (*confidence, 0),
        ModuleVerdict::RequestStrike { confidence, proportionality, .. } => {
            (*confidence, *proportionality)
        }
        ModuleVerdict::Report { confidence, .. } => (*confidence, 0),
        ModuleVerdict::Ignore => (0.0, 0),
    };
    CasperReq {
        module: meta.name.clone(),
        verdict_kind: kind.into(),
        target,
        confidence,
        proportionality,
        risk_level: meta.risk_level,
        attack_certainty: meta.limits.humble(signal.raw_confidence),
        target_legitimacy: signal.raw_confidence,
    }
}

fn map_response(resp: CasperResp) -> CognitiveConstraint {
    let provenance = Some(format!("casper:{}", crate::ffi::version()));
    match resp.decision.as_str() {
        "deny" => CognitiveConstraint::Veto {
            rationale: resp.rationale,
            provenance,
        },
        "allow" => CognitiveConstraint::Abstain {
            rationale: format!("non-authoritative ALLOW discarded: {}", resp.rationale),
        },
        "uncertain" => CognitiveConstraint::Abstain {
            rationale: resp.rationale,
        },
        other => CognitiveConstraint::Veto {
            rationale: format!("invalid cognitive decision {other:?}: {}", resp.rationale),
            provenance,
        },
    }
}

impl CognitiveLobe for CasperCognitiveLobe {
    fn name(&self) -> &'static str {
        "casper-cognitive"
    }

    fn constrain(
        &self,
        signal: &Signal,
        meta: &ModuleMeta,
        verdict: &ModuleVerdict,
    ) -> Result<CognitiveConstraint> {
        self.ensure_init()?;
        let req = request(meta, verdict, signal);
        let req_json = serde_json::to_string(&req)?;
        let out = crate::ffi::evaluate(&req_json)?;
        let resp: CasperResp = serde_json::from_str(&out)?;
        Ok(map_response(resp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_allow_can_never_become_authority() {
        let c = map_response(CasperResp {
            decision: "allow".into(),
            rationale: "looks fine".into(),
        });
        assert!(matches!(c, CognitiveConstraint::Abstain { .. }));
    }

    #[test]
    fn model_deny_becomes_veto() {
        let c = map_response(CasperResp {
            decision: "deny".into(),
            rationale: "unsafe".into(),
        });
        assert!(matches!(c, CognitiveConstraint::Veto { .. }));
    }

    #[test]
    fn malformed_decision_fails_closed() {
        let c = map_response(CasperResp {
            decision: "maybe".into(),
            rationale: "unknown schema".into(),
        });
        assert!(matches!(c, CognitiveConstraint::Veto { .. }));
    }
}
