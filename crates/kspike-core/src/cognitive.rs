//! ORACLE cognitive-lobe contract.
//!
//! The cognitive lobe is deliberately non-authoritative: it can abstain or
//! veto a side effect, but there is no positive ALLOW representation.

use serde::{Deserialize, Serialize};

use crate::{ModuleMeta, ModuleVerdict, Result, Signal};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum CognitiveConstraint {
    Abstain {
        rationale: String,
    },
    Veto {
        rationale: String,
        provenance: Option<String>,
    },
}

impl CognitiveConstraint {
    pub fn veto_reason(&self) -> Option<&str> {
        match self {
            Self::Veto { rationale, .. } => Some(rationale.as_str()),
            Self::Abstain { .. } => None,
        }
    }

    pub fn is_veto(&self) -> bool {
        matches!(self, Self::Veto { .. })
    }
}

pub trait CognitiveLobe: Send + Sync {
    fn name(&self) -> &'static str;
    fn constrain(
        &self,
        signal: &Signal,
        meta: &ModuleMeta,
        verdict: &ModuleVerdict,
    ) -> Result<CognitiveConstraint>;
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format_has_no_allow_variant() {
        let raw = r#"{"decision":"allow","rationale":"model says yes"}"#;
        let parsed = serde_json::from_str::<CognitiveConstraint>(raw);
        assert!(parsed.is_err(), "cognitive wire format must not represent ALLOW");
    }

    #[test]
    fn veto_and_abstain_have_distinct_authority() {
        let abstain = CognitiveConstraint::Abstain { rationale: "no view".into() };
        assert!(!abstain.is_veto());
        assert_eq!(abstain.veto_reason(), None);

        let veto = CognitiveConstraint::Veto {
            rationale: "unsafe".into(),
            provenance: Some("test".into()),
        };
        assert!(veto.is_veto());
        assert_eq!(veto.veto_reason(), Some("unsafe"));
    }
}
