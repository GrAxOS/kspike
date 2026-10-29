//! Meterpreter beacon detector + sinkhole striker.
//!
//! MSF original:  windows/meterpreter/reverse_tcp, reverse_https
//! KSpike mirror: detector.net.meterpreter_beacon + striker.net.meterpreter_sinkhole
//!
//! Detector tells:
//!   • Stage-0: 4-byte length prefix (little-endian), then exactly that many
//!     bytes — repeating at regular intervals on a single TCP flow.
//!   • Stage-1: TLV framing after key exchange, packet size mod 16 == 0
//!     (AES-CBC blocks) with sustained uplink/downlink ratio ~1:3.
//!   • A stageless reverse_https handshake often leaks a distinctive
//!     32-byte sized POST/GET to /<random>_m.gif URIs.
//!
//! Striker redirects the flow's destination to a local honeypot and issues
//! the attacker a fake "OK" so their loader stays engaged while we collect
//! evidence — judge-gated.

use kspike_core::prelude::*;

pub struct MeterpreterBeaconDetector { meta: ModuleMeta }

impl Default for MeterpreterBeaconDetector {
    fn default() -> Self {
        Self {
            meta: ModuleMeta {
                name: "detector.net.meterpreter_beacon".into(),
                kind: ModuleKind::Detector,
                version: "0.1.0".into(),
                description: "Flags Meterpreter stageless/staged C2 shape on a flow.".into(),
                author: "gratech".into(),
                risk_level: 0,
                limits: KnownLimits::new()
                    .add(Limitation {
                        id: "encryption-opaque".into(),
                        description: "Cannot decrypt; judges by size patterns and timing.".into(),
                        confidence_penalty: 0.20,
                        mitigation: Some("combine with shikata detector and destination reputation".into()),
                    }),
                tags: vec!["meterpreter".into(), "c2".into(), "network".into()],
            },
        }
    }
}

impl Module for MeterpreterBeaconDetector {
    fn meta(&self) -> &ModuleMeta { &self.meta }
    fn evaluate(&self, s: &Signal) -> Result<ModuleVerdict> {
        // Accept both flow-summary signals (user-space) and XDP kernel tags.
        let is_xdp = s.kind.starts_with("meterpreter.");
        if !(s.kind.starts_with("net.flow.summary") || is_xdp) {
            return Ok(ModuleVerdict::Ignore);
        }
        if is_xdp {
            return Ok(ModuleVerdict::Report {
                note: format!("Meterpreter beacon (kernel-XDP detection) from {:?}", s.actor),
                confidence: self.meta.limits.humble(s.raw_confidence.max(0.85)),
            });
        }
        let len_prefix = s.data.get("len_prefix_match").and_then(|v| v.as_bool()).unwrap_or(false);
        let cbc_blocks = s.data.get("sizes_mod16_zero_ratio").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let m_gif_uri  = s.data.get("uri").and_then(|v| v.as_str())
                          .map(|u| u.ends_with("_m.gif")).unwrap_or(false);

        let confidence: f32 = (if len_prefix {0.45} else {0.0})
                            + (cbc_blocks as f32 * 0.35)
                            + (if m_gif_uri {0.30} else {0.0});
        if confidence >= 0.55 {
            Ok(ModuleVerdict::Report {
                note: format!("meterpreter beacon shape on flow {:?} (c={:.2})", s.actor, confidence),
                confidence: self.meta.limits.humble(confidence.min(0.95)),
            })
        } else { Ok(ModuleVerdict::Ignore) }
    }
    fn apply(&self, v: &ModuleVerdict, _: Option<&str>) -> Result<serde_json::Value> {
        Ok(serde_json::json!({ "module": self.meta.name, "applied": v }))
    }
}

#[cfg(feature = "strikers")]
pub struct MeterpreterSinkholeStriker { meta: ModuleMeta }

#[cfg(feature = "strikers")]
impl Default for MeterpreterSinkholeStriker {
    fn default() -> Self {
        Self {
            meta: ModuleMeta {
                name: "striker.net.meterpreter_sinkhole".into(),
                kind: ModuleKind::Striker,
                version: "0.1.0".into(),
                description: "DNATs a confirmed Meterpreter flow into a local honeypot + keeps the attacker engaged.".into(),
                author: "gratech".into(),
                risk_level: 7,
                limits: KnownLimits::new()
                    .add(Limitation {
                        id: "partial-decoy".into(),
                        description: "Honeypot may not mimic all Meterpreter commands — sophisticated operator will notice.".into(),
                        confidence_penalty: 0.20,
                        mitigation: Some("rotate honeypot profiles; never lie about filesystem layout".into()),
                    })
                    .add(Limitation {
                        id: "legal-exposure".into(),
                        description: "Engaging attacker by impersonation may breach some jurisdictions' computer-misuse statutes.".into(),
                        confidence_penalty: 0.25,
                        mitigation: Some("operator confirms deployment region in roe.toml".into()),
                    }),
                tags: vec!["sinkhole".into(), "honeypot".into(), "c2".into(), "offensive".into()],
            },
        }
    }
}

#[cfg(feature = "strikers")]
impl Module for MeterpreterSinkholeStriker {
    fn meta(&self) -> &ModuleMeta { &self.meta }
    fn evaluate(&self, s: &Signal) -> Result<ModuleVerdict> {
        if !s.kind.starts_with("c2.meterpreter.confirmed") { return Ok(ModuleVerdict::Ignore); }
        let Some(target) = &s.target else { return Ok(ModuleVerdict::Ignore); };
        Ok(ModuleVerdict::RequestStrike {
            action: "dnat_to_honeypot".into(),
            target: target.clone(),
            justification: "confirmed Meterpreter C2; sinkhole preserves operator situational awareness".into(),
            confidence: self.meta.limits.humble(s.raw_confidence),
            proportionality: 4,
        })
    }
    fn apply(&self, v: &ModuleVerdict, authz: Option<&str>) -> Result<serde_json::Value> {
        let Some(note) = authz else {
            return Err(KSpikeError::RoeViolation(
                "striker.net.meterpreter_sinkhole called without judge authorization".into()));
        };
        if let ModuleVerdict::RequestStrike { action, target, .. } = v {
            warn!("[striker.net.meterpreter_sinkhole] authz={note} → {target}");
            return Ok(serde_json::json!({
                "module": self.meta.name, "action": action, "target": target,
                "authorized_by": note,
                "steps": [
                    {"op":"nft","rule":"add rule inet kspike postrouting ip daddr <target> counter dnat to 127.0.0.1:4444"},
                    {"op":"honeypot","profile":"meterpreter_win10_x64","log":"/var/log/kspike/honey"}
                ],
                "applied": true
            }));
        }
        Ok(serde_json::json!({ "applied": false }))
    }
}
