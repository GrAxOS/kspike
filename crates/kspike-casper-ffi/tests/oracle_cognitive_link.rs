#![cfg(feature = "link_casper")]

use kspike_casper_ffi::CasperCognitiveLobe;
use kspike_core::{
    CognitiveConstraint, CognitiveLobe, KnownLimits, ModuleKind, ModuleMeta,
    ModuleVerdict, Signal, SignalSource,
};

fn meta(risk_level: u8) -> ModuleMeta {
    ModuleMeta {
        name: "oracle.link-test".into(),
        kind: ModuleKind::Defender,
        version: "0.1".into(),
        description: "linked C11 cognitive test".into(),
        author: "test".into(),
        risk_level,
        limits: KnownLimits::default(),
        tags: vec![],
    }
}

fn signal() -> Signal {
    Signal::new(SignalSource::Network, "proof.synthetic").confidence(0.95)
}

fn defend() -> ModuleVerdict {
    ModuleVerdict::Defend {
        action: "quarantine".into(),
        target: "self".into(),
        confidence: 0.95,
    }
}

#[test]
fn c11_allow_collapses_to_abstain_and_deny_to_veto() {
    if std::env::var_os("KSPIKE_CASPER_LIB").is_none() {
        eprintln!("KSPIKE_CASPER_LIB not set; linked test skipped");
        return;
    }
    let lobe = CasperCognitiveLobe::new("/dev/null");

    let low_risk = lobe.constrain(&signal(), &meta(1), &defend()).unwrap();
    assert!(matches!(low_risk, CognitiveConstraint::Abstain { .. }));

    let high_risk = lobe.constrain(&signal(), &meta(9), &defend()).unwrap();
    assert!(matches!(high_risk, CognitiveConstraint::Veto { .. }));

    assert_eq!(kspike_casper_ffi::ffi::version(), "casper-stub-1.0");
}
