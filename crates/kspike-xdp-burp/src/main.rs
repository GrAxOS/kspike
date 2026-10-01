//! `kspike-xdp-burp` — binary loader.
//!
//! Without the `aya_runtime` feature, this binary runs the pcap-replay
//! pipeline: it builds an Engine, attaches an `XdpBurpTap`, injects
//! synthetic XDP events, and drains them into the engine so the full
//! path (detect → judge → defend/strike → ledger) runs end-to-end.
//!
//! With `aya_runtime`, this same binary loads the eBPF object, attaches
//! it to the configured interface, and pipes the RingBuf into the same
//! `XdpBurpTap`. See `docs/design/XDP-BURP.md` for build instructions.

use anyhow::Result;
use kspike_core::BANNER;
use kspike_judge::{Judge, KhzJudge, StaticJudge, roe::Roe};
use kspike_modules::engine::{Engine, EngineConfig};
use kspike_modules::defenders::{FilesystemImmunityDefender, KernelLockdownDefender, SshQuarantineDefender};
use kspike_modules::detectors::SshBruteforceDetector;
use kspike_modules::msf_mirror as msf;
use kspike_kernel::canary::MemoryCanary;
use kspike_kernel::KernelTap;
use kspike_xdp_burp::{XdpBurpConfig, XdpBurpTap};
#[cfg(not(feature = "aya_runtime"))]
use kspike_xdp_burp::PcapReplay;
#[cfg(not(feature = "aya_runtime"))]
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env()
            .add_directive("info".parse().unwrap()))
        .with_target(false).compact().init();

    println!("{BANNER}");
    println!("▶ kspike-xdp-burp: transparent kernel MITM pipeline\n");

    // ─── Engine + judge + stock modules ────────────────────────────────────
    let roe = Roe::default_roe();
    let static_judge = StaticJudge::new(roe);
    let judge: Arc<dyn Judge> = Arc::new(KhzJudge::new(static_judge, 0.35));
    let engine = Arc::new(Engine::new(
        EngineConfig { ledger_path: Some("./kspike-evidence.jsonl".into()), dry_run: false },
        judge,
    ));

    #[cfg(feature = "oracle_cognitive")]
    if let Ok(model_path) = std::env::var("ORACLE_COGNITIVE_MODEL") {
        engine.set_cognitive_lobe(Arc::new(
            kspike_casper_ffi::CasperCognitiveLobe::new(model_path),
        ));
        tracing::info!("ORACLE cognitive veto lobe configured");
    }

    let canary = Arc::new(MemoryCanary::new());
    engine.register(Arc::new(SshBruteforceDetector::default()))?;
    engine.register(Arc::new(SshQuarantineDefender::default()))?;
    engine.register(Arc::new(KernelLockdownDefender::default()))?;
    engine.register(Arc::new(FilesystemImmunityDefender::default()))?;
    engine.register(Arc::new(msf::EternalBlueProbeDetector::default()))?;
    engine.register(Arc::new(msf::SmbV1Killswitch::default()))?;
    engine.register(Arc::new(msf::Log4ShellJndiDetector::default()))?;
    engine.register(Arc::new(msf::MeterpreterBeaconDetector::default()))?;
    engine.register(Arc::new(msf::PsExecAbuseDetector::default()))?;
    engine.register(Arc::new(msf::ShikataPolymorphicDetector::default()))?;
    engine.register(Arc::new(msf::KerberoastDetector::default()))?;
    engine.register(Arc::new(msf::CredDumpCanaryDefender::new(canary.clone())))?;
    engine.register(Arc::new(msf::CanaryTokenDeception::new(canary.clone())))?;

    // ─── Tap ───────────────────────────────────────────────────────────────
    let mut tap_cfg = XdpBurpConfig::default();
    if let Ok(interface) = std::env::var("KSPIKE_IFACE") {
        tap_cfg.interface = interface;
    }
    let mut tap = XdpBurpTap::new(tap_cfg);

    // Either attach the real XDP program (aya_runtime), or run the replay.
    #[cfg(feature = "aya_runtime")]
    let _xdp_runtime = {
        let bpf_path = std::env::var("KSPIKE_BPF")
            .map_err(|_| anyhow::anyhow!("KSPIKE_BPF must point to the compiled eBPF object"))?;
        let runtime = kspike_xdp_burp::runtime::attach(
            &mut tap,
            std::path::Path::new(&bpf_path),
        ).await?;
        println!("▶ XDP program attached to {}", tap.config().interface);
        runtime
    };

    #[cfg(not(feature = "aya_runtime"))]
    {
        tap.mark_active();
        println!("▶ replay mode: injecting synthetic XDP events\n");
        PcapReplay::log4shell(&tap,  Ipv4Addr::new(185,100,87,41), Ipv4Addr::new(10,0,0,5));
        PcapReplay::meterpreter(&tap, Ipv4Addr::new(203,0,113,99), Ipv4Addr::new(10,0,0,5));
        PcapReplay::eternalblue(&tap, Ipv4Addr::new(10,0,0,99),    Ipv4Addr::new(10,0,0,5));
    }

    // ─── Main loop ─────────────────────────────────────────────────────────
    // In a real deployment this is a long-running tokio task; here we drain
    // the queue once, then exit with stats.
    let (tx, mut rx) = mpsc::unbounded_channel();
    let engine_bg = engine.clone();
    let handle = tokio::spawn(async move {
        while let Some(batch) = rx.recv().await {
            for sig in batch {
                if let Err(e) = engine_bg.ingest(sig) {
                    tracing::warn!("engine ingest error: {e}");
                }
            }
        }
    });

    #[cfg(feature = "aya_runtime")]
    loop {
        let batch = tap.poll().unwrap_or_default();
        if !batch.is_empty() {
            let _ = tx.send(batch);
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutdown signal received");
                break;
            }
        }
    }

    #[cfg(not(feature = "aya_runtime"))]
    for _ in 0..20 {
        let batch = tap.poll().unwrap_or_default();
        if !batch.is_empty() {
            let _ = tx.send(batch);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    drop(tx);
    let _ = handle.await;

    let s = engine.stats();
    println!("\n▶ stats: signals={} defenses={} strikes={} denials={} reports={}",
             s.signals, s.defenses, s.strikes, s.denials, s.reports);
    println!("▶ ledger: ./kspike-evidence.jsonl");
    Ok(())
}
