use anyhow::{Context, Result};
use kspike_kernel::kind_str;
use kspike_xdp_burp::{runtime, AttachMode, XdpBurpConfig, XdpBurpTap};
use std::env;
use std::path::Path;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    let iface = env::var("KSPIKE_IFACE").context("KSPIKE_IFACE missing")?;
    let bpf = env::var("KSPIKE_BPF").context("KSPIKE_BPF missing")?;
    let hold_ms: u64 = env::var("KSPIKE_HOLD_MS")
        .unwrap_or_else(|_| "8000".to_string())
        .parse()
        .context("KSPIKE_HOLD_MS invalid")?;

    let mut cfg = XdpBurpConfig::default();
    cfg.interface = iface.clone();
    cfg.mode = AttachMode::Skb;
    let mut tap = XdpBurpTap::new(cfg);
    let sink = tap.sink();

    let rt = runtime::attach(&mut tap, Path::new(&bpf)).await?;
    println!("KSPIKE_XDP_ATTACHED iface={iface} bpf={bpf} hold_ms={hold_ms}");
    tokio::time::sleep(Duration::from_millis(hold_ms)).await;
    let events = {
        let mut q = sink.lock().unwrap();
        q.drain(..).collect::<Vec<_>>()
    };
    println!("KSPIKE_EVENT_COUNT={}", events.len());
    for (i, ev) in events.iter().enumerate() {
        println!(
            "KSPIKE_EVENT index={} kind={} threat={} confidence_milli={} src_port={} dst_port={} payload_hash={:016x} ts_ns={}",
            i, kind_str(&ev.kind), ev.threat, ev.confidence_milli,
            ev.src_port, ev.dst_port, ev.payload_hash, ev.ts_ns
        );
    }

    drop(rt);
    println!("KSPIKE_XDP_PROBE_DONE iface={iface}");
    Ok(())
}
