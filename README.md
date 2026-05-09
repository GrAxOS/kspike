# kspike

> Dual-mode kernel defense and active-response framework — Casper-governed, judge-gated, forever auditable.

[![CI](https://github.com/Graxos/kspike/actions/workflows/ci.yml/badge.svg)](https://github.com/Graxos/kspike/actions)
[![License](https://img.shields.io/badge/license-See%20LICENSE-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)

**Status:** v0.4 — Daemon + TUI + Casper governance + Honeypot + K-Forge shipped. 18-crate Rust workspace, public preview.

---

## What it is

`kspike` is a kernel-layer defense framework written in Rust. It combines:

- **eBPF/XDP and LSM observation paths** — kernel-fast-path packet inspection plus Linux Security Module telemetry.
- **A Casper "judge" pipeline** — every active-response action passes through a deterministic policy gate before it executes, producing a tamper-evident, ed25519-signed audit log.
- **Dual-mode operation** — Observation mode for monitoring; Response mode for in-kernel mitigation.

It is designed for environments that need EDR-grade kernel visibility but cannot ship closed-source vendor agents — regulated industries, sovereign deployments, air-gapped clusters.

## What's shipped (v0.1 → v0.4)

- **v0.1 — Foundation:** core engine (Module trait, EventBus, Evidence), Khz balancer, judge framework (Static / Khz / Manual, 4-condition ROE), CLI.
- **v0.2 — MSF-Mirror:** 9 defense modules mirroring real Metasploit techniques — EternalBlue, PSExec, Log4Shell, Shikata, Meterpreter ×2, Kerberoast, credential-dump canary, canary tokens.
- **v0.3 — XDP-Burp:** user-space tokio loader + eBPF XDP program, RingBuf + PerfEventArray + sinkhole map, FNV-1a no-alloc hash, IPv4/IPv6 schema, MSF-mirror modules wired to the XDP fast-path.
- **v0.4 — Daemon + TUI + Honeypot + K-Forge:** UNIX-socket daemon (kspiked) with hardened systemd unit, msfconsole-style interactive REPL (zero extra deps), honeypot profiles for Win10 / Ubuntu 20.04 / SMB Win7, Casper FFI integration.

See [`ROADMAP.md`](ROADMAP.md) for the full version history and v1.0 plans.

## Why "judge-gated"

Most kernel-response tools execute mitigations as soon as a rule fires. `kspike` requires every mitigation to be approved by an offline-verifiable policy (the "judge") and emits a signed decision record. If you can't explain why a kernel killed a process six months later, you can't pass an audit. This pipeline exists so that you can.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  eBPF / LSM │ ──▶ │ Judge (Rust) │ ──▶ │ Action / FFI │
│  observers  │     │  policy gate │     │   to Casper  │
└─────────────┘     └──────────────┘     └──────────────┘
                            │
                            ▼
                    ┌──────────────┐
                    │ Audit ledger │
                    │ (append-only)│
                    └──────────────┘
```

The 18-crate workspace splits responsibilities cleanly — `kspike-core`, `kspike-judge`, `kspike-ebpf-lsm`, `kspike-xdp-burp`, `kspike-honeypot`, `kspike-casper-ffi`, `kspike-daemon`, `kspike-tui`, `kspike-cli`, and others. The eBPF sub-crates build with the `bpfel-unknown-none` target and are excluded from the host workspace build.

## Status & honest caveats

This is a **public preview at v0.4**. The workspace builds and runs on Linux x86_64 with the components listed above.

The following are **not** production-ready yet:

- ARM64 / NEON paths (planned)
- Multi-node ledger replication
- Formal verification of the judge pipeline (in design)

If you are evaluating `kspike` for production use, please open a discussion or reach out directly — see *Commercial use* below.

## Build

```bash
cargo build --release
```

Requires: Linux 5.15+, Rust 1.75+, kernel headers, `clang` for eBPF compilation.

## Why this exists

Built by [Sulaiman Alshammari](https://github.com/Grar00t) at [Graxos](https://github.com/Graxos) — sovereign AI infrastructure, built in Riyadh.

## Commercial use & advisory

`kspike` is open for inspection. For:

- Production hardening engagements
- Custom LSM/eBPF integrations
- Kernel-security architecture reviews

Contact: **cartier403c@gmail.com** · DM on GitHub.

## License

Casper-Sovereign License 1.0 — see [LICENSE](LICENSE).
