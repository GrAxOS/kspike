# kspike

> Dual-mode kernel defense and active-response framework — Casper-governed, judge-gated, forever auditable.

[![CI](https://github.com/Graxos/kspike/actions/workflows/ci.yml/badge.svg)](https://github.com/Graxos/kspike/actions)
[![License](https://img.shields.io/badge/license-See%20LICENSE-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)

**Status:** v0.7 — LSM paths + FFI integration working end-to-end. Public preview.

---

## What it is

`kspike` is a kernel-layer defense framework written in Rust. It combines:

- **eBPF/LSM observation paths** — read-only telemetry from the Linux Security Module hooks.
- **A Casper "judge" pipeline** — every active-response action passes through a deterministic policy gate before it executes, producing a tamper-evident audit log.
- **Dual-mode operation** — Observation mode for monitoring; Response mode for in-kernel mitigation.

It is designed for environments that need EDR-grade kernel visibility but cannot ship closed-source vendor agents — regulated industries, sovereign deployments, air-gapped clusters.

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

- `crates/observer` — eBPF/LSM event ingestion
- `crates/judge` — policy evaluation, deterministic
- `crates/casper-ffi` — bridge to the Casper inference engine for context-aware decisions
- `crates/ledger` — append-only signed audit log

See [`ROADMAP.md`](ROADMAP.md) for v1.0 plans.

## Status & honest caveats

This is a **public preview at v0.7**. End-to-end LSM + FFI works on Linux x86_64. The following are **not** production-ready yet:

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

See [LICENSE](LICENSE).
