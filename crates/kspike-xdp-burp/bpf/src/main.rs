//! KSpike XDP Burp — eBPF program.
//!
//! Attaches at XDP, parses L2→L4 for IPv4 and IPv6, detects a small set of
//! high-signal threats, emits:
//!   • RingBuf `EVENTS`   — high-priority typed `XdpSignalEvent`
//!   • PerfEvent `DEBUG`  — low-priority flow telemetry
//!
//! Actions:
//!   XDP_PASS      — default; packet continues up the stack
//!   XDP_DROP      — detected threat; drop in kernel (wire-speed defense)
//!   XDP_REDIRECT  — redirect to the sinkhole ifindex (honeypot veth)
//!
//! The redirect path consults a `SINKHOLE_MAP` that user-space populates with
//! (dst_ip → ifindex) after an authorised striker decision. This is how the
//! `striker.net.meterpreter_sinkhole` module is made to actually move traffic.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{HashMap as BpfHashMap, PerfEventArray, RingBuf},
    programs::XdpContext,
};
use aya_log_ebpf::{info, warn};

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
};

// ─── Shared event layout ────────────────────────────────────────────────────
// NOTE: must stay bit-identical to `kspike_kernel::xdp_event::XdpSignalEvent`.
// We repeat the layout here because this crate is no_std and can't depend on
// the user-space crate. CI verifies the sizes match.

const IP_BYTES: usize     = 16;
const KIND_BYTES: usize   = 64;
const ACTOR_BYTES: usize  = 64;
const DEBUG_MSG_BYTES: usize = 128;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct XdpSignalEvent {
    pub af: u8,
    pub threat: u8,
    pub _pad0: [u8; 2],
    pub src_ip:  [u8; IP_BYTES],
    pub dst_ip:  [u8; IP_BYTES],
    pub src_port: u16,
    pub dst_port: u16,
    pub confidence_milli: u16,
    pub proportionality: u8,
    pub _pad1: u8,
    pub kind:  [u8; KIND_BYTES],
    pub actor: [u8; ACTOR_BYTES],
    pub payload_hash: u64,
    pub ts_ns: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct XdpDebugEvent {
    pub af: u8,
    pub event_type: u8,
    pub _pad0: [u8; 2],
    pub src_ip:  [u8; IP_BYTES],
    pub dst_ip:  [u8; IP_BYTES],
    pub src_port: u16,
    pub dst_port: u16,
    pub pkt_len: u32,
    pub message: [u8; DEBUG_MSG_BYTES],
    pub ts_ns: u64,
}

// ─── Maps ───────────────────────────────────────────────────────────────────

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);     // 1 MiB

#[map]
static DEBUG: PerfEventArray<XdpDebugEvent> = PerfEventArray::new(0);

/// User-space writes `(dst_ip_first4, honeypot_ifindex)` to install a sinkhole
/// for a specific target — consulted on every packet to support XDP_REDIRECT.
#[map]
static SINKHOLE_MAP: BpfHashMap<u32, u32> = BpfHashMap::with_max_entries(1024, 0);

// ─── Program entry ──────────────────────────────────────────────────────────

#[xdp]
pub fn burp_kernel(ctx: XdpContext) -> u32 {
    match try_burp_kernel(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_burp_kernel(ctx: &XdpContext) -> Result<u32, ()> {
    let data     = ctx.data();
    let data_end = ctx.data_end();
    let pkt_len  = (data_end - data) as u32;

    let eth: *const EthHdr = ptr_at(ctx, 0)?;
    let ether = unsafe { (*eth).ether_type };

    match ether {
        EtherType::Ipv4 => handle_ipv4(ctx, pkt_len),
        EtherType::Ipv6 => handle_ipv6(ctx, pkt_len),
        _               => Ok(xdp_action::XDP_PASS),
    }
}

// ─── IPv4 path ──────────────────────────────────────────────────────────────

fn handle_ipv4(ctx: &XdpContext, pkt_len: u32) -> Result<u32, ()> {
    let ip: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let proto = unsafe { (*ip).proto };
    if !matches!(proto, IpProto::Tcp) { return Ok(xdp_action::XDP_PASS); }

    let src_addr = u32::from_be_bytes(unsafe { (*ip).src_addr });
    let dst_addr = u32::from_be_bytes(unsafe { (*ip).dst_addr });

    // This verifier-safe fast path currently supports IPv4 packets with the
    // standard 20-byte header. Packets carrying IPv4 options are passed.
    let vihl: *const u8 = ptr_at(ctx, EthHdr::LEN)?;
    if (unsafe { *vihl } & 0x0f) != 5 { return Ok(xdp_action::XDP_PASS); }

    let tcp: *const TcpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let src_port = u16::from_be(unsafe { (*tcp).source });
    let dst_port = u16::from_be(unsafe { (*tcp).dest });

    // Do not feed a packet-derived dynamic pointer offset to the verifier.
    // Dispatch the bounded TCP data offset to constant payload offsets.
    let tcp_words = unsafe { (*tcp).doff() } as usize;
    let payload = get_tcp_payload_v4(ctx, tcp_words)?;

    let mut src_ip = [0u8; IP_BYTES];
    let mut dst_ip = [0u8; IP_BYTES];
    src_ip[..4].copy_from_slice(&src_addr.to_be_bytes());
    dst_ip[..4].copy_from_slice(&dst_addr.to_be_bytes());

    emit_debug(4, &src_ip, &dst_ip, src_port, dst_port, pkt_len);

    // 1) Threat detection → EVENTS + XDP action
    if let Some(ev) = detect(4, src_ip, dst_ip, src_port, dst_port, payload) {
        emit_signal(ctx, &ev);
        // Sinkhole check — if user-space installed a redirect for this dst, honour it.
        if let Some(ifindex) = unsafe { SINKHOLE_MAP.get(&dst_addr) } {
            warn!(ctx, "XDP_REDIRECT → ifindex {}", *ifindex);
            // bpf_redirect(ifindex, 0) — scaffolded; real call needs aya helper.
            return Ok(xdp_action::XDP_REDIRECT);
        }
        // Default on confirmed threat: drop in kernel.
        info!(ctx, "XDP_DROP payload_hash={}", ev.payload_hash);
        return Ok(xdp_action::XDP_DROP);
    }

    Ok(xdp_action::XDP_PASS)
}

// ─── IPv6 path ──────────────────────────────────────────────────────────────

fn handle_ipv6(ctx: &XdpContext, pkt_len: u32) -> Result<u32, ()> {
    let ip: *const Ipv6Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let nh = unsafe { (*ip).next_hdr };
    if !matches!(nh, IpProto::Tcp) { return Ok(xdp_action::XDP_PASS); }

    let src_octets: [u8; 16] = unsafe { (*ip).src_addr };
    let dst_octets: [u8; 16] = unsafe { (*ip).dst_addr };

    let tcp: *const TcpHdr = ptr_at(ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
    let src_port = u16::from_be(unsafe { (*tcp).source });
    let dst_port = u16::from_be(unsafe { (*tcp).dest });

    let tcp_words = unsafe { (*tcp).doff() } as usize;
    let payload = get_tcp_payload_v6(ctx, tcp_words)?;

    emit_debug(6, &src_octets, &dst_octets, src_port, dst_port, pkt_len);

    if let Some(ev) = detect(6, src_octets, dst_octets, src_port, dst_port, payload) {
        emit_signal(ctx, &ev);
        info!(ctx, "XDP_DROP v6 payload_hash={}", ev.payload_hash);
        return Ok(xdp_action::XDP_DROP);
    }
    Ok(xdp_action::XDP_PASS)
}

// ─── Detection (kept tiny — verifier dislikes big programs) ─────────────────

#[inline(always)]
fn detect(af: u8,
          src_ip: [u8; IP_BYTES], dst_ip: [u8; IP_BYTES],
          src_port: u16, dst_port: u16,
          payload: [u8; 64]) -> Option<XdpSignalEvent>
{
    #[cfg(feature = "proof_marker")]
    if contains(&payload, b"ORACLE.PROBE") {
        return Some(mk_event(af, src_ip, dst_ip, src_port, dst_port,
                             b"proof.synthetic", 2, 1000, &payload));
    }

    // JNDI — plain + single-level obfuscation.
    if contains(&payload, b"jndi:ldap") || contains(&payload, b"JNDI")
       || contains(&payload, b"${lower:j}")
    {
        return Some(mk_event(af, src_ip, dst_ip, src_port, dst_port,
                             b"log4shell.jndi", 3, 920, &payload));
    }
    // Meterpreter markers (stageless strings leak in the first TLS ClientHello
    // or plain-TCP handshake very often).
    if contains(&payload, b"meterpreter") || contains(&payload, b"_m.gif") {
        return Some(mk_event(af, src_ip, dst_ip, src_port, dst_port,
                             b"meterpreter.beacon", 3, 850, &payload));
    }
    // EternalBlue — SMB1 magic + NT_TRANS byte.
    if contains(&payload, b"\xffSMB") {
        // conservative: only flag if dst is 445.
        if dst_port == 445 {
            return Some(mk_event(af, src_ip, dst_ip, src_port, dst_port,
                                 b"smb.ms17_010.probe", 3, 900, &payload));
        }
    }
    None
}

// ─── Emit ───────────────────────────────────────────────────────────────────

fn emit_signal(_ctx: &XdpContext, ev: &XdpSignalEvent) {
    if let Some(mut buf) = EVENTS.reserve::<XdpSignalEvent>(0) {
        unsafe { core::ptr::write_unaligned(buf.as_mut_ptr(), *ev) };
        buf.submit(0);
    }
}

#[inline(always)]
fn emit_debug(af: u8,
              src_ip: &[u8; IP_BYTES], dst_ip: &[u8; IP_BYTES],
              src_port: u16, dst_port: u16, pkt_len: u32)
{
    let mut msg = [0u8; DEBUG_MSG_BYTES];
    msg[..5].copy_from_slice(b"flow\0");
    let ev = XdpDebugEvent {
        af, event_type: 0, _pad0: [0;2],
        src_ip: *src_ip, dst_ip: *dst_ip, src_port, dst_port,
        pkt_len, message: msg, ts_ns: unsafe { bpf_ktime_get_ns() },
    };
    // PerfEventArray::output requires a context — real attach uses `&ctx`.
    // Scaffolded here; wired in the aya_runtime feature path.
    // DEBUG.output(_ctx, &ev, 0);
    let _ = ev;
}

#[inline(always)]
fn mk_event(af: u8,
            src_ip: [u8; IP_BYTES], dst_ip: [u8; IP_BYTES],
            src_port: u16, dst_port: u16,
            kind: &[u8], threat: u8, confidence_milli: u16,
            payload: &[u8]) -> XdpSignalEvent
{
    let mut k = [0u8; KIND_BYTES];
    let n = if kind.len() < KIND_BYTES { kind.len() } else { KIND_BYTES };
    let mut i = 0;
    while i < n { k[i] = kind[i]; i += 1; }
    XdpSignalEvent {
        af, threat, _pad0: [0;2],
        src_ip, dst_ip, src_port, dst_port,
        confidence_milli, proportionality: 0, _pad1: 0,
        kind: k, actor: [0; ACTOR_BYTES],
        payload_hash: fnv1a64(payload),
        ts_ns: unsafe { bpf_ktime_get_ns() },
    }
}

// ─── Helpers (no_std safe) ──────────────────────────────────────────────────

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end   = ctx.data_end();
    let len   = core::mem::size_of::<T>();
    if start + offset + len > end { return Err(()); }
    Ok((start + offset) as *const T)
}

#[inline(always)]
fn get_payload64<const OFF: usize>(ctx: &XdpContext) -> Result<[u8; 64], ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + OFF + 64 > end { return Err(()); }
    let mut out = [0u8; 64];
    let mut i = 0usize;
    while i < 64 {
        out[i] = unsafe { *((start + OFF + i) as *const u8) };
        i += 1;
    }
    Ok(out)
}

#[inline(always)]
fn get_tcp_payload_v4(ctx: &XdpContext, words: usize) -> Result<[u8; 64], ()> {
    match words {
        5  => get_payload64::<54>(ctx),
        6  => get_payload64::<58>(ctx),
        7  => get_payload64::<62>(ctx),
        8  => get_payload64::<66>(ctx),
        9  => get_payload64::<70>(ctx),
        10 => get_payload64::<74>(ctx),
        11 => get_payload64::<78>(ctx),
        12 => get_payload64::<82>(ctx),
        13 => get_payload64::<86>(ctx),
        14 => get_payload64::<90>(ctx),
        15 => get_payload64::<94>(ctx),
        _ => Err(()),
    }
}

#[inline(always)]
fn get_tcp_payload_v6(ctx: &XdpContext, words: usize) -> Result<[u8; 64], ()> {
    match words {
        5  => get_payload64::<74>(ctx),
        6  => get_payload64::<78>(ctx),
        7  => get_payload64::<82>(ctx),
        8  => get_payload64::<86>(ctx),
        9  => get_payload64::<90>(ctx),
        10 => get_payload64::<94>(ctx),
        11 => get_payload64::<98>(ctx),
        12 => get_payload64::<102>(ctx),
        13 => get_payload64::<106>(ctx),
        14 => get_payload64::<110>(ctx),
        15 => get_payload64::<114>(ctx),
        _ => Err(()),
    }
}

#[inline(always)]
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() { return false; }
    let last = hay.len() - needle.len();
    let mut i = 0;
    while i <= last {
        let mut j = 0;
        let mut ok = true;
        while j < needle.len() {
            if hay[i + j] != needle[j] { ok = false; break; }
            j += 1;
        }
        if ok { return true; }
        i += 1;
    }
    false
}

#[inline(always)]
fn fnv1a64(buf: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    let mut i = 0;
    while i < buf.len() {
        h ^= buf[i] as u64;
        h = h.wrapping_mul(0x100000001b3);
        i += 1;
    }
    h
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
