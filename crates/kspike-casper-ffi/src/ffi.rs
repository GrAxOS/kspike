//! Low-level FFI bindings. Behind `link_casper`, we dlopen libcasper.so at
//! runtime so the binary stays linkable without Casper on the host.

#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::ffi::CString;
use std::sync::{Mutex, OnceLock};

use libc::{c_char, c_int, c_void};

#[derive(Debug)]
pub struct CasperLib {
    init:     unsafe extern "C" fn(*const c_char) -> c_int,
    evaluate: unsafe extern "C" fn(*const c_char, *mut c_char, c_int) -> c_int,
    shutdown: unsafe extern "C" fn(),
    version:  unsafe extern "C" fn() -> *const c_char,
    handle:   *mut c_void,
}

unsafe impl Send for CasperLib {}
unsafe impl Sync for CasperLib {}

static LIB: OnceLock<Mutex<Option<CasperLib>>> = OnceLock::new();

#[cfg(feature = "link_casper")]
mod imp {
    use super::*;
    use libc::{dlerror, dlopen, dlsym, RTLD_NOW};

    fn last_dlerror() -> String {
        unsafe {
            let p = dlerror();
            if p.is_null() { return "<unknown>".into(); }
            std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }

    pub unsafe fn load(path: &str) -> anyhow::Result<CasperLib> {
        // Clear stale error.
        let _ = unsafe { dlerror() };
        let cpath = CString::new(path)?;
        let h = unsafe { dlopen(cpath.as_ptr(), RTLD_NOW) };
        if h.is_null() {
            anyhow::bail!("dlopen({path}) failed: {}", last_dlerror());
        }

        unsafe fn sym<T>(h: *mut c_void, name: &[u8]) -> anyhow::Result<T> {
            let s = unsafe { dlsym(h, name.as_ptr() as *const c_char) };
            if s.is_null() {
                let n = std::str::from_utf8(&name[..name.len().saturating_sub(1)])
                    .unwrap_or("?");
                anyhow::bail!("dlsym({n}) missing");
            }
            // SAFETY: caller guarantees the signature.
            Ok(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&s) })
        }

        Ok(CasperLib {
            init:     unsafe { sym(h, b"casper_init\0")? },
            evaluate: unsafe { sym(h, b"casper_judge_evaluate\0")? },
            shutdown: unsafe { sym(h, b"casper_shutdown\0")? },
            version:  unsafe { sym(h, b"casper_version\0")? },
            handle: h,
        })
    }
}

#[cfg(not(feature = "link_casper"))]
mod imp {
    use super::*;
    pub unsafe fn load(_path: &str) -> anyhow::Result<CasperLib> {
        anyhow::bail!("kspike-casper-ffi built without `link_casper` feature")
    }
}

pub fn init(model_path: &str) -> anyhow::Result<()> {
    // Allow override via env (helpful for tests / dev installs).
    let so_path = std::env::var("KSPIKE_CASPER_LIB")
        .unwrap_or_else(|_| "libcasper.so".into());
    let lib = unsafe { imp::load(&so_path)? };
    let cp = CString::new(model_path)?;
    let rc = unsafe { (lib.init)(cp.as_ptr()) };
    if rc != 0 { anyhow::bail!("casper_init returned {rc}"); }
    let slot = LIB.get_or_init(|| Mutex::new(None));
    *slot.lock().unwrap() = Some(lib);
    Ok(())
}

pub fn evaluate(req_json: &str) -> anyhow::Result<String> {
    let slot = LIB.get().ok_or_else(|| anyhow::anyhow!("casper not initialised"))?;
    let guard = slot.lock().unwrap();
    let lib = guard.as_ref().ok_or_else(|| anyhow::anyhow!("casper not initialised"))?;

    let req = CString::new(req_json)?;
    let mut out = vec![0u8; 65_536];
    let n = unsafe {
        (lib.evaluate)(
            req.as_ptr(),
            out.as_mut_ptr() as *mut c_char,
            out.len() as c_int,
        )
    };
    if n < 0 { anyhow::bail!("casper_judge_evaluate returned {n}"); }
    if n as usize > out.len() { anyhow::bail!("casper_judge_evaluate overflow: {n}"); }
    out.truncate(n as usize);
    Ok(String::from_utf8(out)?)
}

pub fn available() -> bool { cfg!(feature = "link_casper") }

/// Get the Casper Engine version string. Returns "stub" if not linked.
pub fn version() -> String {
    if !available() { return "stub".into(); }
    let slot = match LIB.get() { Some(s) => s, None => return "uninitialised".into() };
    let guard = slot.lock().unwrap();
    let Some(lib) = guard.as_ref() else { return "uninitialised".into(); };
    let p = unsafe { (lib.version)() };
    if p.is_null() { return "<null-version>".into(); }
    unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned()
}
