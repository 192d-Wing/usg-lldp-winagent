//! Npcap packet backend.
//!
//! `wpcap.dll` is loaded at runtime from `%SystemRoot%\System32\Npcap` by
//! absolute path, never by search order, so the service starts and reports
//! a clear error when Npcap is absent. Two pcap handles are opened per
//! adapter: one for receive (filtered to EtherType 0x88CC, inbound only)
//! owned by a blocking reader thread, and one for send owned by the port
//! task. libpcap handles are not safe for concurrent use from two threads.

use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use lldp_codec::MacAddr;
use lldp_core::packet_io::{AdapterId, PacketChannel, PacketIo, PacketIoError, RecvFuture};
use tokio::sync::mpsc;
use windows::Win32::Foundation::{FreeLibrary, HMODULE};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW, SetDllDirectoryW,
};
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows::core::PCSTR;

use crate::util::{to_wide, wide_to_string};

/// Minimum Npcap version: 1.50 added ARM64 support.
pub const MIN_NPCAP_VERSION: (u32, u32) = (1, 50);

const PCAP_ERRBUF_SIZE: usize = 256;
const PCAP_D_IN: c_int = 1;
const SNAPLEN: c_int = 9300;
const READ_TIMEOUT_MS: c_int = 1000;
const QUEUE_DEPTH: usize = 64;

#[repr(C)]
struct PcapT {
    _private: [u8; 0],
}

#[repr(C)]
struct BpfProgram {
    bf_len: c_uint,
    bf_insns: *mut c_void,
}

#[repr(C)]
struct Timeval {
    tv_sec: i32,
    tv_usec: i32,
}

#[repr(C)]
struct PcapPkthdr {
    ts: Timeval,
    caplen: u32,
    len: u32,
}

type PcapLibVersion = unsafe extern "C" fn() -> *const c_char;
type PcapCreate = unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut PcapT;
type PcapSetInt = unsafe extern "C" fn(*mut PcapT, c_int) -> c_int;
type PcapActivate = unsafe extern "C" fn(*mut PcapT) -> c_int;
type PcapCompile =
    unsafe extern "C" fn(*mut PcapT, *mut BpfProgram, *const c_char, c_int, c_uint) -> c_int;
type PcapSetFilter = unsafe extern "C" fn(*mut PcapT, *mut BpfProgram) -> c_int;
type PcapFreeCode = unsafe extern "C" fn(*mut BpfProgram);
type PcapNextEx = unsafe extern "C" fn(*mut PcapT, *mut *mut PcapPkthdr, *mut *const u8) -> c_int;
type PcapSendPacket = unsafe extern "C" fn(*mut PcapT, *const u8, c_int) -> c_int;
type PcapClose = unsafe extern "C" fn(*mut PcapT);
type PcapGetErr = unsafe extern "C" fn(*mut PcapT) -> *mut c_char;

/// Resolved entry points of `wpcap.dll`.
struct Api {
    module: HMODULE,
    lib_version: PcapLibVersion,
    create: PcapCreate,
    set_snaplen: PcapSetInt,
    set_promisc: PcapSetInt,
    set_timeout: PcapSetInt,
    set_immediate_mode: PcapSetInt,
    activate: PcapActivate,
    compile: PcapCompile,
    setfilter: PcapSetFilter,
    freecode: PcapFreeCode,
    next_ex: PcapNextEx,
    sendpacket: PcapSendPacket,
    close: PcapClose,
    geterr: PcapGetErr,
    setdirection: Option<PcapSetInt>,
    setmintocopy: Option<PcapSetInt>,
}

// SAFETY: function pointers into a loaded DLL are immutable; the module
// handle is only used in Drop.
#[allow(unsafe_code)]
unsafe impl Send for Api {}
#[allow(unsafe_code)]
unsafe impl Sync for Api {}

impl Drop for Api {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: `module` came from LoadLibraryExW and no function pointer
        // outlives this struct.
        unsafe {
            let _ = FreeLibrary(self.module);
        }
    }
}

/// The Npcap backend. Clone-cheap through `Arc`.
#[derive(Clone)]
pub struct NpcapBackend {
    api: Arc<Api>,
    version: String,
}

impl std::fmt::Debug for NpcapBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NpcapBackend")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

#[allow(unsafe_code)]
fn load_symbol<T: Copy>(module: HMODULE, name: &str) -> Result<T, PacketIoError> {
    let cname = CString::new(name)
        .map_err(|_| PacketIoError::BackendUnavailable(format!("bad symbol name {name}")))?;
    // SAFETY: `cname` is NUL-terminated and `module` is a loaded library.
    let p = unsafe { GetProcAddress(module, PCSTR(cname.as_ptr().cast())) }
        .ok_or_else(|| PacketIoError::BackendUnavailable(format!("wpcap.dll lacks {name}")))?;
    // SAFETY: the caller names the correct function pointer type for the
    // documented libpcap symbol; the sizes are identical.
    Ok(unsafe { std::mem::transmute_copy::<unsafe extern "system" fn() -> isize, T>(&p) })
}

#[allow(unsafe_code)]
fn load_optional<T: Copy>(module: HMODULE, name: &str) -> Option<T> {
    load_symbol(module, name).ok()
}

impl NpcapBackend {
    /// Loads `wpcap.dll` from the Npcap system directory and checks the
    /// version.
    #[allow(unsafe_code)]
    pub fn load() -> Result<Self, PacketIoError> {
        let mut sysdir = [0u16; 260];
        // SAFETY: the buffer is valid for its length.
        let n = unsafe { GetSystemDirectoryW(Some(&mut sysdir)) } as usize;
        if n == 0 || n >= sysdir.len() {
            return Err(PacketIoError::BackendUnavailable(
                "GetSystemDirectoryW failed".into(),
            ));
        }
        let npcap_dir = format!("{}\\Npcap", wide_to_string(&sysdir));
        let dll = format!("{npcap_dir}\\wpcap.dll");
        let dir_w = to_wide(&npcap_dir);
        let dll_w = to_wide(&dll);
        // SAFETY: both strings are NUL-terminated. SetDllDirectoryW lets
        // wpcap.dll find its sibling Packet.dll; the altered search path
        // flag makes the load relative to the DLL's own directory.
        let module = unsafe {
            let _ = SetDllDirectoryW(windows::core::PCWSTR(dir_w.as_ptr()));
            LoadLibraryExW(
                windows::core::PCWSTR(dll_w.as_ptr()),
                None,
                LOAD_WITH_ALTERED_SEARCH_PATH,
            )
        }
        .map_err(|e| PacketIoError::BackendUnavailable(format!("cannot load {dll}: {e}")))?;

        let api = Api {
            module,
            lib_version: load_symbol(module, "pcap_lib_version")?,
            create: load_symbol(module, "pcap_create")?,
            set_snaplen: load_symbol(module, "pcap_set_snaplen")?,
            set_promisc: load_symbol(module, "pcap_set_promisc")?,
            set_timeout: load_symbol(module, "pcap_set_timeout")?,
            set_immediate_mode: load_symbol(module, "pcap_set_immediate_mode")?,
            activate: load_symbol(module, "pcap_activate")?,
            compile: load_symbol(module, "pcap_compile")?,
            setfilter: load_symbol(module, "pcap_setfilter")?,
            freecode: load_symbol(module, "pcap_freecode")?,
            next_ex: load_symbol(module, "pcap_next_ex")?,
            sendpacket: load_symbol(module, "pcap_sendpacket")?,
            close: load_symbol(module, "pcap_close")?,
            geterr: load_symbol(module, "pcap_geterr")?,
            setdirection: load_optional(module, "pcap_setdirection"),
            setmintocopy: load_optional(module, "pcap_setmintocopy"),
        };
        // SAFETY: pcap_lib_version returns a static NUL-terminated string.
        let version = unsafe { CStr::from_ptr((api.lib_version)()) }
            .to_string_lossy()
            .into_owned();
        let parsed = crate::parse::parse_npcap_version(&version);
        if let Some(v) = parsed
            && v < MIN_NPCAP_VERSION
        {
            return Err(PacketIoError::BackendUnavailable(format!(
                "Npcap {}.{} is older than the required {}.{} ({version})",
                v.0, v.1, MIN_NPCAP_VERSION.0, MIN_NPCAP_VERSION.1
            )));
        }
        Ok(Self {
            api: Arc::new(api),
            version,
        })
    }

    /// The string reported by `pcap_lib_version`.
    pub fn version(&self) -> &str {
        &self.version
    }

    #[allow(unsafe_code)]
    fn open_handle(
        &self,
        device: &CStr,
        adapter: &AdapterId,
        filter: Option<&str>,
        inbound_only: bool,
    ) -> Result<Handle, PacketIoError> {
        let api = &self.api;
        let mut errbuf = [0 as c_char; PCAP_ERRBUF_SIZE];
        let fail = |reason: String| PacketIoError::OpenFailed {
            adapter: adapter.clone(),
            reason,
        };
        // SAFETY: all pointers are valid for the calls; `p` is closed on
        // every error path and owned by `Handle` on success.
        unsafe {
            let p = (api.create)(device.as_ptr(), errbuf.as_mut_ptr());
            if p.is_null() {
                return Err(fail(
                    CStr::from_ptr(errbuf.as_ptr())
                        .to_string_lossy()
                        .into_owned(),
                ));
            }
            let mut h = Handle {
                api: Arc::clone(api),
                p,
            };
            (api.set_snaplen)(p, SNAPLEN);
            (api.set_promisc)(p, 0);
            (api.set_timeout)(p, READ_TIMEOUT_MS);
            (api.set_immediate_mode)(p, 1);
            let rc = (api.activate)(p);
            if rc < 0 {
                return Err(fail(format!("pcap_activate: {}", h.last_error())));
            }
            if inbound_only && let Some(setdir) = api.setdirection {
                // Best effort: avoids receiving our own transmissions. The
                // port also drops frames whose source is its own MAC.
                let _ = setdir(p, PCAP_D_IN);
            }
            if let Some(mintocopy) = api.setmintocopy {
                let _ = mintocopy(p, 0);
            }
            if let Some(f) = filter {
                let cf = CString::new(f).map_err(|_| fail("bad filter".into()))?;
                let mut prog = BpfProgram {
                    bf_len: 0,
                    bf_insns: std::ptr::null_mut(),
                };
                if (api.compile)(p, &raw mut prog, cf.as_ptr(), 1, 0) < 0 {
                    return Err(fail(format!("pcap_compile: {}", h.last_error())));
                }
                let rc = (api.setfilter)(p, &raw mut prog);
                (api.freecode)(&raw mut prog);
                if rc < 0 {
                    return Err(fail(format!("pcap_setfilter: {}", h.last_error())));
                }
            }
            h.p = p;
            Ok(h)
        }
    }
}

struct Handle {
    api: Arc<Api>,
    p: *mut PcapT,
}

// SAFETY: a Handle is used from exactly one thread at a time; the pcap
// handle itself has no thread affinity.
#[allow(unsafe_code)]
unsafe impl Send for Handle {}

impl Handle {
    #[allow(unsafe_code)]
    fn last_error(&self) -> String {
        // SAFETY: pcap_geterr returns a NUL-terminated buffer owned by `p`.
        unsafe { CStr::from_ptr((self.api.geterr)(self.p)) }
            .to_string_lossy()
            .into_owned()
    }
}

impl Drop for Handle {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        if !self.p.is_null() {
            // SAFETY: `p` was returned by pcap_create and not yet closed.
            unsafe { (self.api.close)(self.p) };
            self.p = std::ptr::null_mut();
        }
    }
}

/// An open Npcap channel.
pub struct NpcapChannel {
    mac: MacAddr,
    send: Handle,
    rx: mpsc::Receiver<Vec<u8>>,
    stop: Arc<AtomicBool>,
    overflow: Arc<AtomicU64>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl NpcapChannel {
    /// Frames dropped because the port task was not keeping up.
    pub fn overflow_count(&self) -> u64 {
        self.overflow.load(Ordering::Relaxed)
    }
}

impl Drop for NpcapChannel {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.reader.take() {
            // The reader wakes at least every READ_TIMEOUT_MS.
            let _ = t.join();
        }
    }
}

impl PacketChannel for NpcapChannel {
    fn mac(&self) -> MacAddr {
        self.mac
    }

    #[allow(unsafe_code)]
    fn send(&mut self, frame: &[u8]) -> Result<(), PacketIoError> {
        let len = c_int::try_from(frame.len())
            .map_err(|_| PacketIoError::SendFailed("frame too large".into()))?;
        // SAFETY: `frame` is valid for `len` bytes; `p` is an activated handle.
        let rc = unsafe { (self.send.api.sendpacket)(self.send.p, frame.as_ptr(), len) };
        if rc != 0 {
            Err(PacketIoError::SendFailed(self.send.last_error()))
        } else {
            Ok(())
        }
    }

    fn recv(&mut self) -> RecvFuture<'_> {
        Box::pin(async move { self.rx.recv().await.ok_or(PacketIoError::Closed) })
    }
}

impl PacketIo for NpcapBackend {
    #[allow(unsafe_code)]
    fn open(&self, adapter: &AdapterId) -> Result<Box<dyn PacketChannel>, PacketIoError> {
        let info = crate::adapters::enumerate()
            .map_err(|e| PacketIoError::OpenFailed {
                adapter: adapter.clone(),
                reason: e.to_string(),
            })?
            .into_iter()
            .find(|a| a.guid.eq_ignore_ascii_case(&adapter.0))
            .ok_or_else(|| PacketIoError::OpenFailed {
                adapter: adapter.clone(),
                reason: "adapter not found".into(),
            })?;
        let mac = info.mac.ok_or_else(|| PacketIoError::OpenFailed {
            adapter: adapter.clone(),
            reason: "adapter has no MAC address".into(),
        })?;
        let device = CString::new(format!("\\Device\\NPF_{}", info.guid)).map_err(|_| {
            PacketIoError::OpenFailed {
                adapter: adapter.clone(),
                reason: "bad device name".into(),
            }
        })?;

        let recv = self.open_handle(&device, adapter, Some("ether proto 0x88cc"), true)?;
        let send = self.open_handle(&device, adapter, None, false)?;

        let (tx, rx) = mpsc::channel(QUEUE_DEPTH);
        let stop = Arc::new(AtomicBool::new(false));
        let overflow = Arc::new(AtomicU64::new(0));
        let reader = {
            let stop = Arc::clone(&stop);
            let overflow = Arc::clone(&overflow);
            let name = format!("npcap-rx-{}", info.alias);
            std::thread::Builder::new()
                .name(name)
                .spawn(move || reader_loop(&recv, &tx, &stop, &overflow))
                .map_err(|e| PacketIoError::OpenFailed {
                    adapter: adapter.clone(),
                    reason: format!("thread: {e}"),
                })?
        };
        Ok(Box::new(NpcapChannel {
            mac,
            send,
            rx,
            stop,
            overflow,
            reader: Some(reader),
        }))
    }
}

#[allow(unsafe_code)]
fn reader_loop(h: &Handle, tx: &mpsc::Sender<Vec<u8>>, stop: &AtomicBool, overflow: &AtomicU64) {
    while !stop.load(Ordering::Relaxed) {
        let mut hdr: *mut PcapPkthdr = std::ptr::null_mut();
        let mut data: *const u8 = std::ptr::null();
        // SAFETY: `h.p` is an activated handle; on return 1, `hdr` and
        // `data` point to a packet valid until the next call.
        let rc = unsafe { (h.api.next_ex)(h.p, &raw mut hdr, &raw mut data) };
        match rc {
            1 => {
                // SAFETY: as above; `as_ref` turns a null header into None.
                let Some(hdr) = (unsafe { hdr.as_ref() }) else {
                    continue;
                };
                if data.is_null() {
                    continue;
                }
                // SAFETY: as above; caplen bytes are readable at `data`.
                let frame =
                    unsafe { std::slice::from_raw_parts(data, hdr.caplen as usize) }.to_vec();
                match tx.try_send(frame) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        overflow.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => return,
                }
            }
            0 => {}      // timeout; loop re-checks `stop`
            _ => return, // -1 error or -2 EOF: channel closes, port task sees Closed
        }
    }
}
