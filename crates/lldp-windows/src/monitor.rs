//! Event-driven interface change detection using
//! `NotifyIpInterfaceChange` and `NotifyUnicastIpAddressChange`.
//!
//! The callbacks only wake a Tokio `Notify`; the async side re-enumerates
//! (debounced) and diffs against the previous snapshot. This keeps all
//! real work off the system callback thread.

use std::collections::BTreeMap;
use std::ffi::c_void;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
    NotifyIpInterfaceChange, NotifyUnicastIpAddressChange,
};
use windows::Win32::Networking::WinSock::AF_UNSPEC;

use lldp_core::{InterfaceChange, InterfaceInfo};

use crate::adapters::{EnumerateError, enumerate};

/// Registered system notifications. Cancelled on drop.
pub struct Subscription {
    iface: HANDLE,
    addr: HANDLE,
    notify: Arc<Notify>,
}

// SAFETY: the handles are only used for cancellation and the Arc is Sync.
#[allow(unsafe_code)]
unsafe impl Send for Subscription {}
#[allow(unsafe_code)]
unsafe impl Sync for Subscription {}

#[allow(unsafe_code)]
unsafe extern "system" fn on_interface_change(
    ctx: *const c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: `ctx` is the Arc<Notify> pointer registered in `subscribe`,
    // kept alive by `Subscription` until after cancellation.
    unsafe { (*ctx.cast::<Notify>()).notify_one() };
}

#[allow(unsafe_code)]
unsafe extern "system" fn on_address_change(
    ctx: *const c_void,
    _row: *const MIB_UNICASTIPADDRESS_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: as above.
    unsafe { (*ctx.cast::<Notify>()).notify_one() };
}

impl Subscription {
    /// Registers for interface and address change notifications.
    #[allow(unsafe_code)]
    pub fn subscribe() -> Result<Self, EnumerateError> {
        let notify = Arc::new(Notify::new());
        let ctx = Arc::as_ptr(&notify).cast::<c_void>();
        let mut iface = HANDLE::default();
        let mut addr = HANDLE::default();
        // SAFETY: `ctx` outlives the registration because `notify` is
        // stored in the returned Subscription, whose Drop cancels first.
        let rc = unsafe {
            NotifyIpInterfaceChange(
                AF_UNSPEC,
                Some(on_interface_change),
                Some(ctx),
                false,
                &raw mut iface,
            )
        };
        if rc.is_err() {
            return Err(EnumerateError(format!(
                "NotifyIpInterfaceChange returned {}",
                rc.0
            )));
        }
        // SAFETY: as above.
        let rc = unsafe {
            NotifyUnicastIpAddressChange(
                AF_UNSPEC,
                Some(on_address_change),
                Some(ctx),
                false,
                &raw mut addr,
            )
        };
        if rc.is_err() {
            // SAFETY: cancelling a handle we just received.
            unsafe {
                let _ = CancelMibChangeNotify2(iface);
            }
            return Err(EnumerateError(format!(
                "NotifyUnicastIpAddressChange returned {}",
                rc.0
            )));
        }
        Ok(Self {
            iface,
            addr,
            notify,
        })
    }

    /// Waits until the system reports a change.
    pub async fn changed(&self) {
        self.notify.notified().await;
    }
}

impl Drop for Subscription {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: handles came from the Notify* registrations; cancelling
        // blocks until any in-flight callback returns, so the Notify can be
        // dropped afterwards.
        unsafe {
            let _ = CancelMibChangeNotify2(self.iface);
            let _ = CancelMibChangeNotify2(self.addr);
        }
    }
}

/// Keeps a snapshot and produces events on each refresh.
#[derive(Debug, Default)]
pub struct Differ {
    current: BTreeMap<String, InterfaceInfo>,
}

impl Differ {
    /// Replaces the snapshot with `fresh` and returns what changed.
    pub fn update(&mut self, fresh: Vec<InterfaceInfo>) -> Vec<InterfaceChange> {
        let mut events = Vec::new();
        let mut next = BTreeMap::new();
        for a in fresh {
            match self.current.remove(&a.guid) {
                None => events.push(InterfaceChange::Added(a.clone())),
                Some(old) => {
                    if old.connected != a.connected {
                        events.push(if a.connected {
                            InterfaceChange::LinkUp(a.clone())
                        } else {
                            InterfaceChange::LinkDown(a.clone())
                        });
                    } else if old != a {
                        events.push(InterfaceChange::Changed(a.clone()));
                    }
                }
            }
            next.insert(a.guid.clone(), a);
        }
        for (_, gone) in std::mem::take(&mut self.current) {
            events.push(InterfaceChange::Removed(gone));
        }
        self.current = next;
        events
    }

    /// Current snapshot.
    pub fn adapters(&self) -> impl Iterator<Item = &InterfaceInfo> {
        self.current.values()
    }
}

/// How often the adapter list is re-read without a notification.
const RESCAN_INTERVAL: Duration = Duration::from_secs(10);

/// Runs the monitor: emits an initial `Added` for every adapter, then
/// diffs after each system notification, debounced by `settle`, and at
/// least every [`RESCAN_INTERVAL`].
pub async fn run(
    sub: Subscription,
    settle: Duration,
    out: tokio::sync::mpsc::Sender<InterfaceChange>,
) -> Result<(), EnumerateError> {
    let mut differ = Differ::default();
    for e in differ.update(enumerate()?) {
        if out.send(e).await.is_err() {
            return Ok(());
        }
    }
    loop {
        // Not every change raises a notification: an unplugged USB or dock
        // NIC reports link down, then becomes "not present" silently once
        // its IP interface is gone. Rescan periodically as well.
        if tokio::time::timeout(RESCAN_INTERVAL, sub.changed())
            .await
            .is_ok()
        {
            tokio::time::sleep(settle).await;
            // Drain any notifications that arrived during the settle window.
            while let Ok(()) = tokio::time::timeout(Duration::ZERO, sub.changed()).await {}
        }
        match enumerate() {
            Ok(fresh) => {
                for e in differ.update(fresh) {
                    if out.send(e).await.is_err() {
                        return Ok(());
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
}
