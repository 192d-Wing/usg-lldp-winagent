//! The packet backend abstraction and a mock for tests.
//!
//! Adapter enumeration is deliberately not part of this trait: the
//! platform crate discovers interfaces through its own APIs and asks the
//! backend to open a channel by adapter identifier.

use core::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use lldp_codec::MacAddr;
use tokio::sync::mpsc;

/// Backend-independent adapter identifier (on Windows, the adapter GUID
/// string without braces).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AdapterId(pub String);

/// Packet backend errors.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PacketIoError {
    /// The backend library or driver is not available.
    BackendUnavailable(String),
    /// The adapter could not be opened.
    OpenFailed {
        /// Adapter.
        adapter: AdapterId,
        /// Reason.
        reason: String,
    },
    /// A send failed.
    SendFailed(String),
    /// The channel was closed (adapter removed or backend shut down).
    Closed,
}

impl fmt::Display for PacketIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendUnavailable(r) => write!(f, "packet backend unavailable: {r}"),
            Self::OpenFailed { adapter, reason } => {
                write!(f, "cannot open adapter {}: {reason}", adapter.0)
            }
            Self::SendFailed(r) => write!(f, "send failed: {r}"),
            Self::Closed => write!(f, "packet channel closed"),
        }
    }
}

impl std::error::Error for PacketIoError {}

/// Boxed future returned by [`PacketChannel::recv`].
pub type RecvFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>, PacketIoError>> + Send + 'a>>;

/// A packet backend that can open channels on adapters.
pub trait PacketIo: Send + Sync {
    /// Opens a channel on `adapter` filtered to LLDP frames.
    fn open(&self, adapter: &AdapterId) -> Result<Box<dyn PacketChannel>, PacketIoError>;
}

/// An open send/receive channel on one adapter.
pub trait PacketChannel: Send {
    /// The adapter's MAC address, used as the frame source.
    fn mac(&self) -> MacAddr;
    /// Sends one complete Ethernet frame.
    fn send(&mut self, frame: &[u8]) -> Result<(), PacketIoError>;
    /// Receives one complete Ethernet frame with EtherType 0x88CC. The
    /// backend applies the EtherType filter; the caller validates the rest.
    fn recv(&mut self) -> RecvFuture<'_>;
}

/// Shared state of a mock channel, for tests.
#[derive(Debug, Default)]
pub struct MockState {
    /// Frames the port sent, oldest first.
    pub sent: Vec<Vec<u8>>,
}

/// A mock channel: frames pushed with [`MockHandle::inject`] are received,
/// frames sent are recorded.
pub struct MockChannel {
    mac: MacAddr,
    rx: mpsc::Receiver<Vec<u8>>,
    state: Arc<Mutex<MockState>>,
}

/// Test-side handle to a [`MockChannel`].
#[derive(Clone)]
pub struct MockHandle {
    tx: mpsc::Sender<Vec<u8>>,
    state: Arc<Mutex<MockState>>,
}

impl MockHandle {
    /// Queues a frame for the port to receive.
    pub async fn inject(&self, frame: Vec<u8>) {
        let _ = self.tx.send(frame).await;
    }

    /// Takes all frames sent so far.
    pub fn take_sent(&self) -> Vec<Vec<u8>> {
        self.state
            .lock()
            .map(|mut s| std::mem::take(&mut s.sent))
            .unwrap_or_default()
    }

    /// Number of frames sent so far.
    pub fn sent_count(&self) -> usize {
        self.state.lock().map_or(0, |s| s.sent.len())
    }
}

impl MockChannel {
    /// Creates a mock channel and its handle.
    pub fn new(mac: MacAddr) -> (Self, MockHandle) {
        let (tx, rx) = mpsc::channel(64);
        let state = Arc::new(Mutex::new(MockState::default()));
        (
            Self {
                mac,
                rx,
                state: Arc::clone(&state),
            },
            MockHandle { tx, state },
        )
    }
}

impl PacketChannel for MockChannel {
    fn mac(&self) -> MacAddr {
        self.mac
    }

    fn send(&mut self, frame: &[u8]) -> Result<(), PacketIoError> {
        self.state
            .lock()
            .map(|mut s| s.sent.push(frame.to_vec()))
            .map_err(|_| PacketIoError::SendFailed("mock poisoned".into()))
    }

    fn recv(&mut self) -> RecvFuture<'_> {
        Box::pin(async move { self.rx.recv().await.ok_or(PacketIoError::Closed) })
    }
}
