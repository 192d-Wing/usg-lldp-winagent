//! LLDP agent engine (IEEE 802.1AB-2016 clause 9 and 10), platform
//! independent.
//!
//! - [`timers`]: the LLDP timer parameters and their allowed ranges.
//! - [`local`]: what this system advertises.
//! - [`neighbor`]: the remote systems table for one port.
//! - [`stats`]: the 802.1AB statistics counters.
//! - [`port`]: the per-port transmit and receive state machines as a
//!   sans-IO type driven by explicit time, so it is deterministic in tests.
//! - [`packet_io`]: the trait a packet backend implements, plus a mock.
//! - [`runtime`]: a Tokio task that drives a [`port::Port`] over a
//!   [`packet_io::PacketChannel`].
//! - [`interface`]: platform-neutral interface descriptions.
//! - [`agent`]: one port task per managed interface, driven by interface
//!   changes and a policy [`agent::Resolver`].

#![forbid(unsafe_code)]

pub mod agent;
pub mod interface;
pub mod local;
pub mod neighbor;
pub mod packet_io;
pub mod port;
pub mod runtime;
pub mod stats;
pub mod timers;

pub use agent::{Agent, AgentEvent, Decision, PortHooks, Resolver};
pub use interface::{InterfaceChange, InterfaceInfo, InterfaceKind, UnicastAddress};
pub use local::{LocalPort, LocalSystem};
pub use neighbor::{Msap, Neighbor, NeighborTable};
pub use packet_io::{PacketChannel, PacketIo, PacketIoError};
pub use port::{Action, AdminStatus, Port, PortConfig, PortEvent};
pub use stats::PortStats;
pub use timers::TimerParams;
