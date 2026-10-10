//! Tokio driver for a [`Port`] over a [`PacketChannel`].

use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::Instant;

use crate::local::{LocalPort, LocalSystem};
use crate::neighbor::Neighbor;
use crate::packet_io::{PacketChannel, PacketIoError};
use crate::port::{Action, AdminStatus, Port, PortEvent};
use crate::stats::PortStats;

/// Control messages for a running port task.
#[derive(Debug)]
pub enum PortCommand {
    /// Change administrative status.
    SetAdminStatus(AdminStatus),
    /// The link came up.
    LinkUp,
    /// The link went down.
    LinkDown,
    /// Replace advertised content.
    UpdateLocal(Box<(LocalSystem, LocalPort)>),
    /// Start a new fast transmission period with unchanged content.
    Readvertise,
    /// Return a snapshot of state.
    Snapshot(oneshot::Sender<PortSnapshot>),
    /// Send a shutdown LLDPDU and stop the task.
    Shutdown,
}

/// A point-in-time copy of a port's state.
#[derive(Debug, Clone)]
pub struct PortSnapshot {
    /// Neighbors.
    pub neighbors: Vec<Neighbor>,
    /// Counters.
    pub stats: PortStats,
    /// Administrative status.
    pub admin_status: AdminStatus,
    /// Link state.
    pub link_up: bool,
    /// What the port currently advertises.
    pub local_lldpdu: lldp_codec::Lldpdu,
    /// Source MAC of transmitted frames.
    pub mac: lldp_codec::MacAddr,
    /// When the snapshot was taken, for converting `Instant`s.
    pub taken_at: std::time::Instant,
}

/// Why the task ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exit {
    /// A `Shutdown` command was received.
    Shutdown,
    /// The command channel was dropped.
    CommandChannelClosed,
    /// The packet channel failed.
    ChannelError(PacketIoError),
}

/// Drives `port` until shut down.
///
/// Events are published on `events`; a lagging or absent subscriber never
/// blocks the port.
pub async fn run_port(
    mut port: Port,
    mut chan: Box<dyn PacketChannel>,
    mut cmds: mpsc::Receiver<PortCommand>,
    events: broadcast::Sender<PortEvent>,
) -> Exit {
    loop {
        let deadline = port.next_deadline().map(Instant::from_std);
        let sleep = async {
            match deadline {
                Some(d) => tokio::time::sleep_until(d).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::pin!(sleep);

        let actions = tokio::select! {
            biased;
            cmd = cmds.recv() => {
                let now = Instant::now().into_std();
                match cmd {
                    None => return Exit::CommandChannelClosed,
                    Some(PortCommand::Shutdown) => {
                        let actions = port.shutdown(now);
                        let _ = apply(&mut chan, &events, actions);
                        return Exit::Shutdown;
                    }
                    Some(PortCommand::SetAdminStatus(s)) => port.set_admin_status(s, now),
                    Some(PortCommand::LinkUp) => port.link_up(now),
                    Some(PortCommand::LinkDown) => port.link_down(now),
                    Some(PortCommand::UpdateLocal(b)) => {
                        let (system, local) = *b;
                        port.update_local(system, local, now)
                    }
                    Some(PortCommand::Readvertise) => port.readvertise(now),
                    Some(PortCommand::Snapshot(reply)) => {
                        let _ = reply.send(PortSnapshot {
                            neighbors: port.neighbors().iter().cloned().collect(),
                            stats: *port.stats(),
                            admin_status: port.admin_status(),
                            link_up: port.is_link_up(),
                            local_lldpdu: port.local_lldpdu(),
                            mac: port.mac(),
                            taken_at: now,
                        });
                        Vec::new()
                    }
                }
            }
            frame = chan.recv() => {
                let now = Instant::now().into_std();
                match frame {
                    Ok(f) => port.handle_frame(&f, now),
                    Err(e) => return Exit::ChannelError(e),
                }
            }
            () = &mut sleep => port.tick(Instant::now().into_std()),
        };
        if let Err(e) = apply(&mut chan, &events, actions) {
            return Exit::ChannelError(e);
        }
    }
}

fn apply(
    chan: &mut Box<dyn PacketChannel>,
    events: &broadcast::Sender<PortEvent>,
    actions: Vec<Action>,
) -> Result<(), PacketIoError> {
    for a in actions {
        match a {
            Action::Transmit(frame) => chan.send(&frame)?,
            Action::Event(e) => {
                let _ = events.send(e);
            }
        }
    }
    Ok(())
}
