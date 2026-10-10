//! The per-port LLDP agent: transmit state machine, transmit timer and
//! credit machine, and receive state machine (IEEE 802.1AB-2016 clause
//! 9.2.7 through 9.2.10, `verify`).
//!
//! `Port` performs no I/O and reads no clock. Every entry point takes
//! `now` and returns the [`Action`]s the caller must carry out, so the
//! machine is deterministic and testable without a runtime.

use std::time::{Duration, Instant};

use lldp_codec::ethernet::{parse_lldp_frame, write_lldp_frame};
use lldp_codec::{DecodeError, LldpDestination, Lldpdu, MacAddr};

use crate::local::{LocalPort, LocalSystem};
use crate::neighbor::{Insert, Msap, Neighbor, NeighborTable};
use crate::stats::PortStats;
use crate::timers::TimerParams;

/// `adminStatus` (802.1AB 9.2.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdminStatus {
    /// `disabled`: neither transmit nor receive.
    Disabled,
    /// `enabledRxOnly`.
    RxOnly,
    /// `enabledTxOnly`.
    TxOnly,
    /// `enabledRxTx`.
    RxTx,
}

impl AdminStatus {
    /// Whether transmission is administratively enabled.
    pub const fn tx(self) -> bool {
        matches!(self, Self::TxOnly | Self::RxTx)
    }

    /// Whether reception is administratively enabled.
    pub const fn rx(self) -> bool {
        matches!(self, Self::RxOnly | Self::RxTx)
    }
}

/// Static per-port settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortConfig {
    /// Initial administrative status.
    pub admin_status: AdminStatus,
    /// Destination address scope for transmitted LLDPDUs.
    pub destination: LldpDestination,
    /// Maximum neighbors held for this port.
    pub max_neighbors: usize,
    /// Maximum LLDPDU size to transmit (1500 for standard frames).
    pub max_lldpdu_len: usize,
}

impl Default for PortConfig {
    fn default() -> Self {
        Self {
            admin_status: AdminStatus::RxTx,
            destination: LldpDestination::NearestBridge,
            max_neighbors: 8,
            max_lldpdu_len: 1500,
        }
    }
}

/// Why a neighbor was removed other than by TTL expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveReason {
    /// The neighbor sent an LLDPDU with TTL 0.
    ShutdownReceived,
    /// The local link went down.
    LinkDown,
    /// Reception was administratively disabled.
    AdminDisabled,
    /// The agent is shutting down.
    AgentShutdown,
}

/// Something the port observed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PortEvent {
    /// A new neighbor appeared.
    NeighborAdded(Neighbor),
    /// A known neighbor's advertised content changed.
    NeighborUpdated(Neighbor),
    /// A neighbor's TTL expired.
    NeighborExpired(Neighbor),
    /// A neighbor was removed for a reason other than expiry.
    NeighborRemoved {
        /// The neighbor.
        neighbor: Neighbor,
        /// Why.
        reason: RemoveReason,
    },
    /// A frame for a new neighbor was dropped because the table is full.
    TooManyNeighbors {
        /// Identity of the dropped neighbor.
        msap: Msap,
    },
    /// A received frame was discarded.
    FrameDiscarded(DecodeError),
    /// An LLDPDU could not be built for transmission.
    TransmitError(String),
}

/// Something the caller must do.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // events carry a full neighbor; actions are short-lived
pub enum Action {
    /// Send this complete Ethernet frame.
    Transmit(Vec<u8>),
    /// Report this event.
    Event(PortEvent),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxState {
    /// Not transmitting (link down, admin off, or never started).
    Off,
    /// Transmitting normally.
    Running,
    /// A shutdown LLDPDU was sent; wait for `reinitDelay` before starting.
    ReinitWait(Instant),
}

/// The per-port agent.
#[derive(Debug)]
pub struct Port {
    cfg: PortConfig,
    timers: TimerParams,
    system: LocalSystem,
    local: LocalPort,
    mac: MacAddr,
    link_up: bool,
    tx_state: TxState,
    /// `txTTR`: when the next scheduled transmission is due.
    tx_ttr: Option<Instant>,
    /// `txFast`: remaining fast transmissions.
    tx_fast: u8,
    /// `txCredit`.
    tx_credit: u8,
    /// When `txCredit` next increments.
    credit_tick: Instant,
    /// `txNow`: a transmission is requested.
    tx_now: bool,
    /// When the last LLDPDU (other than a shutdown) was sent.
    last_tx: Option<Instant>,
    neighbors: NeighborTable,
    stats: PortStats,
}

impl Port {
    /// Creates a port with the link down. Call [`Port::link_up`] to start.
    pub fn new(
        cfg: PortConfig,
        timers: TimerParams,
        system: LocalSystem,
        local: LocalPort,
        mac: MacAddr,
        now: Instant,
    ) -> Self {
        let neighbors = NeighborTable::new(cfg.max_neighbors);
        Self {
            cfg,
            timers,
            system,
            local,
            mac,
            link_up: false,
            tx_state: TxState::Off,
            tx_ttr: None,
            tx_fast: 0,
            tx_credit: timers.tx_credit_max,
            credit_tick: now,
            tx_now: false,
            last_tx: None,
            neighbors,
            stats: PortStats::default(),
        }
    }

    /// Current neighbors.
    pub const fn neighbors(&self) -> &NeighborTable {
        &self.neighbors
    }

    /// Current statistics.
    pub const fn stats(&self) -> &PortStats {
        &self.stats
    }

    /// Current administrative status.
    pub const fn admin_status(&self) -> AdminStatus {
        self.cfg.admin_status
    }

    /// Whether the link is up.
    pub const fn is_link_up(&self) -> bool {
        self.link_up
    }

    /// The MAC used as frame source.
    pub const fn mac(&self) -> MacAddr {
        self.mac
    }

    /// Timer parameters in effect.
    pub const fn timers(&self) -> &TimerParams {
        &self.timers
    }

    /// What this port currently advertises.
    pub fn local_lldpdu(&self) -> Lldpdu {
        self.local.build_lldpdu(&self.system, self.timers.ttl())
    }

    fn tx_wanted(&self) -> bool {
        self.link_up && self.cfg.admin_status.tx()
    }

    fn rx_enabled(&self) -> bool {
        self.link_up && self.cfg.admin_status.rx()
    }

    /// `txInitializeLLDP` plus the start of a fast transmission period.
    fn tx_initialize(&mut self, now: Instant) {
        self.tx_state = TxState::Running;
        self.tx_fast = self.timers.tx_fast_init;
        self.tx_credit = self.timers.tx_credit_max;
        self.credit_tick = now.checked_add(Duration::from_secs(1)).unwrap_or(now);
        self.tx_ttr = None;
        self.tx_now = true;
    }

    /// The link came up.
    pub fn link_up(&mut self, now: Instant) -> Vec<Action> {
        let mut actions = Vec::new();
        if self.link_up {
            return actions;
        }
        self.link_up = true;
        if self.tx_wanted() {
            match self.tx_state {
                TxState::ReinitWait(until) if until > now => {}
                _ => self.tx_initialize(now),
            }
        }
        actions.extend(self.tick(now));
        actions
    }

    /// The link went down. Neighbors are dropped (`rxInitializeLLDP` on
    /// the next link up would do so anyway) and transmission stops. No
    /// shutdown LLDPDU can be sent on a down link.
    pub fn link_down(&mut self, _now: Instant) -> Vec<Action> {
        if !self.link_up {
            return Vec::new();
        }
        self.link_up = false;
        self.tx_state = TxState::Off;
        self.tx_ttr = None;
        self.tx_now = false;
        self.remove_all(RemoveReason::LinkDown)
    }

    /// Changes the administrative status.
    pub fn set_admin_status(&mut self, status: AdminStatus, now: Instant) -> Vec<Action> {
        let mut actions = Vec::new();
        let was_tx = self.tx_wanted();
        let was_rx = self.rx_enabled();
        self.cfg.admin_status = status;
        if was_tx && !self.tx_wanted() {
            actions.extend(self.tx_shutdown(now));
        } else if !was_tx && self.tx_wanted() {
            match self.tx_state {
                TxState::ReinitWait(until) if until > now => {}
                _ => self.tx_initialize(now),
            }
        }
        if was_rx && !self.rx_enabled() {
            actions.extend(self.remove_all(RemoveReason::AdminDisabled));
        }
        actions.extend(self.tick(now));
        actions
    }

    /// Replaces the advertised content (`localChange`).
    pub fn update_local(
        &mut self,
        system: LocalSystem,
        local: LocalPort,
        now: Instant,
    ) -> Vec<Action> {
        let changed = self.system != system || self.local != local;
        self.system = system;
        self.local = local;
        if changed {
            self.local_change(now)
        } else {
            Vec::new()
        }
    }

    /// Signals that locally advertised information changed and an LLDPDU
    /// should be sent as soon as credit allows.
    pub fn local_change(&mut self, now: Instant) -> Vec<Action> {
        if self.tx_state == TxState::Running {
            self.tx_now = true;
        }
        self.tick(now)
    }

    /// Starts a new fast transmission period with unchanged content, for
    /// when the neighbor may have lost our entry: resume from sleep, or
    /// another local agent sent a shutdown LLDPDU carrying our identity.
    pub fn readvertise(&mut self, now: Instant) -> Vec<Action> {
        if self.tx_state == TxState::Running {
            self.tx_fast = self.timers.tx_fast_init;
            // Keep msgFastTx spacing from a frame that has only just gone
            // out, rather than sending the same LLDPDU twice in a row.
            let spaced = self
                .last_tx
                .and_then(|t| t.checked_add(self.timers.fast_tx_interval()))
                .filter(|next| *next > now);
            match spaced {
                Some(next) => self.tx_ttr = Some(next),
                None => self.tx_now = true,
            }
        }
        self.tick(now)
    }

    /// Stops the port for agent shutdown: sends a shutdown LLDPDU if
    /// transmitting and drops all neighbors.
    pub fn shutdown(&mut self, now: Instant) -> Vec<Action> {
        let mut actions = self.tx_shutdown(now);
        self.tx_state = TxState::Off;
        actions.extend(self.remove_all(RemoveReason::AgentShutdown));
        actions
    }

    /// `txShutdownFrame`: send TTL 0 with mandatory TLVs only, then wait
    /// `reinitDelay` before any further transmission.
    fn tx_shutdown(&mut self, now: Instant) -> Vec<Action> {
        let mut actions = Vec::new();
        if self.tx_state == TxState::Running && self.link_up {
            let pdu = Lldpdu::new(
                self.system.chassis_id.clone(),
                self.local.port_id.clone(),
                0,
            );
            match self.frame_for(&pdu) {
                Ok(frame) => {
                    PortStats::inc(&mut self.stats.tx_frames_total);
                    actions.push(Action::Transmit(frame));
                }
                Err(e) => actions.push(Action::Event(PortEvent::TransmitError(e))),
            }
        }
        if self.tx_state == TxState::Running {
            self.tx_state =
                TxState::ReinitWait(now.checked_add(self.timers.reinit_delay()).unwrap_or(now));
        }
        self.tx_ttr = None;
        self.tx_now = false;
        actions
    }

    fn remove_all(&mut self, reason: RemoveReason) -> Vec<Action> {
        self.neighbors
            .clear()
            .into_iter()
            .map(|neighbor| {
                PortStats::inc(&mut self.stats.rem_deletes);
                Action::Event(PortEvent::NeighborRemoved { neighbor, reason })
            })
            .collect()
    }

    fn frame_for(&self, pdu: &Lldpdu) -> Result<Vec<u8>, String> {
        let bytes = pdu
            .encode(self.cfg.max_lldpdu_len)
            .map_err(|e| e.to_string())?;
        let mut frame = Vec::with_capacity(bytes.len().saturating_add(14));
        write_lldp_frame(&mut frame, self.cfg.destination, self.mac, &bytes);
        Ok(frame)
    }

    /// Processes a received Ethernet frame.
    pub fn handle_frame(&mut self, frame: &[u8], now: Instant) -> Vec<Action> {
        let mut actions = Vec::new();
        if !self.rx_enabled() {
            return actions;
        }
        let (header, pdu) = match parse_lldp_frame(frame) {
            Ok(x) => x,
            Err(e) => {
                self.count_frame_error();
                actions.push(Action::Event(PortEvent::FrameDiscarded(e)));
                return actions;
            }
        };
        if header.src == self.mac {
            // Our own transmission echoed back by the capture backend.
            return actions;
        }
        let Some(scope) = LldpDestination::from_mac(header.dst) else {
            PortStats::inc(&mut self.stats.rx_frames_discarded_total);
            return actions;
        };
        let decoded = match Lldpdu::decode(pdu) {
            Ok(d) => d,
            Err(e) => {
                self.count_frame_error();
                actions.push(Action::Event(PortEvent::FrameDiscarded(e)));
                return actions;
            }
        };
        PortStats::inc(&mut self.stats.rx_frames_total);
        self.stats.rx_tlvs_discarded_total = self
            .stats
            .rx_tlvs_discarded_total
            .saturating_add(u64::from(decoded.report.tlvs_discarded));
        self.stats.rx_tlvs_unrecognized_total = self
            .stats
            .rx_tlvs_unrecognized_total
            .saturating_add(u64::from(decoded.report.tlvs_unrecognized));

        let lldpdu = decoded.lldpdu;
        let msap = Msap {
            scope,
            chassis_id: lldpdu.chassis_id.clone(),
            port_id: lldpdu.port_id.clone(),
        };

        if lldpdu.ttl == 0 {
            if let Some(neighbor) = self.neighbors.remove(&msap) {
                PortStats::inc(&mut self.stats.rem_deletes);
                actions.push(Action::Event(PortEvent::NeighborRemoved {
                    neighbor,
                    reason: RemoveReason::ShutdownReceived,
                }));
            }
            return actions;
        }

        match self.neighbors.upsert(msap.clone(), header.src, lldpdu, now) {
            Insert::Added => {
                PortStats::inc(&mut self.stats.rem_inserts);
                if let Some(n) = self.neighbors.get(&msap) {
                    actions.push(Action::Event(PortEvent::NeighborAdded(n.clone())));
                }
                // A new neighbor starts a fast transmission period so it
                // learns about us promptly.
                if self.tx_state == TxState::Running {
                    self.tx_fast = self.timers.tx_fast_init;
                    self.tx_now = true;
                }
            }
            Insert::Updated => {
                if let Some(n) = self.neighbors.get(&msap) {
                    actions.push(Action::Event(PortEvent::NeighborUpdated(n.clone())));
                }
            }
            Insert::Refreshed => {}
            Insert::Dropped => {
                PortStats::inc(&mut self.stats.rem_drops);
                PortStats::inc(&mut self.stats.rx_frames_discarded_total);
                actions.push(Action::Event(PortEvent::TooManyNeighbors { msap }));
            }
        }
        actions.extend(self.tick(now));
        actions
    }

    /// Records that a frame arrived but was dropped before decoding because
    /// the receive queue overflowed.
    pub fn note_queue_overflow(&mut self) {
        PortStats::inc(&mut self.stats.rx_queue_overflow);
        PortStats::inc(&mut self.stats.rx_frames_discarded_total);
    }

    fn count_frame_error(&mut self) {
        PortStats::inc(&mut self.stats.rx_frames_discarded_total);
        PortStats::inc(&mut self.stats.rx_frames_errors);
    }

    /// Advances timers to `now`: expires neighbors, refills credit, and
    /// transmits if due.
    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        let mut actions = Vec::new();

        for neighbor in self.neighbors.expire(now) {
            PortStats::inc(&mut self.stats.rx_ageouts_total);
            actions.push(Action::Event(PortEvent::NeighborExpired(neighbor)));
        }

        if let TxState::ReinitWait(until) = self.tx_state
            && until <= now
        {
            if self.tx_wanted() {
                self.tx_initialize(now);
            } else {
                self.tx_state = TxState::Off;
            }
        }

        if self.tx_state != TxState::Running {
            return actions;
        }

        // txCredit increments once per second up to txCreditMax.
        while self.credit_tick <= now {
            self.tx_credit = self
                .tx_credit
                .saturating_add(1)
                .min(self.timers.tx_credit_max);
            self.credit_tick = self
                .credit_tick
                .checked_add(Duration::from_secs(1))
                .unwrap_or(now);
        }

        if self.tx_ttr.is_some_and(|t| t <= now) {
            self.tx_now = true;
        }

        if self.tx_now && self.tx_credit > 0 {
            let pdu = self.local_lldpdu();
            match self.frame_for(&pdu) {
                Ok(frame) => {
                    PortStats::inc(&mut self.stats.tx_frames_total);
                    actions.push(Action::Transmit(frame));
                }
                Err(e) => actions.push(Action::Event(PortEvent::TransmitError(e))),
            }
            self.tx_credit = self.tx_credit.saturating_sub(1);
            self.tx_now = false;
            self.last_tx = Some(now);
            // txFast counts LLDPDUs sent in the fast period: this frame
            // consumed one, and the interval to the next frame is fast only
            // while more remain (`verify` against 9.2.5 / 9.2.10).
            self.tx_fast = self.tx_fast.saturating_sub(1);
            let interval = if self.tx_fast > 0 {
                self.timers.fast_tx_interval()
            } else {
                self.timers.tx_interval()
            };
            self.tx_ttr = now.checked_add(interval);
        }

        actions
    }

    /// When [`Port::tick`] next needs to run, if anything is pending.
    pub fn next_deadline(&self) -> Option<Instant> {
        let mut deadline = self.neighbors.next_expiry();
        let mut consider = |t: Instant| deadline = Some(deadline.map_or(t, |d| d.min(t)));
        match self.tx_state {
            TxState::ReinitWait(until) => consider(until),
            TxState::Running => {
                if let Some(t) = self.tx_ttr {
                    consider(t);
                }
                if self.tx_now && self.tx_credit == 0 {
                    consider(self.credit_tick);
                }
            }
            TxState::Off => {}
        }
        deadline
    }
}
