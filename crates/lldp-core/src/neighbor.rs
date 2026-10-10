//! The remote systems table for one port (802.1AB-2016 9.2.7.5, 9.2.7.7.4,
//! 9.2.7.7.5).

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use lldp_codec::{ChassisId, LldpDestination, Lldpdu, MacAddr, PortId};

/// MAC Service Access Point identifier: what makes a neighbor unique.
///
/// 802.1AB identifies a remote system by the combination of Chassis ID and
/// Port ID. The destination address scope is included so that the same
/// device reached through different propagation scopes is tracked as
/// separate entries, as the standard keeps separate agents per scope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Msap {
    /// Destination address scope the LLDPDU arrived on.
    pub scope: LldpDestination,
    /// Remote Chassis ID.
    pub chassis_id: ChassisId,
    /// Remote Port ID.
    pub port_id: PortId,
}

/// One remote system as last heard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbor {
    /// Identity.
    pub msap: Msap,
    /// Source MAC of the last frame.
    pub source_mac: MacAddr,
    /// The last decoded LLDPDU, in full.
    pub lldpdu: Lldpdu,
    /// TTL advertised in the last LLDPDU.
    pub ttl: u16,
    /// When this neighbor was first seen.
    pub first_seen: Instant,
    /// When the last LLDPDU arrived.
    pub last_seen: Instant,
    /// When the entry expires if no further LLDPDU arrives.
    pub expires_at: Instant,
    /// Number of LLDPDUs received for this neighbor, saturating.
    pub frames: u64,
}

impl Neighbor {
    /// Seconds until expiry, zero if already expired.
    pub fn remaining_ttl(&self, now: Instant) -> Duration {
        self.expires_at.saturating_duration_since(now)
    }
}

/// Outcome of offering an LLDPDU to the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Insert {
    /// A new neighbor was added.
    Added,
    /// An existing neighbor's content changed.
    Updated,
    /// An existing neighbor was refreshed with identical content.
    Refreshed,
    /// The table is full; the LLDPDU was dropped (802.1AB "too many
    /// neighbors").
    Dropped,
}

/// Bounded table of neighbors keyed by MSAP.
#[derive(Debug, Clone)]
pub struct NeighborTable {
    entries: BTreeMap<Msap, Neighbor>,
    capacity: usize,
}

impl NeighborTable {
    /// Creates an empty table holding at most `capacity` neighbors.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity: capacity.max(1),
        }
    }

    /// Maximum number of neighbors.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of neighbors.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Looks up a neighbor.
    pub fn get(&self, msap: &Msap) -> Option<&Neighbor> {
        self.entries.get(msap)
    }

    /// All neighbors in MSAP order.
    pub fn iter(&self) -> impl Iterator<Item = &Neighbor> {
        self.entries.values()
    }

    /// Records an LLDPDU with a nonzero TTL.
    pub fn upsert(
        &mut self,
        msap: Msap,
        source_mac: MacAddr,
        lldpdu: Lldpdu,
        now: Instant,
    ) -> Insert {
        let ttl = lldpdu.ttl;
        let expires_at = now
            .checked_add(Duration::from_secs(u64::from(ttl)))
            .unwrap_or(now);
        if let Some(existing) = self.entries.get_mut(&msap) {
            let changed = existing.lldpdu != lldpdu || existing.source_mac != source_mac;
            existing.lldpdu = lldpdu;
            existing.source_mac = source_mac;
            existing.ttl = ttl;
            existing.last_seen = now;
            existing.expires_at = expires_at;
            existing.frames = existing.frames.saturating_add(1);
            return if changed {
                Insert::Updated
            } else {
                Insert::Refreshed
            };
        }
        if self.entries.len() >= self.capacity {
            return Insert::Dropped;
        }
        self.entries.insert(
            msap.clone(),
            Neighbor {
                msap,
                source_mac,
                lldpdu,
                ttl,
                first_seen: now,
                last_seen: now,
                expires_at,
                frames: 1,
            },
        );
        Insert::Added
    }

    /// Removes a neighbor, returning it.
    pub fn remove(&mut self, msap: &Msap) -> Option<Neighbor> {
        self.entries.remove(msap)
    }

    /// Removes and returns every neighbor whose TTL has expired.
    pub fn expire(&mut self, now: Instant) -> Vec<Neighbor> {
        let expired: Vec<Msap> = self
            .entries
            .values()
            .filter(|n| n.expires_at <= now)
            .map(|n| n.msap.clone())
            .collect();
        expired
            .iter()
            .filter_map(|m| self.entries.remove(m))
            .collect()
    }

    /// Removes and returns every neighbor.
    pub fn clear(&mut self) -> Vec<Neighbor> {
        std::mem::take(&mut self.entries).into_values().collect()
    }

    /// The earliest expiry among current neighbors.
    pub fn next_expiry(&self) -> Option<Instant> {
        self.entries.values().map(|n| n.expires_at).min()
    }
}
