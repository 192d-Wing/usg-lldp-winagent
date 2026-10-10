//! Statistics counters mirroring the 802.1AB statistics variables (9.2.6.1
//! to 9.2.6.7) and the LLDP-V2-MIB statistics group (11.5.2).
//! `lldpduLengthErrors` (9.2.6.8) is not counted.

/// Per-port counters. Names follow the LLDP MIB objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PortStats {
    /// `lldpStatsRxPortFramesTotal`: valid LLDP frames received.
    pub rx_frames_total: u64,
    /// `lldpStatsRxPortFramesDiscardedTotal`: frames discarded for any reason.
    pub rx_frames_discarded_total: u64,
    /// `lldpStatsRxPortFramesErrors`: frames with a detectable error.
    pub rx_frames_errors: u64,
    /// `lldpStatsRxPortTLVsDiscardedTotal`: TLVs discarded for any reason.
    pub rx_tlvs_discarded_total: u64,
    /// `lldpStatsRxPortTLVsUnrecognizedTotal`: TLVs of unrecognized type.
    pub rx_tlvs_unrecognized_total: u64,
    /// `lldpStatsRxPortAgeoutsTotal`: neighbors aged out by TTL expiry.
    pub rx_ageouts_total: u64,
    /// `lldpStatsTxPortFramesTotal`: LLDP frames transmitted.
    pub tx_frames_total: u64,
    /// `lldpStatsRemTablesInserts` contribution: neighbors added.
    pub rem_inserts: u64,
    /// `lldpStatsRemTablesDeletes` contribution: neighbors removed for any
    /// reason other than ageout.
    pub rem_deletes: u64,
    /// `lldpStatsRemTablesDrops` contribution: neighbors not added because
    /// the table was full.
    pub rem_drops: u64,
    /// Frames dropped before decoding because the receive queue was full.
    /// Not an IEEE counter; counted in `rx_frames_discarded_total` as well.
    pub rx_queue_overflow: u64,
}

impl PortStats {
    pub(crate) fn inc(c: &mut u64) {
        *c = c.saturating_add(1);
    }
}
