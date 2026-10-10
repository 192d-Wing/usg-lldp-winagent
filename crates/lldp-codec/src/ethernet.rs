//! Ethernet encapsulation of LLDPDUs (IEEE Std 802.1AB-2016 clause 7).

use core::fmt;

use crate::error::DecodeError;

/// EtherType assigned to LLDP.
pub const LLDP_ETHERTYPE: u16 = 0x88CC;

/// EtherType of an IEEE 802.1Q customer VLAN tag.
const VLAN_TAG_ETHERTYPE: u16 = 0x8100;

/// Length of an untagged Ethernet header.
const HEADER_LEN: usize = 14;

/// A 48-bit MAC address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// Returns the raw octets.
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }

    /// Reads a MAC address from the first six octets of `b`.
    pub fn from_slice(b: &[u8]) -> Option<Self> {
        let arr: [u8; 6] = b.get(..6)?.try_into().ok()?;
        Some(Self(arr))
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// The LLDP multicast destination addresses and their propagation scope
/// (IEEE Std 802.1AB-2016 7.1, Table 7-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LldpDestination {
    /// 01-80-C2-00-00-0E. Not forwarded by any bridge. The default for
    /// station-to-switch discovery.
    NearestBridge,
    /// 01-80-C2-00-00-03. Forwarded by Two-Port MAC Relays only.
    NearestNonTpmrBridge,
    /// 01-80-C2-00-00-00. Forwarded by TPMRs and provider bridges.
    NearestCustomerBridge,
}

impl LldpDestination {
    /// The multicast MAC address for this scope.
    pub const fn mac(self) -> MacAddr {
        match self {
            Self::NearestBridge => MacAddr([0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E]),
            Self::NearestNonTpmrBridge => MacAddr([0x01, 0x80, 0xC2, 0x00, 0x00, 0x03]),
            Self::NearestCustomerBridge => MacAddr([0x01, 0x80, 0xC2, 0x00, 0x00, 0x00]),
        }
    }

    /// Classifies a destination MAC, if it is one of the LLDP addresses.
    pub fn from_mac(mac: MacAddr) -> Option<Self> {
        [
            Self::NearestBridge,
            Self::NearestNonTpmrBridge,
            Self::NearestCustomerBridge,
        ]
        .into_iter()
        .find(|d| d.mac() == mac)
    }
}

/// A parsed Ethernet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthernetHeader {
    /// Destination address.
    pub dst: MacAddr,
    /// Source address.
    pub src: MacAddr,
    /// EtherType of the payload (after any VLAN tag).
    pub ethertype: u16,
    /// VLAN ID if a single 802.1Q tag was present. LLDPDUs are specified to
    /// be sent untagged, but some equipment tags them; the tag is accepted
    /// and reported.
    pub vlan_id: Option<u16>,
}

/// Splits an Ethernet frame into its header and payload.
///
/// Accepts an optional single 802.1Q tag. Does not require the EtherType to
/// be LLDP; use [`parse_lldp_frame`] for that.
pub fn parse_ethernet(frame: &[u8]) -> Result<(EthernetHeader, &[u8]), DecodeError> {
    let truncated = || DecodeError::TruncatedFrame { len: frame.len() };
    let dst = MacAddr::from_slice(frame.get(0..6).ok_or_else(truncated)?).ok_or_else(truncated)?;
    let src = MacAddr::from_slice(frame.get(6..12).ok_or_else(truncated)?).ok_or_else(truncated)?;
    let mut ethertype = read_u16(frame, 12).ok_or_else(truncated)?;
    let mut offset = HEADER_LEN;
    let mut vlan_id = None;
    if ethertype == VLAN_TAG_ETHERTYPE {
        let tci = read_u16(frame, offset).ok_or_else(truncated)?;
        vlan_id = Some(tci & 0x0FFF);
        ethertype =
            read_u16(frame, offset.checked_add(2).ok_or_else(truncated)?).ok_or_else(truncated)?;
        offset = offset.checked_add(4).ok_or_else(truncated)?;
    }
    let payload = frame.get(offset..).ok_or_else(truncated)?;
    Ok((
        EthernetHeader {
            dst,
            src,
            ethertype,
            vlan_id,
        },
        payload,
    ))
}

/// Parses an Ethernet frame and checks that it carries LLDP.
///
/// Returns the header and the LLDPDU bytes. The LLDPDU is bounded by
/// [`crate::MAX_LLDPDU_LEN`]. Trailing padding (for frames shorter than 60
/// octets) is left in place; the LLDPDU decoder stops at the End TLV.
pub fn parse_lldp_frame(frame: &[u8]) -> Result<(EthernetHeader, &[u8]), DecodeError> {
    let (header, payload) = parse_ethernet(frame)?;
    if header.ethertype != LLDP_ETHERTYPE {
        return Err(DecodeError::WrongEtherType {
            ethertype: header.ethertype,
        });
    }
    if payload.len() > crate::MAX_LLDPDU_LEN {
        return Err(DecodeError::LldpduTooLarge { len: payload.len() });
    }
    Ok((header, payload))
}

/// Writes an untagged Ethernet header followed by `lldpdu` into `out`.
pub fn write_lldp_frame(out: &mut Vec<u8>, dst: LldpDestination, src: MacAddr, lldpdu: &[u8]) {
    out.extend_from_slice(&dst.mac().0);
    out.extend_from_slice(&src.0);
    out.extend_from_slice(&LLDP_ETHERTYPE.to_be_bytes());
    out.extend_from_slice(lldpdu);
}

pub(crate) fn read_u16(b: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    let s: [u8; 2] = b.get(at..end)?.try_into().ok()?;
    Some(u16::from_be_bytes(s))
}
