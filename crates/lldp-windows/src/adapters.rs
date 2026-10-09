//! Network adapter discovery through IP Helper (`GetIfTable2` and
//! `GetAdaptersAddresses`), joined on interface LUID.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use lldp_codec::MacAddr;
use lldp_core::{InterfaceInfo, InterfaceKind, UnicastAddress};
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    GetAdaptersAddresses, GetIfTable2, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211,
    IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_UNICAST_ADDRESS_LH, MIB_IF_TABLE2,
};
use windows::Win32::NetworkManagement::Ndis::{
    MediaConnectStateConnected, NdisPhysicalMedium802_3,
};
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IpDadStatePreferred, IpSuffixOriginRandom, SOCKADDR_IN,
    SOCKADDR_IN6,
};

use crate::util::{guid_string, wide_to_string};

/// Errors from adapter enumeration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumerateError(pub String);

impl std::fmt::Display for EnumerateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "adapter enumeration failed: {}", self.0)
    }
}

impl std::error::Error for EnumerateError {}

/// Enumerates every interface Windows knows about, including loopback and
/// tunnels; the caller filters by `kind`.
#[allow(unsafe_code)]
pub fn enumerate() -> Result<Vec<InterfaceInfo>, EnumerateError> {
    let mut adapters = Vec::new();
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: GetIfTable2 allocates the table and stores its pointer in
    // `table`; it is freed with FreeMibTable below on every path.
    let rc = unsafe { GetIfTable2(&raw mut table) };
    if rc.is_err() || table.is_null() {
        return Err(EnumerateError(format!("GetIfTable2 returned {}", rc.0)));
    }
    // SAFETY: `table` is a valid table for the duration of this block, and
    // `NumEntries` rows follow the header as documented.
    unsafe {
        let count = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
        for row in rows {
            let flags = row.InterfaceAndOperStatusFlags._bitfield;
            let hardware = flags & 0x01 != 0;
            let connector = flags & 0x04 != 0;
            let kind = if row.Type == IF_TYPE_IEEE80211 {
                InterfaceKind::Wifi
            } else if row.Type == IF_TYPE_ETHERNET_CSMACD {
                if hardware && connector && row.PhysicalMediumType == NdisPhysicalMedium802_3 {
                    InterfaceKind::PhysicalEthernet
                } else {
                    InterfaceKind::Virtual
                }
            } else {
                InterfaceKind::Other
            };
            let mac = (row.PhysicalAddressLength == 6)
                .then(|| MacAddr::from_slice(&row.PhysicalAddress))
                .flatten();
            adapters.push(InterfaceInfo {
                guid: guid_string(&row.InterfaceGuid),
                luid: row.InterfaceLuid.Value,
                if_index: row.InterfaceIndex,
                alias: wide_to_string(&row.Alias),
                description: wide_to_string(&row.Description),
                mac,
                connected: row.MediaConnectState == MediaConnectStateConnected,
                link_speed: row.TransmitLinkSpeed,
                kind,
                addresses: Vec::new(),
            });
        }
        FreeMibTable(table.cast());
    }
    attach_addresses(&mut adapters)?;
    Ok(adapters)
}

#[allow(unsafe_code)]
fn attach_addresses(adapters: &mut [InterfaceInfo]) -> Result<(), EnumerateError> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u8> = Vec::new();
    for _ in 0..4 {
        buf.resize(size as usize, 0);
        // SAFETY: `buf` has `size` bytes and GetAdaptersAddresses writes a
        // linked list within it, updating `size` on overflow.
        let rc = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC.0),
                flags,
                None,
                Some(buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>()),
                &raw mut size,
            )
        };
        match rc {
            0 => break,
            111 => {} // ERROR_BUFFER_OVERFLOW: size now holds the needed length
            other => {
                return Err(EnumerateError(format!(
                    "GetAdaptersAddresses returned {other}"
                )));
            }
        }
    }
    let mut node = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    // SAFETY: the list lives inside `buf`, which outlives the walk; each
    // Next pointer either points into `buf` or is null, per the API.
    unsafe {
        while !node.is_null() {
            let a = &*node;
            if let Some(ad) = adapters.iter_mut().find(|ad| ad.luid == a.Luid.Value) {
                let mut u = a.FirstUnicastAddress;
                while !u.is_null() {
                    if let Some(addr) = unicast(&*u) {
                        ad.addresses.push(addr);
                    }
                    u = (*u).Next;
                }
            }
            node = a.Next;
        }
    }
    Ok(())
}

#[allow(unsafe_code, clippy::cast_ptr_alignment)] // SOCKADDR buffers from IP Helper are suitably aligned
unsafe fn unicast(u: &IP_ADAPTER_UNICAST_ADDRESS_LH) -> Option<UnicastAddress> {
    let sa = u.Address.lpSockaddr;
    if sa.is_null() {
        return None;
    }
    // SAFETY: lpSockaddr points to a SOCKADDR of at least iSockaddrLength
    // bytes whose family selects the concrete layout.
    let addr = unsafe {
        match (*sa).sa_family {
            AF_INET => {
                let v4 = &*sa.cast::<SOCKADDR_IN>();
                IpAddr::V4(Ipv4Addr::from(u32::from_be(v4.sin_addr.S_un.S_addr)))
            }
            AF_INET6 => {
                let v6 = &*sa.cast::<SOCKADDR_IN6>();
                IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.u.Byte))
            }
            _ => return None,
        }
    };
    Some(UnicastAddress {
        addr,
        temporary: u.SuffixOrigin == IpSuffixOriginRandom,
        preferred: u.DadState == IpDadStatePreferred,
        prefix_len: u.OnLinkPrefixLength,
    })
}
