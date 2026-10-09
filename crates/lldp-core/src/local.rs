//! What this system advertises (the "local system MIB" of 802.1AB
//! clause 10.2). Construction of these values from Windows is the job of
//! the platform crate; this module only assembles LLDPDUs from them.

use lldp_codec::{ChassisId, Lldpdu, ManagementAddress, OrgTlv, PortId, SystemCapabilities, Tlv};

/// System-wide advertisement content, identical on every port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSystem {
    /// Chassis ID. Must not change while the agent runs.
    pub chassis_id: ChassisId,
    /// System Name TLV value, if advertised.
    pub system_name: Option<Vec<u8>>,
    /// System Description TLV value, if advertised.
    pub system_description: Option<Vec<u8>>,
    /// System Capabilities TLV, if advertised.
    pub capabilities: Option<SystemCapabilities>,
    /// Organizationally specific TLVs advertised on every port.
    pub org_tlvs: Vec<OrgTlv>,
}

impl LocalSystem {
    /// A system that advertises only the mandatory chassis identity.
    pub const fn minimal(chassis_id: ChassisId) -> Self {
        Self {
            chassis_id,
            system_name: None,
            system_description: None,
            capabilities: None,
            org_tlvs: Vec::new(),
        }
    }
}

/// Per-port advertisement content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPort {
    /// Port ID.
    pub port_id: PortId,
    /// Port Description TLV value, if advertised.
    pub port_description: Option<Vec<u8>>,
    /// Management addresses to advertise on this port, in order.
    pub management_addresses: Vec<ManagementAddress>,
    /// Organizationally specific TLVs for this port only.
    pub org_tlvs: Vec<OrgTlv>,
}

impl LocalPort {
    /// A port that advertises only its identity.
    pub const fn minimal(port_id: PortId) -> Self {
        Self {
            port_id,
            port_description: None,
            management_addresses: Vec::new(),
            org_tlvs: Vec::new(),
        }
    }

    /// Builds the LLDPDU this port transmits.
    ///
    /// TLV order after the mandatory three follows the order used by most
    /// switch implementations: Port Description, System Name, System
    /// Description, System Capabilities, Management Address, then
    /// organizationally specific TLVs. 802.1AB does not mandate an order
    /// for optional TLVs.
    pub fn build_lldpdu(&self, system: &LocalSystem, ttl: u16) -> Lldpdu {
        let mut pdu = Lldpdu::new(system.chassis_id.clone(), self.port_id.clone(), ttl);
        if let Some(d) = &self.port_description {
            pdu.optional.push(Tlv::PortDescription(d.clone()));
        }
        if let Some(n) = &system.system_name {
            pdu.optional.push(Tlv::SystemName(n.clone()));
        }
        if let Some(d) = &system.system_description {
            pdu.optional.push(Tlv::SystemDescription(d.clone()));
        }
        if let Some(c) = system.capabilities {
            pdu.optional.push(Tlv::SystemCapabilities(c));
        }
        for m in &self.management_addresses {
            pdu.optional.push(Tlv::ManagementAddress(m.clone()));
        }
        for o in system.org_tlvs.iter().chain(&self.org_tlvs) {
            pdu.optional.push(Tlv::Organizational(o.clone()));
        }
        pdu
    }
}
