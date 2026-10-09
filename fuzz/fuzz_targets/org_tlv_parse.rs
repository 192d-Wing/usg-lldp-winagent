//! Parse arbitrary bytes as an organizationally specific TLV value and run
//! the typed decoders. A typed value must re-encode, and decoding that
//! re-encoding must give the same typed value (decode is idempotent).
//! Reserved bits are not required to survive, so raw-byte equality is not
//! asserted; received TLVs are stored raw and never re-encoded anyway.
#![no_main]

use libfuzzer_sys::fuzz_target;
use lldp_codec::org::DecodedOrgTlv;
use lldp_codec::OrgTlv;

fuzz_target!(|data: &[u8]| {
    let Some(raw) = OrgTlv::parse(data) else { return };
    let typed = raw.decode();
    let again = match &typed {
        DecodedOrgTlv::Ieee8021(t) => t.to_org_tlv(),
        DecodedOrgTlv::Ieee8023(t) => Some(t.to_org_tlv()),
        DecodedOrgTlv::Med(t) => t.to_org_tlv(),
        _ => return,
    };
    let again = again.expect("a decoded TLV must re-encode");
    assert_eq!(again.oui, raw.oui);
    assert_eq!(again.subtype, raw.subtype);
    assert_eq!(again.decode(), typed, "typed decode must be idempotent");
});
