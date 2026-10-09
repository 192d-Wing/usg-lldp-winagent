//! Parse arbitrary bytes as an Ethernet frame carrying LLDP and decode
//! the payload. Never panics.
#![no_main]

use libfuzzer_sys::fuzz_target;
use lldp_codec::ethernet::parse_lldp_frame;
use lldp_codec::Lldpdu;

fuzz_target!(|data: &[u8]| {
    if let Ok((_hdr, pdu)) = parse_lldp_frame(data) {
        let _ = Lldpdu::decode(pdu);
    }
});
