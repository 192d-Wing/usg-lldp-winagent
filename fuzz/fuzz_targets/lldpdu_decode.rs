//! Decode arbitrary bytes as an LLDPDU. If decoding succeeds, re-encode
//! and decode again: the second decode must equal the first (round-trip
//! property), and nothing may panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use lldp_codec::Lldpdu;

fuzz_target!(|data: &[u8]| {
    let Ok(first) = Lldpdu::decode(data) else { return };
    for org in first.lldpdu.organizational() {
        let _ = org.decode();
    }
    let bytes = first.lldpdu.encode(lldp_codec::MAX_LLDPDU_LEN).expect("decoded LLDPDU must re-encode");
    let second = Lldpdu::decode(&bytes).expect("re-encoded LLDPDU must decode");
    assert_eq!(first.lldpdu, second.lldpdu);
});
