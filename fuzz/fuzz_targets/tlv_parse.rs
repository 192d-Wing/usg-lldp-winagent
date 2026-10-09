//! Walk arbitrary bytes with the TLV iterator. Must terminate and never
//! panic; after an error the iterator must yield nothing further.
#![no_main]

use libfuzzer_sys::fuzz_target;
use lldp_codec::tlv::TlvIter;

fuzz_target!(|data: &[u8]| {
    let mut it = TlvIter::new(data);
    let mut saw_err = false;
    for item in it.by_ref() {
        assert!(!saw_err, "iterator yielded after an error");
        match item {
            Ok(tlv) => assert!(tlv.value.len() <= lldp_codec::tlv::MAX_VALUE_LEN),
            Err(_) => saw_err = true,
        }
    }
});
