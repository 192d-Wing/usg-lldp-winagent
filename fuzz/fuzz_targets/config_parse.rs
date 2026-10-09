//! Parse arbitrary text as a configuration file. Never panics; a valid
//! configuration must survive a YAML round trip unchanged.
#![no_main]

use libfuzzer_sys::fuzz_target;
use lldp_config::Config;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(cfg) = Config::from_yaml(text) {
        let again = cfg.to_yaml().expect("valid config must serialize");
        assert_eq!(Config::from_yaml(&again).expect("serialized config must parse"), cfg);
    }
});
