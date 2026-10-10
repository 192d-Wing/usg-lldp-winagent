//! LLDP timer and transmission parameters. Defaults and ranges are those
//! of IEEE Std 802.1AB-2016, 9.2.5. The LLDP-V2-MIB (11.5.2) gives other
//! ranges for three of them (msgTxInterval 5 to 32768, msgTxHold 2 to 10,
//! txCreditMax 1 to 100); 11.5.2 says clause 9 takes precedence. Clause 9
//! gives no range for reinitDelay, so the MIB's is used.

use core::fmt;
use std::time::Duration;

/// The configurable LLDP parameters and their IEEE ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerParams {
    /// `msgTxInterval`: seconds between LLDPDUs in normal operation.
    /// Range 1 to 3600, default 30 (9.2.5.7).
    pub msg_tx_interval: u16,
    /// `msgTxHold`: multiplier for TTL. Range 1 to 100, default 4 (9.2.5.6).
    pub msg_tx_hold: u8,
    /// `msgFastTx`: seconds between LLDPDUs during fast transmission.
    /// Range 1 to 3600, default 1 (9.2.5.5).
    pub msg_fast_tx: u16,
    /// `txFastInit`: number of LLDPDUs sent during a fast transmission
    /// period. Range 1 to 8, default 4 (9.2.5.19).
    pub tx_fast_init: u8,
    /// `txCreditMax`: maximum number of consecutive LLDPDUs that can be
    /// transmitted at any time. Range 1 to 10, default 5 (9.2.5.17).
    pub tx_credit_max: u8,
    /// `reinitDelay`: seconds to wait after a shutdown before
    /// re-initializing transmission. Default 2 (9.2.5.10), range 1 to 10.
    pub reinit_delay: u8,
}

/// A parameter outside its IEEE range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerParamError {
    /// Parameter name as in the standard.
    pub name: &'static str,
    /// Value supplied.
    pub value: u32,
    /// Inclusive minimum.
    pub min: u32,
    /// Inclusive maximum.
    pub max: u32,
}

impl fmt::Display for TimerParamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} = {} is outside the allowed range {} to {}",
            self.name, self.value, self.min, self.max
        )
    }
}

impl std::error::Error for TimerParamError {}

impl Default for TimerParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl TimerParams {
    /// The IEEE default values.
    pub const DEFAULT: Self = Self {
        msg_tx_interval: 30,
        msg_tx_hold: 4,
        msg_fast_tx: 1,
        tx_fast_init: 4,
        tx_credit_max: 5,
        reinit_delay: 2,
    };

    /// Checks every parameter against its range.
    pub fn validate(&self) -> Result<(), TimerParamError> {
        check("msgTxInterval", u32::from(self.msg_tx_interval), 1, 3600)?;
        check("msgTxHold", u32::from(self.msg_tx_hold), 1, 100)?;
        check("msgFastTx", u32::from(self.msg_fast_tx), 1, 3600)?;
        check("txFastInit", u32::from(self.tx_fast_init), 1, 8)?;
        check("txCreditMax", u32::from(self.tx_credit_max), 1, 10)?;
        check("reinitDelay", u32::from(self.reinit_delay), 1, 10)?;
        Ok(())
    }

    /// TTL to advertise: `min(65535, msgTxInterval * msgTxHold + 1)`
    /// (9.2.5.22).
    pub fn ttl(&self) -> u16 {
        let v = u32::from(self.msg_tx_interval)
            .saturating_mul(u32::from(self.msg_tx_hold))
            .saturating_add(1);
        u16::try_from(v).unwrap_or(u16::MAX)
    }

    /// `msgTxInterval` as a duration.
    pub fn tx_interval(&self) -> Duration {
        Duration::from_secs(u64::from(self.msg_tx_interval))
    }

    /// `msgFastTx` as a duration.
    pub fn fast_tx_interval(&self) -> Duration {
        Duration::from_secs(u64::from(self.msg_fast_tx))
    }

    /// `reinitDelay` as a duration.
    pub fn reinit_delay(&self) -> Duration {
        Duration::from_secs(u64::from(self.reinit_delay))
    }
}

fn check(name: &'static str, value: u32, min: u32, max: u32) -> Result<(), TimerParamError> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(TimerParamError {
            name,
            value,
            min,
            max,
        })
    }
}
