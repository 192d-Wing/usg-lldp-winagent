//! WinLLDP configuration: schema version 1.
//!
//! The YAML file is the source of truth. A small set of registry policy
//! values (read by the platform crate) can override it through
//! [`PolicyOverrides`]; policy always wins.

#![forbid(unsafe_code)]

mod glob;
pub mod schema;

use core::fmt;

pub use schema::*;

/// Why a configuration was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The YAML could not be parsed or does not match the schema.
    Parse(String),
    /// The schema version is not supported.
    UnsupportedVersion {
        /// Version found.
        found: u32,
        /// Version this build supports.
        supported: u32,
    },
    /// One or more values are invalid.
    Invalid(Vec<Violation>),
}

/// One invalid value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Dotted path to the setting, for example `lldp.transmit_interval`.
    pub path: String,
    /// What is wrong and what is allowed.
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(m) => write!(f, "configuration parse error: {m}"),
            Self::UnsupportedVersion { found, supported } => {
                write!(
                    f,
                    "configuration version {found} is not supported; this build supports version {supported}"
                )
            }
            Self::Invalid(v) => {
                writeln!(f, "configuration has {} invalid value(s):", v.len())?;
                for x in v {
                    writeln!(f, "  {}: {}", x.path, x.message)?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Schema version this build reads and writes.
pub const SCHEMA_VERSION: u32 = 1;

impl Config {
    /// Parses and validates YAML text.
    pub fn from_yaml(text: &str) -> Result<Self, ConfigError> {
        let cfg: Self =
            serde_yaml_ng::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        if cfg.version != SCHEMA_VERSION {
            return Err(ConfigError::UnsupportedVersion {
                found: cfg.version,
                supported: SCHEMA_VERSION,
            });
        }
        cfg.validate()?;
        Ok(cfg)
    }

    /// Serializes to YAML.
    pub fn to_yaml(&self) -> Result<String, ConfigError> {
        serde_yaml_ng::to_string(self).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Checks every value against its allowed range.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut v = Vec::new();
        let timers = self.lldp.timer_params();
        if let Err(e) = timers.validate() {
            let path = match e.name {
                "msgTxInterval" => "lldp.transmit_interval",
                "msgTxHold" => "lldp.hold_multiplier",
                "msgFastTx" => "lldp.fast_tx_interval",
                "txFastInit" => "lldp.fast_tx_count",
                "txCreditMax" => "lldp.tx_credit_max",
                _ => "lldp.reinit_delay",
            };
            v.push(Violation {
                path: path.into(),
                message: format!("{e} (IEEE 802.1AB range)"),
            });
        }
        if !(1..=64).contains(&self.lldp.max_neighbors_per_interface) {
            v.push(Violation {
                path: "lldp.max_neighbors_per_interface".into(),
                message: format!(
                    "{} is outside 1 to 64",
                    self.lldp.max_neighbors_per_interface
                ),
            });
        }
        match (&self.lldp.chassis_id.source, &self.lldp.chassis_id.value) {
            (ChassisIdSource::Custom, None) => v.push(Violation {
                path: "lldp.chassis_id.value".into(),
                message: "required when source is custom".into(),
            }),
            (ChassisIdSource::Custom, Some(s)) if s.is_empty() || s.len() > 255 => {
                v.push(Violation {
                    path: "lldp.chassis_id.value".into(),
                    message: "must be 1 to 255 bytes".into(),
                });
            }
            (src, Some(_)) if *src != ChassisIdSource::Custom => v.push(Violation {
                path: "lldp.chassis_id.value".into(),
                message: "only allowed when source is custom".into(),
            }),
            _ => {}
        }
        check_opt_str(
            &mut v,
            "lldp.system_name_override",
            self.lldp.system_name_override.as_deref(),
        );
        check_opt_str(
            &mut v,
            "lldp.system_description_override",
            self.lldp.system_description_override.as_deref(),
        );
        if !(0..=8).contains(&self.lldp.management_addresses.max_per_interface) {
            v.push(Violation {
                path: "lldp.management_addresses.max_per_interface".into(),
                message: "must be 0 to 8".into(),
            });
        }
        for (i, pat) in self.interfaces.exclude.iter().enumerate() {
            if pat.is_empty() {
                v.push(Violation {
                    path: format!("interfaces.exclude[{i}]"),
                    message: "pattern is empty".into(),
                });
            }
        }
        for (i, o) in self.interfaces.overrides.iter().enumerate() {
            if o.r#match.is_empty() {
                v.push(Violation {
                    path: format!("interfaces.overrides[{i}].match"),
                    message: "pattern is empty".into(),
                });
            }
            check_opt_str(
                &mut v,
                &format!("interfaces.overrides[{i}].port_description"),
                o.port_description.as_deref(),
            );
        }
        if !(1..=10_000).contains(&self.logging.event_rate_limit_per_minute) {
            v.push(Violation {
                path: "logging.event_rate_limit_per_minute".into(),
                message: "must be 1 to 10000".into(),
            });
        }
        if v.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Invalid(v))
        }
    }

    /// Applies registry policy overrides. Policy wins over the file.
    pub fn apply_policy(&mut self, policy: &PolicyOverrides) {
        if let Some(e) = policy.enabled {
            self.agent.enabled = e;
        }
        if let Some(m) = policy.default_mode {
            self.interfaces.default_mode = m;
        }
        if let Some(b) = policy.advertise_fqdn {
            self.lldp.advertise.system_name_fqdn = b;
        }
        if let Some(b) = policy.advertise_os_version {
            self.lldp.advertise.os_version = b;
        }
        if let Some(b) = policy.advertise_hardware {
            self.lldp.advertise.hardware = b;
        }
        if let Some(b) = policy.advertise_management_address {
            self.lldp.advertise.management_address = b;
        }
    }

    /// Decides how an interface is treated.
    pub fn resolve_interface(
        &self,
        alias: &str,
        guid: &str,
        kind: InterfaceKind,
    ) -> ResolvedInterface {
        let mut r = ResolvedInterface {
            mode: match kind {
                InterfaceKind::PhysicalEthernet => self.interfaces.default_mode,
                InterfaceKind::Wifi => self.interfaces.wifi,
                InterfaceKind::Virtual => self.interfaces.r#virtual,
                InterfaceKind::Other => InterfaceMode::Disabled,
            },
            port_description: None,
            matched_override: None,
        };
        if self
            .interfaces
            .exclude
            .iter()
            .any(|p| glob::matches(p, alias))
        {
            r.mode = InterfaceMode::Disabled;
            return r;
        }
        for (i, o) in self.interfaces.overrides.iter().enumerate() {
            let hit = match o.r#match.strip_prefix("guid:") {
                Some(g) => g
                    .trim_matches(|c| c == '{' || c == '}')
                    .eq_ignore_ascii_case(guid.trim_matches(|c| c == '{' || c == '}')),
                None => glob::matches(&o.r#match, alias),
            };
            if hit {
                if let Some(m) = o.mode {
                    r.mode = m;
                }
                r.port_description.clone_from(&o.port_description);
                r.matched_override = Some(i);
                break;
            }
        }
        if !self.agent.enabled {
            r.mode = InterfaceMode::Disabled;
        }
        r
    }
}

fn check_opt_str(v: &mut Vec<Violation>, path: &str, s: Option<&str>) {
    if let Some(s) = s
        && (s.is_empty() || s.len() > 255)
    {
        v.push(Violation {
            path: path.into(),
            message: "must be 1 to 255 bytes".into(),
        });
    }
}

/// Classification of a network interface supplied by the platform crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceKind {
    /// Physical 802.3 adapter (including USB and dock Ethernet).
    PhysicalEthernet,
    /// 802.11 adapter.
    Wifi,
    /// Hyper-V, bridge, team, or other software adapter.
    Virtual,
    /// Loopback, tunnel, VPN, cellular, anything else.
    Other,
}

/// The outcome of matching an interface against the configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedInterface {
    /// Administrative mode.
    pub mode: InterfaceMode,
    /// Administrator-defined Port Description, if any.
    pub port_description: Option<String>,
    /// Index into `interfaces.overrides` that matched, if any.
    pub matched_override: Option<usize>,
}
