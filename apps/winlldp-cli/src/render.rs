//! Text rendering in the key-value style of PLAN.MD Section 10.

use lldp_ipc::{
    InterfaceView, LldpduView, LocalAdvertisementView, NeighborView, ServiceStatusView,
    StatisticsView,
};

use crate::Report;
use crate::timefmt;

fn kv(key: &str, value: impl std::fmt::Display) {
    println!("{key:<17}: {value}");
}

fn opt(v: Option<&str>) -> &str {
    v.unwrap_or("-")
}

/// Service status.
pub fn status(s: &ServiceStatusView) {
    kv("Service", format!("WinLLDP {}", s.version));
    kv("Uptime", timefmt::duration(s.uptime_secs));
    kv(
        "Packet backend",
        s.npcap_version.as_deref().unwrap_or(&s.backend_status),
    );
    kv("Configuration", &s.config_path);
    if s.config_loaded_unix == 0 {
        kv(
            "Config loaded",
            "never (configuration error, see event 1003)",
        );
    } else {
        kv("Config loaded", timefmt::unix(s.config_loaded_unix));
    }
    kv("Policy applied", s.policy_applied);
    kv("Chassis ID", &s.chassis_id);
    kv("System name", &s.system_name);
    kv(
        "Interfaces",
        format!(
            "{} managed of {} known",
            s.interfaces_managed, s.interfaces_known
        ),
    );
    kv("Neighbors", s.neighbors_total);
}

/// Interface table.
pub fn interfaces(v: &[InterfaceView]) {
    if v.is_empty() {
        println!("no interfaces");
        return;
    }
    let w = v.iter().map(|i| i.alias.len()).max().unwrap_or(9).max(9);
    println!(
        "{:<w$}  {:<17}  {:<9}  {:<5}  {:<17}  {:<9}  Description",
        "Interface", "Kind", "Mode", "Link", "MAC", "Neighbors"
    );
    for i in v {
        println!(
            "{:<w$}  {:<17}  {:<9}  {:<5}  {:<17}  {:<9}  {}",
            i.alias,
            i.kind,
            format!("{:?}", i.mode).to_ascii_lowercase(),
            if i.connected { "up" } else { "down" },
            i.mac.as_deref().unwrap_or("-"),
            if i.managed {
                i.neighbors.to_string()
            } else {
                "-".into()
            },
            i.description
        );
    }
}

fn mgmt(l: &LldpduView, family: &str) -> String {
    let v: Vec<&str> = l
        .management_addresses
        .iter()
        .filter(|m| m.family == family)
        .map(|m| m.address.as_str())
        .collect();
    if v.is_empty() {
        "-".into()
    } else {
        v.join(", ")
    }
}

fn lldpdu_summary(l: &LldpduView) {
    kv("System Name", opt(l.system_name.as_deref()));
    kv(
        "Chassis ID",
        format!("{} ({})", l.chassis_id.value, l.chassis_id.subtype_name),
    );
    kv(
        "Port ID",
        format!("{} ({})", l.port_id.value, l.port_id.subtype_name),
    );
    kv("Port Description", opt(l.port_description.as_deref()));
    kv("Management IPv4", mgmt(l, "ipv4"));
    kv("Management IPv6", mgmt(l, "ipv6"));
    kv(
        "Capabilities",
        l.capabilities.as_ref().map_or_else(
            || "-".to_owned(),
            |c| {
                if c.enabled.is_empty() {
                    "none".into()
                } else {
                    c.enabled.join(", ")
                }
            },
        ),
    );
}

fn lldpdu_detail(l: &LldpduView) {
    // Continuation lines of a multi-line description align under the value.
    kv(
        "System Descr",
        opt(l.system_description.as_deref()).replace('\n', &format!("\n{:19}", "")),
    );
    kv("TTL", format!("{} seconds", l.ttl));
    for m in &l.management_addresses {
        kv(
            "Mgmt Address",
            format!(
                "{} ({}, {} {})",
                m.address, m.family, m.interface_numbering, m.interface_number
            ),
        );
    }
    for o in &l.org_tlvs {
        let org = o.organization.as_deref().unwrap_or("unknown OUI");
        match &o.decoded {
            Some(d) => kv("Org TLV", format!("{org} {}: {}", o.oui, compact(d))),
            None => kv(
                "Org TLV",
                format!("{org} {} subtype {}: {}", o.oui, o.subtype, o.data_hex),
            ),
        }
    }
    for u in &l.unknown_tlvs {
        kv(
            "Unknown TLV",
            format!("type {}: {}", u.tlv_type, u.value_hex),
        );
    }
}

fn compact(v: &serde_json::Value) -> String {
    match v.as_object() {
        Some(map) => map
            .iter()
            .filter(|(k, _)| k.as_str() != "type")
            .map(|(k, v)| {
                format!(
                    "{k}={}",
                    v.as_str().map_or_else(|| v.to_string(), str::to_owned)
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
            .trim()
            .to_owned()
            .pipe(|s| {
                let t = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
                if s.is_empty() {
                    t.to_owned()
                } else {
                    format!("{t} {s}")
                }
            }),
        None => v.to_string(),
    }
}

trait Pipe: Sized {
    fn pipe<R>(self, f: impl FnOnce(Self) -> R) -> R {
        f(self)
    }
}
impl Pipe for String {}

/// Neighbor blocks.
pub fn neighbors(v: &[NeighborView], detail: bool) {
    if v.is_empty() {
        println!("no neighbors");
        return;
    }
    for (i, n) in v.iter().enumerate() {
        if i > 0 {
            println!();
        }
        kv("Local Interface", &n.interface_alias);
        lldpdu_summary(&n.lldpdu);
        kv("TTL Remaining", format!("{} seconds", n.ttl_remaining));
        if detail {
            lldpdu_detail(&n.lldpdu);
            kv("Scope", &n.scope);
            kv("Source MAC", &n.source_mac);
            kv("First Seen", timefmt::unix(n.first_seen_unix));
            kv("Last Seen", timefmt::unix(n.last_seen_unix));
            kv("Frames", n.frames);
        }
    }
}

/// Local advertisement blocks.
pub fn local(v: &[LocalAdvertisementView]) {
    if v.is_empty() {
        println!("no managed interfaces");
        return;
    }
    for (i, a) in v.iter().enumerate() {
        if i > 0 {
            println!();
        }
        kv("Local Interface", &a.interface_alias);
        kv("Mode", format!("{:?}", a.mode).to_ascii_lowercase());
        kv("Destination MAC", &a.destination_mac);
        kv("Source MAC", &a.source_mac);
        lldpdu_summary(&a.lldpdu);
        lldpdu_detail(&a.lldpdu);
        kv("LLDPDU (hex)", &a.lldpdu_hex);
    }
}

/// Statistics table.
pub fn statistics(v: &[StatisticsView]) {
    if v.is_empty() {
        println!("no managed interfaces");
        return;
    }
    for (i, s) in v.iter().enumerate() {
        if i > 0 {
            println!();
        }
        kv("Interface", &s.interface_alias);
        kv("Frames In", s.rx_frames_total);
        kv("Frames Out", s.tx_frames_total);
        kv("Length Errors Out", s.tx_lldpdu_length_errors);
        kv("Frames Discarded", s.rx_frames_discarded_total);
        kv("Frame Errors", s.rx_frames_errors);
        kv("TLVs Discarded", s.rx_tlvs_discarded_total);
        kv("TLVs Unrecognized", s.rx_tlvs_unrecognized_total);
        kv("Ageouts", s.rx_ageouts_total);
        kv(
            "Inserts/Deletes",
            format!("{}/{}", s.rem_inserts, s.rem_deletes),
        );
        kv("Drops (full)", s.rem_drops);
        kv("Queue Overflows", s.rx_queue_overflow);
    }
}

/// Diagnostics report.
pub fn diagnostics(r: &Report) {
    for c in &r.checks {
        println!(
            "[{:<4}] {:<22} {}",
            c.result.to_ascii_uppercase(),
            c.name,
            c.detail
        );
    }
}
