//! Pure parsers for data obtained from Windows APIs. Kept free of
//! platform dependencies so they are unit tested on every CI platform.

/// Parses "Npcap version 1.79, based on libpcap ..." into (major, minor).
pub fn parse_npcap_version(s: &str) -> Option<(u32, u32)> {
    let rest = s.strip_prefix("Npcap version ")?;
    let num: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let mut it = num.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next().unwrap_or("0").parse().ok()?;
    Some((major, minor))
}

/// Parses the structure table for the first type 1 structure.
pub fn parse_smbios_type1(table: &[u8]) -> (Option<String>, Option<String>, Option<String>) {
    let mut off = 0usize;
    while let (Some(&ty), Some(&len)) = (table.get(off), table.get(off.saturating_add(1))) {
        let len = usize::from(len);
        if len < 4 {
            break;
        }
        let formatted = table.get(off..off.saturating_add(len)).unwrap_or_default();
        // String set follows the formatted area and ends with a double NUL.
        let strings_start = off.saturating_add(len);
        let mut strings = Vec::new();
        let mut i = strings_start;
        loop {
            let s_end = table
                .get(i..)
                .and_then(|r| r.iter().position(|&b| b == 0))
                .map(|p| i.saturating_add(p));
            let Some(s_end) = s_end else {
                return (None, None, None);
            };
            if s_end == i {
                i = i.saturating_add(1);
                break;
            }
            strings.push(
                String::from_utf8_lossy(table.get(i..s_end).unwrap_or_default()).into_owned(),
            );
            i = s_end.saturating_add(1);
            if table.get(i) == Some(&0) {
                i = i.saturating_add(1);
                break;
            }
        }
        if ty == 1 && len >= 0x19 {
            let s = |idx: Option<&u8>| {
                idx.and_then(|&n| n.checked_sub(1))
                    .and_then(|n| strings.get(usize::from(n)).cloned())
                    .filter(|s| !s.trim().is_empty())
            };
            let manufacturer = s(formatted.get(4));
            let model = s(formatted.get(5));
            let uuid = formatted.get(8..24).and_then(|u| <[u8; 16]>::try_from(u).ok()).map(|u| {
                // SMBIOS 2.6+ stores the first three fields little-endian.
                let [a0, a1, a2, a3, b0, b1, c0, c1, d0, d1, e0, e1, e2, e3, e4, e5] = u;
                format!(
                    "{a3:02x}{a2:02x}{a1:02x}{a0:02x}-{b1:02x}{b0:02x}-{c1:02x}{c0:02x}-{d0:02x}{d1:02x}-{e0:02x}{e1:02x}{e2:02x}{e3:02x}{e4:02x}{e5:02x}"
                )
            });
            let uuid = uuid.filter(|u| {
                u != "00000000-0000-0000-0000-000000000000"
                    && u != "ffffffff-ffff-ffff-ffff-ffffffffffff"
            });
            return (manufacturer, model, uuid);
        }
        if ty == 127 {
            break;
        }
        off = i;
    }
    (None, None, None)
}

#[cfg(test)]
mod tests {
    use super::{parse_npcap_version, parse_smbios_type1};

    #[test]
    fn version_parsing() {
        assert_eq!(
            parse_npcap_version("Npcap version 1.79, based on libpcap version 1.10.4"),
            Some((1, 79))
        );
        assert_eq!(parse_npcap_version("Npcap version 1.50"), Some((1, 50)));
        assert_eq!(parse_npcap_version("WinPcap version 4.1.3"), None);
    }

    #[test]
    fn parses_type1() {
        let mut t = vec![1u8, 0x1b, 1, 0, 1, 2, 3, 4];
        t.extend_from_slice(&[
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        t.extend_from_slice(&[6, 5, 6]); // wake-up, SKU, family
        t.extend_from_slice(b"Dell Inc.\0Latitude 5550\0v1\0SN\0\0");
        t.extend_from_slice(&[127, 4, 0, 0, 0, 0]);
        let (m, p, u) = parse_smbios_type1(&t);
        assert_eq!(m.as_deref(), Some("Dell Inc."));
        assert_eq!(p.as_deref(), Some("Latitude 5550"));
        assert_eq!(u.as_deref(), Some("00112233-4455-6677-8899-aabbccddeeff"));
        assert_eq!(parse_smbios_type1(&[]), (None, None, None));
        assert_eq!(parse_smbios_type1(&[1, 2]), (None, None, None));
    }
}
