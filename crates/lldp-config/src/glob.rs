//! Minimal case-insensitive glob: `*` matches any run, `?` one character.

pub(crate) fn matches(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().flat_map(char::to_lowercase).collect();
    let t: Vec<char> = text.chars().flat_map(char::to_lowercase).collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_p, mut star_t): (Option<usize>, usize) = (None, 0);
    while ti < t.len() {
        match p.get(pi) {
            Some('*') => {
                star_p = Some(pi);
                star_t = ti;
                pi = pi.saturating_add(1);
            }
            Some('?') => {
                pi = pi.saturating_add(1);
                ti = ti.saturating_add(1);
            }
            Some(c) if t.get(ti) == Some(c) => {
                pi = pi.saturating_add(1);
                ti = ti.saturating_add(1);
            }
            _ => match star_p {
                Some(sp) => {
                    pi = sp.saturating_add(1);
                    star_t = star_t.saturating_add(1);
                    ti = star_t;
                }
                None => return false,
            },
        }
    }
    while p.get(pi) == Some(&'*') {
        pi = pi.saturating_add(1);
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn globs() {
        assert!(matches("vEthernet*", "vEthernet (Default Switch)"));
        assert!(matches("vethernet*", "vEthernet (WSL)"));
        assert!(!matches("vEthernet*", "Ethernet"));
        assert!(matches("Ethernet ?", "Ethernet 2"));
        assert!(!matches("Ethernet ?", "Ethernet 12"));
        assert!(matches("*", ""));
        assert!(matches("*", "anything"));
        assert!(!matches("", "x"));
        assert!(matches("", ""));
        assert!(matches("a*b*c", "aXXbYYc"));
        assert!(!matches("a*b*c", "aXXbYY"));
    }
}
