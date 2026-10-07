//! Who listens where: the /proc/net/* socket tables and /proc/<pid>/fd (whose socket it is).
use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct Listener {
    pub proto: &'static str,
    pub addr: String,
    pub port: u16,
    pub inode: u64,
}

const TABLES: [(&str, &str, &str); 4] = [
    ("/proc/net/tcp", "tcp", "0A"),
    ("/proc/net/tcp6", "tcp", "0A"),
    ("/proc/net/udp", "udp", "07"),
    ("/proc/net/udp6", "udp", "07"),
];

/// Listening sockets, all of them or only those on `only`.
pub fn listeners(only: Option<u16>) -> Vec<Listener> {
    let mut out = vec![];
    for (path, proto, state) in TABLES {
        let Ok(text) = fs::read_to_string(path) else { continue };
        for l in text.lines().skip(1) {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 10 || f[3] != state {
                continue;
            }
            let Some((ip, p)) = f[1].rsplit_once(':') else { continue };
            let Ok(port) = u16::from_str_radix(p, 16) else { continue };
            if only.is_some_and(|o| o != port) {
                continue;
            }
            let (Some(addr), Ok(inode)) = (parse_ip(ip), f[9].parse()) else { continue };
            out.push(Listener { proto, addr: format!("{addr}:{port}"), port, inode });
        }
    }
    out
}

fn parse_ip(hex: &str) -> Option<String> {
    match hex.len() {
        8 => Some(Ipv4Addr::from(u32::from_str_radix(hex, 16).ok()?.swap_bytes()).to_string()),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                let w = u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16).ok()?.swap_bytes();
                b[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
            }
            Some(format!("[{}]", Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

/// The listening sockets a process holds (readable only for your own processes, or as root).
pub fn of_pid(pid: u32) -> Vec<Listener> {
    let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else { return vec![] };
    let inodes: Vec<u64> = fds
        .flatten()
        .filter_map(|fd| fs::read_link(fd.path()).ok()?.to_string_lossy().strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok())
        .collect();
    if inodes.is_empty() {
        return vec![];
    }
    listeners(None).into_iter().filter(|l| inodes.contains(&l.inode)).collect()
}

/// For each inode, the processes that hold that socket open. The second value counts processes I could not read.
pub fn owners(inodes: &[u64]) -> (HashMap<u64, Vec<u32>>, usize) {
    let mut map: HashMap<u64, Vec<u32>> = HashMap::new();
    let mut unreadable = 0;
    let Ok(procs) = fs::read_dir("/proc") else { return (map, 0) };
    for p in procs.flatten() {
        let Some(pid) = p.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            unreadable += 1;
            continue;
        };
        for fd in fds.flatten() {
            let Ok(t) = fs::read_link(fd.path()) else { continue };
            let t = t.to_string_lossy().into_owned();
            if let Some(i) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')).and_then(|s| s.parse().ok()) {
                if inodes.contains(&i) {
                    let v = map.entry(i).or_default();
                    if !v.contains(&pid) {
                        v.push(pid);
                    }
                }
            }
        }
    }
    (map, unreadable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_addresses() {
        assert_eq!(parse_ip("0100007F").unwrap(), "127.0.0.1");
        assert_eq!(parse_ip("00000000000000000000000001000000").unwrap(), "[::1]");
    }
}
