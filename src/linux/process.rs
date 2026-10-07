//! A process as seen from /proc: command, directory, user, who started it and which service/container manages it.
use crate::util::user_name;
use std::fs;
use std::path::PathBuf;

pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmdline: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub exe: Option<PathBuf>,
    pub user: String,
    /// seconds since the epoch
    pub started: Option<u64>,
}

/// Seconds since the epoch at which the system booted.
fn boot_time() -> Option<u64> {
    fs::read_to_string("/proc/stat").ok()?.lines().find_map(|l| l.strip_prefix("btime ")?.trim().parse().ok())
}

pub fn read(pid: u32) -> Option<Proc> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (open, close) = (stat.find('(')?, stat.rfind(')')?);
    let ppid = stat[close + 2..].split_whitespace().nth(1)?.parse().ok()?;
    let cmdline = fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| b.split(|c| *c == 0).filter(|a| !a.is_empty()).map(|a| String::from_utf8_lossy(a).into_owned()).collect())
        .unwrap_or_default();
    let uid = fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("Uid:"))?.split_whitespace().nth(1)?.parse().ok())
        .unwrap_or(0);
    // field 22 of stat: start time in clock ticks since boot (100 per second on every mainstream Linux)
    let started = stat[close + 2..].split_whitespace().nth(19).and_then(|s| s.parse::<u64>().ok()).and_then(|ticks| Some(boot_time()? + ticks / 100));
    Some(Proc {
        pid,
        ppid,
        name: stat[open + 1..close].to_string(),
        cmdline,
        cwd: fs::read_link(format!("/proc/{pid}/cwd")).ok(),
        exe: fs::read_link(format!("/proc/{pid}/exe")).ok(),
        user: user_name(uid),
        started,
    })
}

/// Parent chain, nearest first, up to init (at most 8 steps).
pub fn ancestors(pid: u32) -> Vec<Proc> {
    let mut out = vec![];
    let mut cur = read(pid).map(|p| p.ppid).unwrap_or(0);
    while cur > 0 && out.len() < 8 {
        let Some(p) = read(cur) else { break };
        cur = p.ppid;
        out.push(p);
    }
    out
}

/// Direct children of `pid`.
pub fn children(pid: u32) -> Vec<Proc> {
    all().into_iter().filter(|p| p.ppid == pid).collect()
}

/// Every process that can be read.
pub fn all() -> Vec<Proc> {
    let Ok(rd) = fs::read_dir("/proc") else { return vec![] };
    rd.flatten().filter_map(|e| e.file_name().to_str()?.parse().ok()).filter_map(read).collect()
}

#[derive(Debug, PartialEq)]
pub enum Origin {
    Service { name: String, user: bool },
    Container { runtime: &'static str, id: String },
    Scope(String),
    None,
}

/// Which systemd service or container manages it, read from the cgroup (v2 `0::/path`, or v1 `N:name=systemd:/path`).
pub fn origin(pid: u32) -> Origin {
    let Ok(text) = fs::read_to_string(format!("/proc/{pid}/cgroup")) else { return Origin::None };
    let paths: Vec<&str> = text.lines().filter_map(|l| l.splitn(3, ':').nth(2)).collect();
    // a container shows up in any hierarchy; a service in the systemd one
    let first = paths.iter().map(|p| classify(p)).find(|o| matches!(o, Origin::Container { .. }));
    first.or_else(|| paths.iter().map(|p| classify(p)).find(|o| *o != Origin::None)).unwrap_or(Origin::None)
}

fn classify(path: &str) -> Origin {
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    for s in parts.iter().rev() {
        // LXC and Incus name the payload cgroup after the container
        for (prefix, runtime) in [("lxc.payload.", "lxc"), ("incus.payload.", "incus")] {
            if let Some(name) = s.strip_prefix(prefix) {
                return Origin::Container { runtime, id: name.to_string() };
            }
        }
        for (prefix, runtime) in [("docker-", "docker"), ("libpod-", "podman"), ("cri-containerd-", "containerd"), ("crio-", "cri-o")] {
            if let Some(id) = s.strip_prefix(prefix).and_then(|r| r.strip_suffix(".scope")) {
                return Origin::Container { runtime, id: id.to_string() };
            }
        }
    }
    // cgroup v1 layouts: /docker/<64 hex>, /kubepods/.../<64 hex>
    if let Some(id) = parts.iter().rev().find(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())) {
        let runtime = if parts.first() == Some(&"docker") { "docker" } else { "container" };
        return Origin::Container { runtime, id: id.to_string() };
    }
    if let Some(s) = parts.iter().rev().find(|s| s.ends_with(".service") && !s.starts_with("user@")) {
        return Origin::Service { name: s.to_string(), user: parts.iter().any(|p| p.starts_with("user@")) };
    }
    match parts.last() {
        Some(s) if s.ends_with(".scope") => Origin::Scope(s.to_string()),
        _ => Origin::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_cgroups() {
        assert_eq!(classify("/system.slice/nginx.service"), Origin::Service { name: "nginx.service".into(), user: false });
        assert_eq!(classify("/user.slice/user-1000.slice/user@1000.service/app.slice/foo.service"), Origin::Service { name: "foo.service".into(), user: true });
        assert_eq!(classify("/system.slice/docker-abc123.scope"), Origin::Container { runtime: "docker", id: "abc123".into() });
        assert_eq!(classify("/user.slice/user-1000.slice/session-2.scope"), Origin::Scope("session-2.scope".into()));
        assert_eq!(classify("/lxc.payload.web/system.slice/nginx.service"), Origin::Container { runtime: "lxc", id: "web".into() });
        assert_eq!(classify("/incus.payload.db/init.scope"), Origin::Container { runtime: "incus", id: "db".into() });
        assert_eq!(classify("/kubepods.slice/kubepods-burstable.slice/crio-abc.scope"), Origin::Container { runtime: "cri-o", id: "abc".into() });
        let id = "a".repeat(64);
        assert_eq!(classify(&format!("/docker/{id}")), Origin::Container { runtime: "docker", id });
        assert_eq!(classify("/"), Origin::None);
    }
}
