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
    pub user: String,
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
    Some(Proc {
        pid,
        ppid,
        name: stat[open + 1..close].to_string(),
        cmdline,
        cwd: fs::read_link(format!("/proc/{pid}/cwd")).ok(),
        user: user_name(uid),
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

/// Which systemd service or container manages it, read from the cgroup.
pub fn origin(pid: u32) -> Origin {
    let Ok(text) = fs::read_to_string(format!("/proc/{pid}/cgroup")) else { return Origin::None };
    let Some(path) = text.lines().find_map(|l| l.strip_prefix("0::")) else { return Origin::None };
    classify(path)
}

fn classify(path: &str) -> Origin {
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    for s in parts.iter().rev() {
        for (prefix, runtime) in [("docker-", "docker"), ("libpod-", "podman"), ("cri-containerd-", "containerd")] {
            if let Some(id) = s.strip_prefix(prefix).and_then(|r| r.strip_suffix(".scope")) {
                return Origin::Container { runtime, id: id.to_string() };
            }
        }
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
    }
}
