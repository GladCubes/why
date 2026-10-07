//! A picture of this machine to compare with another: tools, environment, ports, services, containers, packages.
use super::{pkg, sockets};
use crate::compare::Snapshot;
use crate::util::run;
use std::fs;
use std::process::Command;

const TOOLS: [(&str, &[&str]); 31] = [
    ("node", &["--version"]), ("npm", &["--version"]), ("python3", &["--version"]), ("pip3", &["--version"]), ("java", &["-version"]),
    ("dotnet", &["--version"]), ("go", &["version"]), ("rustc", &["--version"]), ("cargo", &["--version"]), ("gcc", &["--version"]),
    ("clang", &["--version"]), ("make", &["--version"]), ("git", &["--version"]), ("docker", &["--version"]), ("podman", &["--version"]),
    ("kubectl", &["version", "--client"]), ("openssl", &["version"]), ("curl", &["--version"]), ("nginx", &["-v"]), ("php", &["--version"]),
    ("ruby", &["--version"]), ("psql", &["--version"]), ("mysql", &["--version"]), ("redis-server", &["--version"]), ("ssh", &["-V"]),
    ("systemctl", &["--version"]), ("bash", &["--version"]), ("sqlite3", &["--version"]), ("perl", &["--version"]), ("zsh", &["--version"]), ("fish", &["--version"]),
];

/// Variables that differ on every login and say nothing about the machine.
const NOISE: [&str; 12] = ["_", "PWD", "OLDPWD", "SHLVL", "TERM", "COLORTERM", "LS_COLORS", "SSH_TTY", "SSH_CLIENT", "SSH_CONNECTION", "DISPLAY", "WINDOWID"];
const NOISE_PREFIX: &[&str] = &["INVOCATION_ID", "JOURNAL_STREAM", "MANAGERPID", "SYSTEMD_EXEC_PID", "MEMORY_PRESSURE", "GIO_", "GJS_", "PRESSURE_VESSEL", "QT_", "GDK_", "EGL_", "ELECTRON", "MCP_", "DESKTOP_SESSION", "SSH_AUTH", "XDG_SESSION", "DBUS_", "KITTY_", "WAYLAND_", "TMUX", "LC_", "CLAUDE", "ANTHROPIC", "AI_AGENT", "BAGGAGE", "SENTRY", "VSCODE", "TERM_", "GNOME_", "LIBVA", "NO_AT_BRIDGE", "MOTD"];

/// stdout and stderr of a successful command (java and nginx print their version on stderr).
fn both(cmd: &str, args: &[&str]) -> Option<String> {
    let o = Command::new(cmd).args(args).env("LC_ALL", "C").output().ok()?;
    o.status.success().then(|| format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

pub fn collect() -> Snapshot {
    let mut s = Snapshot::new();
    s.insert("meta/hostname".into(), fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default().trim().to_string());
    let os = fs::read_to_string("/etc/os-release").unwrap_or_default();
    if let Some(n) = os.lines().find_map(|l| l.strip_prefix("PRETTY_NAME=")) {
        s.insert("meta/os".into(), n.trim_matches('"').to_string());
    }
    s.insert("meta/kernel".into(), fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim().to_string());
    s.insert("meta/arch".into(), std::env::consts::ARCH.to_string());
    s.insert("meta/cpus".into(), std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0).to_string());
    if let Some(kb) = fs::read_to_string("/proc/meminfo").ok().and_then(|m| m.lines().next()?.split_whitespace().nth(1)?.parse::<u64>().ok()) {
        s.insert("meta/memory".into(), format!("{} GB", (kb + 524_288) / 1_048_576));
    }
    for (tool, args) in TOOLS {
        if !pkg::on_path(tool) {
            continue;
        }
        if let Some(v) = both(tool, args).and_then(|o| o.lines().find(|l| !l.trim().is_empty()).map(|l| l.trim().chars().take(90).collect::<String>())) {
            s.insert(format!("tool/{tool}"), v);
        }
    }
    for (k, v) in std::env::vars() {
        if NOISE.contains(&k.as_str()) || NOISE_PREFIX.iter().any(|p| k.starts_with(p)) {
            continue;
        }
        s.insert(format!("env/{k}"), crate::env::comparable(&k, &v));
    }
    let ls = sockets::listeners(None);
    let inodes: Vec<u64> = ls.iter().map(|l| l.inode).collect();
    let (owners, _) = sockets::owners(&inodes);
    for l in ls {
        let who = owners.get(&l.inode).and_then(|p| super::process::read(p[0])).map(|p| p.name).unwrap_or_else(|| "?".into());
        s.insert(format!("port/{}/{}", l.proto, l.port), who);
    }
    if let Some(o) = run("systemctl", &["list-units", "--type=service", "--state=running", "--no-legend", "--no-pager", "--plain"]) {
        for n in o.lines().filter_map(|l| l.split_whitespace().next()) {
            s.insert(format!("service/{n}"), "running".into());
        }
    }
    if let Some(o) = run("systemctl", &["list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--no-pager"]) {
        for n in o.lines().filter_map(|l| l.split_whitespace().next()) {
            s.entry(format!("service/{n}")).or_insert_with(|| "enabled, not running".into());
        }
    }
    for rt in ["docker", "podman"] {
        if let Some(o) = run(rt, &["ps", "--format", "{{.Names}}\t{{.Image}}"]) {
            for l in o.lines() {
                if let Some((n, i)) = l.split_once('\t') {
                    s.insert(format!("container/{n}"), i.to_string());
                }
            }
        }
    }
    for (n, v) in pkg::installed() {
        s.insert(format!("pkg/{n}"), v);
    }
    s
}
