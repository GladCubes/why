//! `why port N` on Windows: who listens (netstat), what runs it, and what sits in front (firewall rules, portproxy, tunnels).
use super::describe;
use super::process;
use super::ps::{ps, rows};
use crate::graph::Node;
use crate::proc::{self, Proc};
use crate::util::{has_token, run, short};
use std::process::Command;

pub struct Listener {
    pub proto: &'static str,
    pub addr: String,
    pub port: u16,
    pub pid: u32,
}

/// `netstat -ano` on any Windows language: TCP lines whose remote side is the all-zero address are listeners; UDP lines have no state.
pub fn parse_netstat(text: &str) -> Vec<Listener> {
    let mut out = vec![];
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        let (proto, local, pid) = match (f.first().map(|s| s.to_ascii_uppercase()).as_deref(), f.len()) {
            (Some("TCP"), 5) if f[2].ends_with(":0") && (f[2].starts_with("0.0.0.0") || f[2].starts_with("[::]")) => ("tcp", f[1], f[4]),
            (Some("UDP"), 4) => ("udp", f[1], f[3]),
            _ => continue,
        };
        let Some((_, p)) = local.rsplit_once(':') else { continue };
        let (Ok(port), Ok(pid)) = (p.parse(), pid.parse()) else { continue };
        out.push(Listener { proto, addr: local.to_string(), port, pid });
    }
    out
}

pub fn listeners(only: Option<u16>, proto: Option<&str>) -> Vec<Listener> {
    let text = Command::new("netstat").arg("-ano").output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    parse_netstat(&text).into_iter().filter(|l| only.is_none_or(|o| o == l.port) && proto.is_none_or(|p| p == l.proto)).collect()
}

pub fn explain(port: u16, proto: Option<&str>) -> Node {
    let mut root = Node::new(match proto { Some(p) => format!("PORT {port}/{p}"), None => format!("PORT {port}") });
    let ls = listeners(Some(port), proto);
    if ls.is_empty() {
        root.add(Node::new(format!("nothing is listening on this port{}", proto.map(|p| format!(" over {p}")).unwrap_or_default())).proof("netstat -ano"));
    }
    let mut pids: Vec<u32> = vec![];
    for l in &ls {
        if !pids.contains(&l.pid) {
            pids.push(l.pid);
        }
    }
    for pid in pids {
        let socks: Vec<&Listener> = ls.iter().filter(|l| l.pid == pid).collect();
        match process::read(pid) {
            Some(p) => {
                root.add(process_node(&p, port, &socks));
            }
            None => {
                root.add(Node::new(format!("listening: pid {pid}, but that process is not visible (it may have just exited)")).unknown().proof("netstat -ano"));
            }
        }
    }
    root.add(front_node(port, proto));
    root
}

fn process_node(p: &Proc, port: u16, socks: &[&Listener]) -> Node {
    let mut n = Node::new(format!("process {} (pid {}, user {})", p.name, p.pid, p.user)).proof("owning process in netstat -ano");
    let list = socks.iter().map(|l| format!("{} {}", l.proto, l.addr)).collect::<Vec<_>>().join(", ");
    n.add(Node::new(format!("listens on: {list}")).proof("netstat -ano"));
    if let Some(exe) = &p.exe {
        let e = n.add(Node::new(format!("executable: {}", exe.display())).proof("WMI Win32_Process.ExecutablePath"));
        e.children.extend(describe::identity(&exe.to_string_lossy()));
    }
    n.children.extend(describe::details(p, Some(port)));
    n
}

/// `why port list`
pub fn list(proto: Option<&str>) -> String {
    let mut ls = listeners(None, proto);
    ls.sort_by(|a, b| (a.port, a.proto, &a.addr).cmp(&(b.port, b.proto, &b.addr)));
    let mut out = format!("{:<7} {:<6} {:<28} {}\n", "PORT", "PROTO", "ADDRESS", "PROCESS");
    for l in &ls {
        let who = proc::all().iter().find(|p| p.pid == l.pid).map(|p| format!("{} ({})", p.name, p.pid)).unwrap_or_else(|| "?".into());
        out.push_str(&format!("{:<7} {:<6} {:<28} {who}\n", l.port, l.proto, l.addr));
    }
    out
}

pub fn complete() -> String {
    let mut v: Vec<(u16, String)> = listeners(None, None).iter().map(|l| (l.port, proc::all().iter().find(|p| p.pid == l.pid).map(|p| p.name.clone()).unwrap_or_default())).collect();
    v.sort();
    v.dedup_by_key(|x| x.0);
    v.iter().map(|(p, n)| format!("{p}\t{n}\n")).collect()
}

/// `netsh interface portproxy show all`: rows `listen addr, listen port, connect addr, connect port`.
pub fn parse_portproxy(text: &str) -> Vec<[String; 4]> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() == 4 && f[1].parse::<u16>().is_ok() && f[3].parse::<u16>().is_ok()).then(|| [f[0].into(), f[1].into(), f[2].into(), f[3].into()])
        })
        .collect()
}

fn front_node(port: u16, proto: Option<&str>) -> Node {
    let mut n = Node::new("network in front of the process");
    let p = port.to_string();
    let mut proxies = 0;
    for family in ["v4tov4", "v4tov6", "v6tov4", "v6tov6"] {
        let out = run("netsh", &["interface", "portproxy", "show", family]).unwrap_or_default();
        for r in parse_portproxy(&out).into_iter().filter(|r| r[1] == p || r[3] == p) {
            proxies += 1;
            n.add(Node::new(format!("portproxy rule: {}:{} → {}:{}", r[0], r[1], r[2], r[3])).proof("netsh interface portproxy (a Windows built-in forwarder, often used with WSL)"));
        }
    }
    let script = format!(r#"$n={port}; Get-NetFirewallPortFilter | ? {{ @($_.LocalPort | ? {{ $_ -eq "$n" -or ($_ -match '^(\d+)-(\d+)$' -and $n -ge [int]$matches[1] -and $n -le [int]$matches[2]) }}).Count -gt 0 }} | % {{ $r=$_ | Get-NetFirewallRule; "{{0}}`t{{1}}`t{{2}}`t{{3}}`t{{4}}`t{{5}}" -f $r.DisplayName,$r.Enabled,$r.Direction,$r.Action,$_.Protocol,$_.LocalPort }}"#);
    match ps(&script) {
        Some(out) => {
            let fw: Vec<Vec<String>> = rows(&out).into_iter().filter(|r| r.len() >= 6 && proto.is_none_or(|pr| r[4].eq_ignore_ascii_case(pr) || r[4].eq_ignore_ascii_case("any"))).collect();
            for r in fw.iter().take(8) {
                n.add(Node::new(format!("firewall rule \"{}\": {} {} {} on {} port {}", short(&r[0], 50), if r[1] == "True" { "enabled" } else { "disabled" }, r[2], r[3], r[4], r[5])).probable().proof("Get-NetFirewallPortFilter + Get-NetFirewallRule"));
            }
            if fw.is_empty() {
                n.add(Node::new("no Windows Firewall rule names this port").proof("Get-NetFirewallPortFilter"));
            }
        }
        None => {
            n.add(Node::new("firewall rules not readable (PowerShell NetSecurity module missing or needs administrator)").unknown());
        }
    }
    if let Some(out) = run("docker", &["ps", "--format", "{{.Names}}\t{{.Ports}}"]) {
        for l in out.lines().filter(|l| l.contains(&format!(":{p}->"))) {
            n.add(Node::new(format!("docker publishes the port: {}", l.replace('\t', "  "))).proof("docker ps"));
        }
    }
    n.children.extend(crate::kubernetes::services(port));
    n.add(crate::tunnel::explain(port, &[]));
    if proxies > 0 {
        n.add(Node::new("a portproxy rule means this port can be answered by another address entirely").probable());
    }
    n
}

#[allow(dead_code)]
fn _unused(_: &str) -> bool {
    has_token("", "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_netstat_in_any_language() {
        let sample = "  Proto  Indirizzo locale        Indirizzo esterno      Stato           PID\n  TCP    0.0.0.0:135            0.0.0.0:0              IN ASCOLTO      1032\n  TCP    192.168.1.5:50123      52.1.2.3:443           STABILITA       4420\n  TCP    [::]:445               [::]:0                 LISTENING       4\n  UDP    0.0.0.0:5353           *:*                                    2244\n  UDP    [::1]:1900             *:*                                    9000\n";
        let l = parse_netstat(sample);
        assert_eq!(l.len(), 4);
        assert_eq!((l[0].proto, l[0].port, l[0].pid), ("tcp", 135, 1032));
        assert_eq!((l[2].proto, l[2].port, l[2].pid), ("udp", 5353, 2244));
        assert_eq!(l[3].addr, "[::1]:1900");
    }

    #[test]
    fn parses_portproxy() {
        let t = "Listen on ipv4:             Connect to ipv4:\n\nAddress         Port        Address         Port\n--------------- ----------  --------------- ----------\n0.0.0.0         8080        172.28.1.2      80\n";
        assert_eq!(parse_portproxy(t), vec![["0.0.0.0".to_string(), "8080".into(), "172.28.1.2".into(), "80".into()]]);
    }
}
