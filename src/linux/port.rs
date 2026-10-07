use super::process::{self, Proc};
use super::{describe, sockets};
use crate::{kubernetes, tunnel};
use crate::graph::Node;
use crate::util::{has_token, run, short};

pub fn explain(port: u16, proto: Option<&str>) -> Node {
    let mut root = Node::new(match proto { Some(p) => format!("PORT {port}/{p}"), None => format!("PORT {port}") });
    let ls: Vec<_> = sockets::listeners(Some(port)).into_iter().filter(|l| proto.is_none_or(|p| l.proto == p)).collect();
    if ls.is_empty() {
        root.add(Node::new(format!("nothing is listening on this port{}", proto.map(|p| format!(" over {p}")).unwrap_or_default())).proof("checked the tcp/tcp6/udp/udp6 tables in /proc/net"));
    }
    let inodes: Vec<u64> = ls.iter().map(|l| l.inode).collect();
    let (owners, unreadable) = if ls.is_empty() { Default::default() } else { sockets::owners(&inodes) };
    let mut by_pid: Vec<(u32, Vec<&sockets::Listener>)> = vec![];
    for l in &ls {
        match owners.get(&l.inode) {
            Some(pids) => pids.iter().for_each(|p| match by_pid.iter_mut().find(|(q, _)| q == p) {
                Some((_, v)) => v.push(l),
                None => by_pid.push((*p, vec![l])),
            }),
            None => {
                root.add(Node::new(format!("listening: {} {}, but I can't tell which process ({unreadable} unreadable processes): try with sudo", l.proto, l.addr)).unknown().proof(format!("socket {} in /proc/net", l.inode)));
            }
        }
    }
    for (pid, socks) in by_pid {
        if let Some(p) = process::read(pid) {
            root.add(process_node(&p, port, &socks));
        }
    }
    root.add(front_node(port, proto));
    root
}

pub fn list(proto: Option<&str>) -> String {
    let mut ls: Vec<_> = sockets::listeners(None).into_iter().filter(|l| proto.is_none_or(|p| l.proto == p)).collect();
    let inodes: Vec<u64> = ls.iter().map(|l| l.inode).collect();
    let (owners, unreadable) = sockets::owners(&inodes);
    ls.sort_by(|a, b| (a.port, a.proto, &a.addr).cmp(&(b.port, b.proto, &b.addr)));
    let mut out = format!("{:<7} {:<6} {:<28} {}\n", "PORT", "PROTO", "ADDRESS", "PROCESS");
    for l in &ls {
        let who = owners.get(&l.inode).and_then(|p| process::read(p[0])).map(|p| format!("{} ({})", p.name, p.pid)).unwrap_or_else(|| "?".into());
        out.push_str(&format!("{:<7} {:<6} {:<28} {who}\n", l.port, l.proto, l.addr));
    }
    if unreadable > 0 {
        out.push_str(&format!("\n{unreadable} processes are not readable: run with sudo to see all owners\n"));
    }
    out
}

pub fn complete() -> String {
    let ls = sockets::listeners(None);
    let inodes: Vec<u64> = ls.iter().map(|l| l.inode).collect();
    let (owners, _) = sockets::owners(&inodes);
    let mut v: Vec<(u16, String)> = ls.iter().map(|l| (l.port, owners.get(&l.inode).and_then(|p| process::read(p[0])).map(|p| p.name).unwrap_or_default())).collect();
    v.sort();
    v.dedup_by_key(|x| x.0);
    v.iter().map(|(p, n)| format!("{p}\t{n}\n")).collect()
}

fn process_node(p: &Proc, port: u16, socks: &[&sockets::Listener]) -> Node {
    let mut n = Node::new(format!("process {} (pid {}, user {})", p.name, p.pid, p.user)).proof(format!("holds the socket open in /proc/{}/fd", p.pid));
    let list = socks.iter().map(|l| format!("{} {}", l.proto, l.addr)).collect::<Vec<_>>().join(", ");
    n.add(Node::new(format!("listens on: {list}")).proof("/proc/net/* tables"));
    n.children.extend(describe::details(p, Some(port)));
    n
}

fn front_node(port: u16, proto: Option<&str>) -> Node {
    let mut n = Node::new("network in front of the process");
    let p = port.to_string();
    let mut via_wg = vec![];
    let mut any_firewall = false;
    for (tool, args) in [("nft", &["list", "ruleset"][..]), ("iptables-save", &[][..]), ("ip6tables-save", &[][..])] {
        let Some(rules) = run(tool, args) else { continue };
        any_firewall = true;
        let other = match proto { Some("tcp") => "udp", Some("udp") => "tcp", _ => "" };
        let hits: Vec<&str> = rules.lines().map(str::trim).filter(|l| l.contains("port") && has_token(l, &p) && (other.is_empty() || !has_word(l, other))).take(6).collect();
        for h in &hits {
            n.add(Node::new(short(h, 140)).probable().proof(format!("{tool}: the rule names the port")));
            via_wg.extend(tunnel::wireguard_in(h));
        }
        if hits.is_empty() {
            n.add(Node::new(format!("no {tool} rule names this port")).proof(tool.to_string()));
        }
    }
    if !any_firewall {
        n.add(Node::new("firewall rules not readable (needs root, or none of nft/iptables is installed)").unknown());
    }
    for rt in ["docker", "podman"] {
        if let Some(out) = run(rt, &["ps", "--format", "{{.Names}}\t{{.Ports}}"]) {
            for l in out.lines().filter(|l| l.contains(&format!(":{p}->"))) {
                n.add(Node::new(format!("{rt} publishes the port: {}", l.replace('\t', "  "))).proof(format!("{rt} ps")));
            }
        }
    }
    n.children.extend(kubernetes::services(port));
    n.add(tunnel::explain(port, &via_wg));
    n
}

fn has_word(line: &str, word: &str) -> bool {
    line.split(|c: char| !c.is_ascii_alphanumeric()).any(|w| w == word)
}
