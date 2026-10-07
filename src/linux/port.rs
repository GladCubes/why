//! `why port N`: who listens, how it was started, which configuration names the port and what sits in front of it.
use super::process::{self, Origin, Proc};
use super::{sockets, tunnel, unit};
use crate::graph::Node;
use crate::util::{grep_token, has_token, run, short};
use std::fs;
use std::path::PathBuf;

pub fn explain(port: u16) -> Node {
    let mut root = Node::new(format!("PORT {port}"));
    let ls = sockets::listeners(Some(port));
    if ls.is_empty() {
        root.add(Node::new("nothing is listening on this port").proof("checked the tcp/tcp6/udp/udp6 tables in /proc/net"));
    }
    let inodes: Vec<u64> = ls.iter().map(|l| l.inode).collect();
    let (owners, unreadable) = if ls.is_empty() { Default::default() } else { sockets::owners(&inodes) };
    // one node per process (not per socket: the same program often listens on IPv4 and IPv6)
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
    root.add(front_node(port));
    root
}

/// `why port list`: every listening port and who holds it.
pub fn list() -> String {
    let mut ls = sockets::listeners(None);
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

/// Names for shell completion: `port\tprocess`.
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
    let cmd = p.cmdline.join(" ");
    let c = n.add(Node::new(format!("command: {}", short(&cmd, 140))).proof(format!("/proc/{}/cmdline", p.pid)));
    if cmd.split_whitespace().any(|a| has_token(a, &port.to_string())) {
        c.add(Node::new(format!("port {port} appears in the command")).probable());
    }
    if let Some(cwd) = &p.cwd {
        n.add(Node::new(format!("working directory: {}", cwd.display())).proof(format!("/proc/{}/cwd", p.pid)));
    }
    if let Some(c) = proxy_target(p) {
        n.add(c);
    }
    n.add(started_by(p));
    n.children.extend(origin_nodes(p, port));
    n.add(config_node(p, port));
    n
}

fn started_by(p: &Proc) -> Node {
    let chain = process::ancestors(p.pid);
    if chain.is_empty() {
        return Node::new("started by: not readable").unknown();
    }
    let text = chain.iter().map(|a| format!("{} ({})", a.name, a.pid)).collect::<Vec<_>>().join(" ← ");
    let mut n = Node::new(format!("started by: {text}")).proof("parent chain in /proc/<pid>/stat");
    if chain[0].pid <= 1 || chain[0].name == "systemd" {
        n.add(Node::new("the parent is systemd: the program detached from its terminal (daemon, `-f`, `&`) or systemd/an app started it").probable());
    }
    if chain.iter().any(|a| a.name.starts_with("tmux")) {
        n.add(Node::new("inside a tmux session: closing the session stops it").probable());
    }
    n
}

fn origin_nodes(p: &Proc, port: u16) -> Vec<Node> {
    let proof = format!("cgroup in /proc/{}/cgroup", p.pid);
    match process::origin(p.pid) {
        Origin::Service { name, user } => {
            let mut n = Node::new(format!("systemd {}service: {name}", if user { "user " } else { "" })).proof(proof);
            let files = unit::files(&name, user);
            if files.is_empty() {
                n.add(Node::new("unit file not found in the standard directories").unknown());
            }
            for f in files {
                let node = n.add(Node::new(format!("file: {}", f.display())).proof("systemd directories"));
                for l in unit::key_lines(&f) {
                    node.add(Node::new(short(&l, 140)));
                    // if the unit launches a script, the port is often written there
                    let script = l.strip_prefix("ExecStart=").and_then(|c| c.trim_start_matches(['-', '@', '+', '!', ':']).split_whitespace().next().map(PathBuf::from));
                    if let Some(s) = script.filter(|s| s.is_file()) {
                        for (i, t) in grep_token(&s, &port.to_string(), 3) {
                            node.add(Node::new(format!("{}:{i}: {t}", s.display())).probable().proof("script launched by ExecStart"));
                        }
                    }
                }
                for (i, t) in grep_token(&f, &port.to_string(), 3) {
                    node.add(Node::new(format!("line {i}: {t}")).probable());
                }
            }
            vec![n]
        }
        Origin::Container { runtime, id } => {
            let mut n = Node::new(format!("{runtime} container: {}", &id[..id.len().min(12)])).proof(proof);
            match run(runtime, &["inspect", "--format", "{{.Name}}  image {{.Config.Image}}", &id]) {
                Some(s) => {
                    n.add(Node::new(s.trim().to_string()).proof(format!("{runtime} inspect")));
                }
                None => {
                    n.add(Node::new(format!("{runtime} does not answer (permissions?): can't tell name and image")).unknown());
                }
            }
            vec![n]
        }
        Origin::Scope(s) => vec![Node::new(format!("scope: {s} (started from a login session or an app, not by a service)")).proof(proof)],
        Origin::None => vec![Node::new("no service or container: started by hand or by a script").proof(proof).probable()],
    }
}

/// Files that may contain the port: arguments that are files, config files in the working directory, /etc/<name>.
fn candidates(p: &Proc) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = vec![];
    let base = p.cwd.clone().unwrap_or_default();
    for a in &p.cmdline {
        let v = a.rsplit_once('=').map(|x| x.1).unwrap_or(a);
        let f = base.join(v);
        if f.is_file() && !out.contains(&f) {
            out.push(f);
        }
    }
    const EXT: [&str; 11] = ["yml", "yaml", "json", "toml", "conf", "cfg", "ini", "env", "properties", "xml", "txt"];
    let noisy = p.cwd.as_deref().is_none_or(|c| c == std::path::Path::new("/") || crate::util::home().as_deref() == Some(c));
    let mut dirs = vec![PathBuf::from(format!("/etc/{}", p.name))];
    if !noisy {
        dirs.push(base.clone());
    }
    for d in dirs {
        let Ok(rd) = fs::read_dir(d) else { continue };
        for e in rd.flatten().take(300) {
            let f = e.path();
            let ok = f.extension().is_some_and(|x| EXT.iter().any(|y| x == *y)) || f.file_name().is_some_and(|n| n.to_string_lossy().starts_with(".env"));
            if ok && f.is_file() && !out.contains(&f) {
                out.push(f);
            }
        }
    }
    let etc = PathBuf::from(format!("/etc/{}.conf", p.name));
    if etc.is_file() {
        out.push(etc);
    }
    out
}

fn config_node(p: &Proc, port: u16) -> Node {
    let files = candidates(p);
    let mut n = Node::new(format!("configuration naming port {port}"));
    for f in &files {
        for (i, t) in grep_token(f, &port.to_string(), 3) {
            n.add(Node::new(format!("{}:{i}: {t}", f.display())).probable().proof("text match, does not prove this is what decides"));
        }
    }
    if n.children.is_empty() {
        n = n.unknown().proof(format!("{} files checked: arguments, working directory, /etc/{}", files.len(), p.name));
        n.label = format!("no configuration file names port {port}");
    }
    n
}

/// What sits in front: nft rules, ports published by containers, tunnels and forwards.
fn front_node(port: u16) -> Node {
    let mut n = Node::new("network in front of the process");
    let p = port.to_string();
    let mut via_wg = vec![];
    match run("nft", &["list", "ruleset"]) {
        Some(rules) => {
            let hits: Vec<&str> = rules.lines().map(str::trim).filter(|l| l.contains("port") && has_token(l, &p)).take(6).collect();
            for h in &hits {
                n.add(Node::new(short(h, 140)).probable().proof("nft list ruleset: the rule names the port"));
                via_wg.extend(tunnel::wireguard_in(h));
            }
            if hits.is_empty() {
                n.add(Node::new("no nft rule names this port").proof("nft list ruleset"));
            }
        }
        None => {
            n.add(Node::new("nft rules not readable (needs root, or nft is missing)").unknown());
        }
    }
    for rt in ["docker", "podman"] {
        if let Some(out) = run(rt, &["ps", "--format", "{{.Names}}\t{{.Ports}}"]) {
            for l in out.lines().filter(|l| l.contains(&format!(":{p}->"))) {
                n.add(Node::new(format!("{rt} publishes the port: {}", l.replace('\t', "  "))).proof(format!("{rt} ps")));
            }
        }
    }
    n.add(tunnel::explain(port, &via_wg));
    n
}

/// docker-proxy forwards the port to a container: find which one from the IP in its command line.
fn proxy_target(p: &Proc) -> Option<Node> {
    if p.name != "docker-proxy" {
        return None;
    }
    let arg = |k: &str| p.cmdline.iter().position(|a| a == k).and_then(|i| p.cmdline.get(i + 1)).cloned();
    let (ip, port) = (arg("-container-ip")?, arg("-container-port")?);
    let mut n = Node::new(format!("forwards to container {ip}:{port}")).proof("docker-proxy arguments");
    let ids = run("docker", &["ps", "-q"]).unwrap_or_default();
    let ids: Vec<&str> = ids.split_whitespace().collect();
    let info = if ids.is_empty() { None } else { run("docker", [&["inspect", "--format", "{{.Name}} | {{.Config.Image}} | {{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"], ids.as_slice()].concat().as_slice()) };
    match info.and_then(|s| s.lines().find(|l| l.split('|').nth(2).is_some_and(|x| x.split_whitespace().any(|a| a == ip))).map(String::from)) {
        Some(l) => {
            let f: Vec<&str> = l.split('|').map(str::trim).collect();
            n.add(Node::new(format!("container {} (image {})", f[0].trim_start_matches('/'), f[1])).proof("docker inspect: same IP"));
        }
        None => {
            n.add(Node::new("container not identified (docker does not answer or it is gone)").unknown());
        }
    }
    Some(n)
}
