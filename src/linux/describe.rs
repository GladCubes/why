use super::process::{self, Origin, Proc};
use super::unit;
use crate::graph::Node;
use crate::util::{grep_token, has_token, run, short};
use std::fs;
use std::path::PathBuf;

pub fn details(p: &Proc, port: Option<u16>) -> Vec<Node> {
    let mut out = vec![];
    let cmd = p.cmdline.join(" ");
    let mut c = Node::new(format!("command: {}", short(&cmd, 140))).proof(format!("/proc/{}/cmdline", p.pid));
    if let Some(port) = port {
        if cmd.split_whitespace().any(|a| has_token(a, &port.to_string())) {
            c.add(Node::new(format!("port {port} appears in the command")).probable());
        }
    }
    if !cmd.is_empty() {
        out.push(c);
    }
    if let Some(cwd) = &p.cwd {
        out.push(Node::new(format!("working directory: {}", cwd.display())).proof(format!("/proc/{}/cwd", p.pid)));
    }
    out.extend(proxy_target(p));
    out.push(started_by(p));
    out.extend(origin_nodes(p, port));
    if let Some(port) = port {
        out.push(config_node(p, port));
    }
    out
}

pub fn started_by(p: &Proc) -> Node {
    if p.ppid == 0 {
        return Node::new("started by: the kernel itself (parent pid 0)").proof("/proc/<pid>/stat");
    }
    let chain = process::ancestors(p.pid);
    if chain.is_empty() {
        return Node::new("started by: not readable").unknown();
    }
    let text = chain.iter().map(|a| format!("{} ({})", a.name, a.pid)).collect::<Vec<_>>().join(" ← ");
    let mut n = Node::new(format!("started by: {text}")).proof("parent chain in /proc/<pid>/stat");
    if chain[0].pid <= 1 || chain[0].name == "systemd" {
        let init = if chain[0].name == "systemd" { "systemd" } else { "init (pid 1)" };
        n.add(Node::new(format!("the parent is {init}: the program detached from its terminal (daemon, `-f`, `&`) or {init} started it")).probable());
    }
    if chain.iter().any(|a| a.name.starts_with("tmux") || a.name.starts_with("screen")) {
        n.add(Node::new("inside a tmux/screen session: closing the session stops it").probable());
    }
    n
}

pub fn origin_nodes(p: &Proc, port: Option<u16>) -> Vec<Node> {
    if p.cmdline.is_empty() && p.exe.is_none() {
        return vec![Node::new("kernel thread: part of the kernel, not a program on disk").proof(format!("no command line and no executable in /proc/{}", p.pid))];
    }
    let proof = format!("cgroup in /proc/{}/cgroup", p.pid);
    match process::origin(p.pid) {
        Origin::Service { name, user } => {
            let mut n = Node::new(format!("systemd {}service: {name}", if user { "user " } else { "" })).proof(proof);
            let files = unit::files(&name, user);
            if files.is_empty() {
                n.add(Node::new("unit file not found in the standard directories (the unit may have been removed since it started)").unknown());
            }
            for f in files {
                let node = n.add(Node::new(format!("file: {}", f.display())).proof("systemd directories"));
                for l in unit::key_lines(&f) {
                    node.add(Node::new(short(&l, 140)));
                    let script = l.strip_prefix("ExecStart=").and_then(|c| c.trim_start_matches(['-', '@', '+', '!', ':']).split_whitespace().next().map(PathBuf::from));
                    if let (Some(port), Some(s)) = (port, script.filter(|s| s.is_file())) {
                        for (i, t) in grep_token(&s, &port.to_string(), 3) {
                            node.add(Node::new(format!("{}:{i}: {t}", s.display())).probable().proof("script launched by ExecStart"));
                        }
                    }
                }
                if let Some(port) = port {
                    for (i, t) in grep_token(&f, &port.to_string(), 3) {
                        node.add(Node::new(format!("line {i}: {t}")).probable());
                    }
                }
            }
            vec![n]
        }
        Origin::Container { runtime, id } => {
            let mut n = Node::new(format!("{runtime} container: {}", &id[..id.len().min(12)])).proof(proof);
            if matches!(runtime, "docker" | "podman") {
                match run(runtime, &["inspect", "--format", "{{.Name}}  image {{.Config.Image}}", &id]) {
                    Some(s) => {
                        n.add(Node::new(s.trim().to_string()).proof(format!("{runtime} inspect")));
                    }
                    None => {
                        n.add(Node::new(format!("{runtime} does not answer (permissions?): can't tell name and image")).unknown());
                    }
                }
            }
            vec![n]
        }
        Origin::Scope(s) if s == "init.scope" => vec![Node::new("init.scope: the system's own init (pid 1 and what it starts directly)").proof(proof)],
        Origin::Scope(s) => vec![Node::new(format!("scope: {s} (started from a login session or an app, not by a service)")).proof(proof)],
        Origin::None if !std::path::Path::new("/run/systemd/system").exists() => {
            vec![Node::new("this system does not run systemd: I can't tell which init service (OpenRC, runit, s6, ...) manages it").unknown().proof(proof)]
        }
        Origin::None => vec![Node::new("no service or container: started by hand or by a script").proof(proof).probable()],
    }
}

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

fn proxy_target(p: &Proc) -> Option<Node> {
    if matches!(p.name.as_str(), "incusd" | "lxd") {
        return forkproxy_target(p);
    }
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

fn forkproxy_target(p: &Proc) -> Option<Node> {
    let args = &p.cmdline[p.cmdline.iter().position(|a| a == "forkproxy")? + 1..];
    let args: Vec<&String> = args.iter().skip_while(|a| a.as_str() == "--").collect();
    let (pid, addr) = (args.get(3)?.parse::<u32>().ok()?, args.get(5)?);
    let mut n = Node::new(format!("proxy device: forwards to {addr} inside another namespace (pid {pid})")).proof("forkproxy arguments");
    match process::origin(pid) {
        Origin::Container { runtime, id } => {
            n.add(Node::new(format!("that process lives in the {runtime} container `{id}`")).proof(format!("cgroup in /proc/{pid}/cgroup")));
        }
        _ => {
            n.add(Node::new("could not tell which container that is").unknown());
        }
    }
    Some(n)
}
