//! `why port N`: chi ascolta, come e' stato avviato, quale configurazione la nomina e cosa c'e' davanti.
use super::process::{self, Origin, Proc};
use super::{sockets, unit};
use crate::graph::Node;
use crate::util::{grep_token, has_token, run, short};
use std::fs;
use std::path::PathBuf;

pub fn explain(port: u16) -> Node {
    let mut root = Node::new(format!("PORTA {port}"));
    let ls = sockets::listeners(port);
    if ls.is_empty() {
        root.add(Node::new("nessun processo e' in ascolto su questa porta").proof("controllate le tabelle tcp/tcp6/udp/udp6 di /proc/net"));
    }
    let inodes: Vec<u64> = ls.iter().map(|l| l.inode).collect();
    let (owners, unreadable) = if ls.is_empty() { Default::default() } else { sockets::owners(&inodes) };
    // un nodo per processo (non uno per socket: lo stesso programma ascolta spesso su IPv4 e IPv6)
    let mut by_pid: Vec<(u32, Vec<&sockets::Listener>)> = vec![];
    for l in &ls {
        match owners.get(&l.inode) {
            Some(pids) => pids.iter().for_each(|p| match by_pid.iter_mut().find(|(q, _)| q == p) {
                Some((_, v)) => v.push(l),
                None => by_pid.push((*p, vec![l])),
            }),
            None => {
                root.add(Node::new(format!("in ascolto: {} {}, ma non so quale processo sia ({unreadable} processi non leggibili): riprova con sudo", l.proto, l.addr)).unknown().proof(format!("socket {} in /proc/net", l.inode)));
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

fn process_node(p: &Proc, port: u16, socks: &[&sockets::Listener]) -> Node {
    let mut n = Node::new(format!("processo {} (pid {}, utente {})", p.name, p.pid, p.user)).proof(format!("tiene aperto il socket in /proc/{}/fd", p.pid));
    let list = socks.iter().map(|l| format!("{} {}", l.proto, l.addr)).collect::<Vec<_>>().join(", ");
    n.add(Node::new(format!("ascolta su: {list}")).proof("tabelle /proc/net/*"));
    let cmd = p.cmdline.join(" ");
    let c = n.add(Node::new(format!("comando: {}", short(&cmd, 140))).proof(format!("/proc/{}/cmdline", p.pid)));
    if cmd.split_whitespace().any(|a| has_token(a, &port.to_string())) {
        c.add(Node::new(format!("la porta {port} compare nel comando")).probable());
    }
    if let Some(cwd) = &p.cwd {
        n.add(Node::new(format!("cartella: {}", cwd.display())).proof(format!("/proc/{}/cwd", p.pid)));
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
        return Node::new("avviato da: non leggibile").unknown();
    }
    let text = chain.iter().map(|a| format!("{} ({})", a.name, a.pid)).collect::<Vec<_>>().join(" ← ");
    let mut n = Node::new(format!("avviato da: {text}")).proof("catena dei genitori in /proc/<pid>/stat");
    if chain[0].pid <= 1 || chain[0].name == "systemd" {
        n.add(Node::new("il genitore e' systemd: il programma si e' staccato dal terminale (daemon, `-f`, `&`) oppure lo ha avviato systemd/l'app").probable());
    }
    if chain.iter().any(|a| a.name.starts_with("tmux")) {
        n.add(Node::new("dentro una sessione tmux: se chiudi la sessione si ferma").probable());
    }
    n
}

fn origin_nodes(p: &Proc, port: u16) -> Vec<Node> {
    let proof = format!("cgroup di /proc/{}/cgroup", p.pid);
    match process::origin(p.pid) {
        Origin::Service { name, user } => {
            let mut n = Node::new(format!("servizio systemd{}: {name}", if user { " (utente)" } else { "" })).proof(proof);
            let files = unit::files(&name, user);
            if files.is_empty() {
                n.add(Node::new("unit file non trovato nelle cartelle standard").unknown());
            }
            for f in files {
                let node = n.add(Node::new(format!("file: {}", f.display())).proof("cartelle di systemd"));
                for l in unit::key_lines(&f) {
                    node.add(Node::new(short(&l, 140)));
                    // se la unit lancia uno script, la porta e' spesso scritta li'
                    let script = l.strip_prefix("ExecStart=").and_then(|c| c.trim_start_matches(['-', '@', '+', '!', ':']).split_whitespace().next().map(PathBuf::from));
                    if let Some(s) = script.filter(|s| s.is_file()) {
                        for (i, t) in grep_token(&s, &port.to_string(), 3) {
                            node.add(Node::new(format!("{}:{i}: {t}", s.display())).probable().proof("script lanciato da ExecStart"));
                        }
                    }
                }
                for (i, t) in grep_token(&f, &port.to_string(), 3) {
                    node.add(Node::new(format!("riga {i}: {t}")).probable());
                }
            }
            vec![n]
        }
        Origin::Container { runtime, id } => {
            let mut n = Node::new(format!("contenitore {runtime}: {}", &id[..id.len().min(12)])).proof(proof);
            match run(runtime, &["inspect", "--format", "{{.Name}}  immagine {{.Config.Image}}", &id]) {
                Some(s) => {
                    n.add(Node::new(s.trim().to_string()).proof(format!("{runtime} inspect")));
                }
                None => {
                    n.add(Node::new(format!("{runtime} non risponde (permessi?): non so nome e immagine")).unknown());
                }
            }
            vec![n]
        }
        Origin::Scope(s) => vec![Node::new(format!("scope: {s} (avviato da una sessione di login o da un'app, non da un servizio)")).proof(proof)],
        Origin::None => vec![Node::new("nessun servizio o contenitore: lanciato a mano o da uno script").proof(proof).probable()],
    }
}

/// File che potrebbero contenere la porta: gli argomenti che sono file, i file di configurazione della cartella di lavoro, /etc/<nome>.
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
    let mut n = Node::new(format!("configurazione che nomina la porta {port}"));
    for f in &files {
        for (i, t) in grep_token(f, &port.to_string(), 3) {
            n.add(Node::new(format!("{}:{i}: {t}", f.display())).probable().proof("corrispondenza di testo, non dimostra che sia questa a decidere"));
        }
    }
    if n.children.is_empty() {
        n = n.unknown().proof(format!("{} file controllati: argomenti, cartella di lavoro, /etc/{}", files.len(), p.name));
        n.label = format!("nessun file di configurazione che nomina la porta {port}");
    }
    n
}

/// Cosa c'e' davanti: regole nft e porte pubblicate dai contenitori.
fn front_node(port: u16) -> Node {
    let mut n = Node::new("rete davanti al processo");
    let p = port.to_string();
    match run("nft", &["list", "ruleset"]) {
        Some(rules) => {
            let hits: Vec<&str> = rules.lines().map(str::trim).filter(|l| l.contains("port") && has_token(l, &p)).take(6).collect();
            for h in &hits {
                n.add(Node::new(short(h, 140)).probable().proof("nft list ruleset: la regola nomina la porta"));
            }
            if hits.is_empty() {
                n.add(Node::new("nessuna regola nft nomina questa porta").proof("nft list ruleset"));
            }
        }
        None => {
            n.add(Node::new("regole nft non leggibili (servono i permessi di root o nft manca)").unknown());
        }
    }
    for rt in ["docker", "podman"] {
        if let Some(out) = run(rt, &["ps", "--format", "{{.Names}}\t{{.Ports}}"]) {
            for l in out.lines().filter(|l| l.contains(&format!(":{p}->"))) {
                n.add(Node::new(format!("{rt} pubblica la porta: {}", l.replace('\t', "  "))).proof(format!("{rt} ps")));
            }
        }
    }
    n
}

/// docker-proxy inoltra la porta a un contenitore: trova quale dall'IP che si legge nel comando.
fn proxy_target(p: &Proc) -> Option<Node> {
    if p.name != "docker-proxy" {
        return None;
    }
    let arg = |k: &str| p.cmdline.iter().position(|a| a == k).and_then(|i| p.cmdline.get(i + 1)).cloned();
    let (ip, port) = (arg("-container-ip")?, arg("-container-port")?);
    let mut n = Node::new(format!("inoltra al contenitore {ip}:{port}")).proof("argomenti di docker-proxy");
    let ids = run("docker", &["ps", "-q"]).unwrap_or_default();
    let ids: Vec<&str> = ids.split_whitespace().collect();
    let info = if ids.is_empty() { None } else { run("docker", [&["inspect", "--format", "{{.Name}} | {{.Config.Image}} | {{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"], ids.as_slice()].concat().as_slice()) };
    match info.and_then(|s| s.lines().find(|l| l.split('|').nth(2).is_some_and(|x| x.split_whitespace().any(|a| a == ip))).map(String::from)) {
        Some(l) => {
            let f: Vec<&str> = l.split('|').map(str::trim).collect();
            n.add(Node::new(format!("contenitore {} (immagine {})", f[0].trim_start_matches('/'), f[1])).proof("docker inspect: stesso IP"));
        }
        None => {
            n.add(Node::new("contenitore non identificato (docker non risponde o non c'e' piu')").unknown());
        }
    }
    Some(n)
}
