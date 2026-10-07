use super::process::{autostart, services_of};
use super::ps::{ps, q, rows};
use crate::graph::Node;
use crate::proc::{self, Proc};
use crate::util::{grep_token, short};
use std::fs;
use std::path::PathBuf;

pub fn details(p: &Proc, port: Option<u16>) -> Vec<Node> {
    let mut out = vec![];
    let cmd = p.cmdline.join(" ");
    let mut c = if cmd.is_empty() {
        Node::new("command: not readable (protected process: an administrator terminal sees it)").unknown()
    } else {
        Node::new(format!("command: {}", short(&cmd, 140))).proof("WMI Win32_Process.CommandLine")
    };
    if let Some(port) = port {
        if cmd.split_whitespace().any(|a| crate::util::has_token(a, &port.to_string())) {
            c.add(Node::new(format!("port {port} appears in the command")).probable());
        }
    }
    out.push(c);
    out.extend(relay_note(p));
    out.push(started_by(p));
    out.extend(service_nodes(p));
    out.extend(autostart_nodes(p));
    if let Some(port) = port {
        out.push(config_node(p, port));
    }
    out
}

fn relay_note(p: &Proc) -> Option<Node> {
    let msg = match proc::norm(&p.name).as_str() {
        "wslrelay" | "wslhost" | "wslservice" => "WSL forwards the localhost ports of Linux distros through this process: the real listener is inside WSL (run `wsl why port N` there)",
        "com.docker.backend" | "vpnkit" | "wslrelay-docker" => "Docker Desktop publishes container ports through this process: see `docker ps` for the container",
        "system" => "PID 4 is the Windows kernel: it holds ports for built-in features (file sharing, HTTP.sys sites, netsh portproxy)",
        _ => return None,
    };
    Some(Node::new(msg).probable().proof("known role of this program"))
}

pub fn started_by(p: &Proc) -> Node {
    let chain = proc::ancestors(p.pid);
    if chain.is_empty() {
        return Node::new("started by: its parent has already exited (so it is not known)").unknown().proof("Win32_Process.ParentProcessId points at a process that no longer exists");
    }
    let text = chain.iter().map(|a| format!("{} ({})", a.name, a.pid)).collect::<Vec<_>>().join(" ← ");
    let mut n = Node::new(format!("started by: {text}")).proof("parent chain in WMI");
    match proc::norm(&chain[0].name).as_str() {
        "services" => {
            n.add(Node::new("the Windows service manager started it: it is a service").probable());
        }
        "explorer" => {
            n.add(Node::new("started from the desktop by a user (Start menu, double click, Run key)").probable());
        }
        "svchost" | "taskeng" | "taskhostw" => {
            n.add(Node::new("started by a scheduled task or a system service").probable());
        }
        "cmd" | "powershell" | "pwsh" | "windowsterminal" | "conhost" => {
            n.add(Node::new("started from a terminal: someone typed it, or a script did").probable());
        }
        _ => {}
    }
    n
}

pub fn service_nodes(p: &Proc) -> Vec<Node> {
    let svcs = services_of(p.pid);
    if svcs.is_empty() {
        return vec![];
    }
    let mut n = Node::new(if svcs.len() == 1 { "Windows service".to_string() } else { format!("hosts {} Windows services", svcs.len()) }).proof("WMI Win32_Service for this process");
    for s in svcs.iter().take(10).filter(|s| s.len() >= 5) {
        let c = n.add(Node::new(format!("{} ({}): {}, start mode {}, runs as {}", s[0], short(&s[1], 40), s[3], s[2], s[4])));
        if let Some(path) = s.get(5).filter(|x| !x.is_empty()) {
            c.add(Node::new(format!("path: {}", short(path, 140))));
        }
    }
    vec![n]
}

pub fn autostart_nodes(p: &Proc) -> Vec<Node> {
    let Some(exe) = &p.exe else { return vec![] };
    let rows = autostart(&exe.to_string_lossy());
    if rows.is_empty() {
        return vec![];
    }
    let mut n = Node::new("starts automatically through").proof("Run keys, scheduled tasks, Startup folders");
    for r in rows.iter().filter(|r| r.len() >= 3) {
        let label = match r[0].as_str() {
            "run" => format!("registry Run key {} = {}", r[1], short(&r[2], 100)),
            "task" => format!("scheduled task {}: {}", r[1], short(&r[2], 110)),
            _ => format!("Startup folder item {} → {}", r[1], r[2]),
        };
        n.add(Node::new(label).probable());
    }
    vec![n]
}

pub fn identity(path: &str) -> Vec<Node> {
    let out = ps(&format!(r#"$f=Get-Item -LiteralPath {p}; $v=$f.VersionInfo; $s=Get-AuthenticodeSignature -LiteralPath {p}; "sig`t$($s.Status)`t$($s.SignerCertificate.Subject)"; "ver`t$($v.CompanyName)`t$($v.ProductName)`t$($v.FileVersion)`t$($v.FileDescription)""#, p = q(path))).unwrap_or_default();
    let mut v = vec![];
    for r in rows(&out) {
        match r[0].as_str() {
            "sig" if r.len() >= 2 => {
                let who = r.get(2).map(|s| s.split(',').next().unwrap_or("").trim_start_matches("CN=").to_string()).filter(|s| !s.is_empty());
                let n = match (r[1].as_str(), who) {
                    ("Valid", Some(w)) => Node::new(format!("signed by {w}: the signature is valid")).proof("Get-AuthenticodeSignature"),
                    ("NotSigned", _) => Node::new("not signed: no publisher can be verified").probable().proof("Get-AuthenticodeSignature"),
                    (st, w) => Node::new(format!("signature status {st}{}", w.map(|w| format!(" ({w})")).unwrap_or_default())).probable().proof("Get-AuthenticodeSignature"),
                };
                v.push(n);
            }
            "ver" if r.len() >= 5 && r[1..].iter().any(|x| !x.is_empty()) => {
                v.push(Node::new(format!("file says: {} {} {} ({})", r[1], r[2], r[3], short(&r[4], 50))).proof("version resource inside the file"));
            }
            _ => {}
        }
    }
    v
}

fn candidates(p: &Proc) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = vec![];
    for a in &p.cmdline {
        let v = a.rsplit_once('=').map(|x| x.1).unwrap_or(a);
        let f = PathBuf::from(v);
        if f.is_file() && !out.contains(&f) {
            out.push(f);
        }
    }
    const EXT: [&str; 11] = ["yml", "yaml", "json", "toml", "conf", "cfg", "ini", "config", "properties", "xml", "env"];
    let stem = p.name.trim_end_matches(".exe").to_string();
    let mut dirs: Vec<PathBuf> = p.exe.as_ref().and_then(|e| e.parent()).map(|d| d.to_path_buf()).into_iter().collect();
    if let Some(pd) = std::env::var_os("ProgramData") {
        dirs.push(PathBuf::from(pd).join(&stem));
    }
    dirs.retain(|d| !d.to_string_lossy().to_lowercase().starts_with("c:\\windows"));
    for d in dirs {
        for e in fs::read_dir(d).into_iter().flatten().flatten().take(300) {
            let f = e.path();
            if f.is_file() && f.extension().is_some_and(|x| EXT.iter().any(|y| x.eq_ignore_ascii_case(y))) && !out.contains(&f) {
                out.push(f);
            }
        }
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
        n = n.unknown().proof(format!("{} files checked: arguments, the program's folder, %ProgramData%", files.len()));
        n.label = format!("no configuration file names port {port}");
    }
    n
}
