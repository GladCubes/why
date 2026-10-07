//! `why service <name>`: why a systemd service is (or is not) running: state, how it is enabled, who wants it, what it runs.
use super::{describe, process, unit};
use crate::graph::Node;
use crate::util::{run, short};
use std::collections::HashMap;

fn show(name: &str, user: bool) -> Option<HashMap<String, String>> {
    let mut args = vec!["show", "--no-pager", name, "-p", "Id,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,MainPID,ExecMainStartTimestamp,Description,TriggeredBy,WantedBy,RequiredBy,Wants,Requires,After,Before,Result,Restart"];
    if user {
        args.insert(0, "--user");
    }
    let out = run("systemctl", &args)?;
    let m: HashMap<String, String> = out.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect();
    (m.get("LoadState").is_some_and(|s| s != "not-found")).then_some(m)
}

fn list(m: &HashMap<String, String>, key: &str) -> Vec<String> {
    m.get(key).map(|v| v.split_whitespace().map(String::from).collect()).unwrap_or_default()
}

pub fn explain(arg: &str) -> Node {
    if !std::path::Path::new("/run/systemd/system").exists() {
        return Node::new(format!("SERVICE {arg}: this system does not run systemd")).unknown().proof("/run/systemd/system is missing; OpenRC, runit and s6 are not supported yet");
    }
    let name = if arg.contains('.') { arg.to_string() } else { format!("{arg}.service") };
    let found = [false, true].into_iter().find_map(|u| show(&name, u).map(|m| (u, m)));
    let Some((user, m)) = found else {
        return Node::new(format!("SERVICE {arg}: no such unit")).unknown().proof("systemctl show reports it as not found (system and user scope)");
    };
    let mut root = Node::new(format!("SERVICE {}{}", m.get("Id").unwrap_or(&name), if user { " (user)" } else { "" })).proof("systemctl show");
    let (active, sub) = (m["ActiveState"].as_str(), m["SubState"].as_str());
    let since = m.get("ExecMainStartTimestamp").filter(|s| !s.is_empty()).map(|s| format!(", since {s}")).unwrap_or_default();
    let n = root.add(Node::new(format!("{active} ({sub}){since}")).proof("systemctl show"));
    if m.get("Result").is_some_and(|r| r != "success") {
        n.add(Node::new(format!("last result: {}", m["Result"])).probable());
    }
    if let Some(d) = m.get("Description").filter(|d| !d.is_empty()) {
        root.add(Node::new(format!("description: {d}")).proof("unit file"));
    }
    // why it exists at boot
    let enabled = m.get("UnitFileState").map(String::as_str).unwrap_or("");
    let mut e = Node::new(format!("unit file state: {}", if enabled.is_empty() { "n/a" } else { enabled })).proof("systemctl show");
    for w in list(&m, "WantedBy").into_iter().chain(list(&m, "RequiredBy")) {
        e.add(Node::new(format!("wanted by {w}: it is started whenever that is")).proof("[Install] section / dependency links"));
    }
    if enabled == "masked" {
        e.add(Node::new("masked: it cannot start at all").probable());
    }
    root.add(e);
    let trig = list(&m, "TriggeredBy");
    if !trig.is_empty() {
        root.add(Node::new(format!("started on demand by: {}", trig.join(", "))).proof("TriggeredBy (socket or timer activation)"));
    }
    // what dependents want it right now
    if let Some(rev) = run("systemctl", &["list-dependencies", "--reverse", "--plain", "--no-pager", "--no-legend", &name]) {
        let deps: Vec<&str> = rev.lines().map(str::trim).filter(|l| !l.is_empty() && *l != name).take(8).collect();
        if !deps.is_empty() {
            root.add(Node::new(format!("pulled in by: {}", deps.join(", "))).proof("systemctl list-dependencies --reverse"));
        }
    }
    let after = list(&m, "After");
    if !after.is_empty() {
        root.add(Node::new(format!("starts after: {}", short(&after.join(", "), 140))).proof("After="));
    }
    let needs: Vec<String> = list(&m, "Requires").into_iter().chain(list(&m, "Wants")).collect();
    if !needs.is_empty() {
        root.add(Node::new(format!("needs: {}", short(&needs.join(", "), 140))).proof("Requires= / Wants="));
    }
    for f in unit::files(&name, user) {
        let node = root.add(Node::new(format!("file: {}", f.display())).proof("systemd directories"));
        for l in unit::key_lines(&f) {
            node.add(Node::new(short(&l, 140)));
        }
    }
    if let Some(p) = m.get("MainPID").and_then(|p| p.parse::<u32>().ok()).filter(|p| *p > 0).and_then(process::read) {
        let mut pn = Node::new(format!("main process {} (pid {}, user {})", p.name, p.pid, p.user)).proof("MainPID");
        let ports = super::sockets::of_pid(p.pid);
        if !ports.is_empty() {
            pn.add(Node::new(format!("listens on: {}", ports.iter().map(|x| format!("{} {}", x.proto, x.addr)).collect::<Vec<_>>().join(", "))).proof("/proc/<pid>/fd + /proc/net"));
        }
        pn.children.extend(describe::details(&p, None).into_iter().take(2));
        root.add(pn);
    } else if active == "active" {
        root.add(Node::new("no main process (oneshot or forking service): see child processes with systemctl status").unknown());
    }
    root
}

/// Names for shell completion.
pub fn complete() -> String {
    run("systemctl", &["list-unit-files", "--type=service", "--no-legend", "--no-pager"]).unwrap_or_default().lines().filter_map(|l| l.split_whitespace().next()).map(|n| format!("{}\n", n.trim_end_matches(".service"))).collect()
}
