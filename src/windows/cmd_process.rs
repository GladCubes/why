//! `why process <pid|name>` on Windows.
use super::cmd_port::listeners;
use super::describe;
use crate::graph::Node;
use crate::proc::{self, Proc};
use crate::util::{ago, date, now};
use std::path::Path;

fn find(arg: &str) -> Vec<Proc> {
    if let Ok(pid) = arg.parse::<u32>() {
        return super::process::read(pid).into_iter().collect();
    }
    let want = proc::norm(Path::new(arg).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default().as_str());
    let me = std::process::id();
    proc::all().into_iter().filter(|p| p.pid != me && proc::norm(&p.name) == want).collect()
}

pub fn explain(arg: &str) -> Node {
    let found = find(arg);
    match found.as_slice() {
        [] => Node::new(format!("PROCESS {arg}: no running process matches")).unknown().proof("looked at the name of every process WMI lists"),
        [one] => tree(&super::process::read(one.pid).unwrap_or_else(|| one.clone())),
        many => {
            let mut root = Node::new(format!("PROCESS {arg}: {} processes match", many.len())).proof("process name");
            for p in many.iter().take(5) {
                let full = super::process::read(p.pid).unwrap_or_else(|| p.clone());
                root.add(tree(&full));
            }
            if many.len() > 5 {
                let rest = many[5..].iter().map(|p| p.pid.to_string()).take(12).collect::<Vec<_>>().join(", ");
                root.add(Node::new(format!("{} more (pids {rest}…): ask about one with `why process <pid>`", many.len() - 5)).unknown());
            }
            root
        }
    }
}

fn tree(p: &Proc) -> Node {
    let mut n = Node::new(format!("process {} (pid {}, user {})", p.name, p.pid, p.user)).proof("WMI Win32_Process");
    if let Some(s) = p.started {
        n.add(Node::new(format!("running for {} (since {})", ago(now().saturating_sub(s)), date(s))).proof("Win32_Process.CreationDate"));
    }
    match &p.exe {
        Some(exe) => {
            let e = n.add(Node::new(format!("executable: {}", exe.display())).proof("Win32_Process.ExecutablePath"));
            e.children.extend(describe::identity(&exe.to_string_lossy()));
            let low = exe.to_string_lossy().to_lowercase();
            if low.contains("\\appdata\\") || low.contains("\\temp\\") || low.contains("\\downloads\\") {
                e.add(Node::new("it runs from a user-writable folder (AppData, Temp or Downloads): normal for per-user apps, worth a look for anything else").probable());
            }
        }
        None => {
            n.add(Node::new("executable path not readable (protected system process or not enough rights: try an administrator terminal)").unknown());
        }
    }
    let ports = listeners(None, None).into_iter().filter(|l| l.pid == p.pid).collect::<Vec<_>>();
    if !ports.is_empty() {
        n.add(Node::new(format!("listens on: {}", ports.iter().map(|x| format!("{} {}", x.proto, x.addr)).collect::<Vec<_>>().join(", "))).proof("netstat -ano"));
    }
    n.children.extend(describe::details(p, None));
    let kids = proc::children(p.pid);
    if !kids.is_empty() {
        let l = kids.iter().take(8).map(|k| format!("{} ({})", k.name, k.pid)).collect::<Vec<_>>().join(", ");
        n.add(Node::new(format!("child processes: {l}{}", if kids.len() > 8 { format!(", +{} more", kids.len() - 8) } else { String::new() })).proof("processes whose parent is this one"));
    }
    n
}

pub fn complete() -> String {
    let mut v: Vec<String> = proc::all().into_iter().map(|p| p.name.trim_end_matches(".exe").to_string()).collect();
    v.sort();
    v.dedup();
    v.iter().map(|n| format!("{n}\n")).collect()
}
