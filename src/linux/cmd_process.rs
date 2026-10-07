use super::process::{self, Proc};
use super::{describe, pkg, sockets};
use crate::graph::Node;
use crate::util::{ago, date, now, short};
use std::path::Path;

fn find(arg: &str) -> Vec<Proc> {
    if let Ok(pid) = arg.parse::<u32>() {
        return process::read(pid).into_iter().collect();
    }
    let base = |s: &str| Path::new(s).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let me = std::process::id();
    process::all()
        .into_iter()
        .filter(|p| p.pid != me && (p.name == arg || p.exe.as_deref().is_some_and(|e| base(&e.to_string_lossy()) == arg) || p.cmdline.first().is_some_and(|c| base(c) == arg)))
        .collect()
}

pub fn explain(arg: &str) -> Node {
    let found = find(arg);
    match found.as_slice() {
        [] => Node::new(format!("PROCESS {arg}: no running process matches")).unknown().proof("looked at the name, the executable and the first word of every readable command line"),
        [one] => tree(one),
        many => {
            let mut root = Node::new(format!("PROCESS {arg}: {} processes match", many.len())).proof("name, executable or command");
            for p in many.iter().take(5) {
                root.add(tree(p));
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
    let mut n = Node::new(format!("process {} (pid {}, user {})", p.name, p.pid, p.user)).proof(format!("/proc/{}", p.pid));
    if let Some(s) = p.started {
        n.add(Node::new(format!("running for {} (since {})", ago(now().saturating_sub(s)), date(s))).proof("start time in /proc/<pid>/stat"));
    }
    if let Some(exe) = &p.exe {
        let shown = exe.to_string_lossy().into_owned();
        let deleted = shown.ends_with(" (deleted)");
        let e = n.add(Node::new(format!("executable: {shown}")).proof(format!("/proc/{}/exe", p.pid)));
        if deleted {
            e.add(Node::new("the file was deleted or replaced after the process started: it is still running the old copy (normal after a package update, suspicious otherwise)").probable());
        } else {
            match pkg::owner_of(exe) {
                Some((tool, who)) => {
                    e.add(Node::new(format!("owned by package {who}")).proof(tool));
                }
                None if pkg::detect().is_some() => {
                    e.add(Node::new("not owned by any package: installed by hand, built locally or downloaded").probable().proof("package manager query"));
                }
                None => {}
            }
        }
    }
    let ports = sockets::of_pid(p.pid);
    if !ports.is_empty() {
        let l = ports.iter().map(|x| format!("{} {}", x.proto, x.addr)).collect::<Vec<_>>().join(", ");
        n.add(Node::new(format!("listens on: {l}")).proof("socket inodes in /proc/<pid>/fd matched against /proc/net/*"));
    }
    n.children.extend(describe::details(p, None));
    let kids = process::children(p.pid);
    if !kids.is_empty() {
        let l = kids.iter().take(8).map(|k| format!("{} ({})", k.name, k.pid)).collect::<Vec<_>>().join(", ");
        n.add(Node::new(format!("child processes: {l}{}", if kids.len() > 8 { format!(", +{} more", kids.len() - 8) } else { String::new() })).proof("processes whose parent is this one"));
    }
    if let Some(cmd) = p.cmdline.first().filter(|_| p.cmdline.len() == 1 && p.cmdline[0].len() > 120) {
        n.add(Node::new(format!("note: very long command ({} characters): {}", cmd.len(), short(cmd, 60))).probable());
    }
    n
}

pub fn complete() -> String {
    let mut v: Vec<String> = process::all().into_iter().map(|p| p.name).collect();
    v.sort();
    v.dedup();
    v.iter().map(|n| format!("{n}\n")).collect()
}

pub fn list() -> String {
    let mut all = process::all();
    all.sort_by_key(|p| p.pid);
    let mut out = format!("{:<8} {:<8} {:<14} {:<12} {:<22} {}\n", "PID", "PPID", "USER", "RUNNING", "NAME", "COMMAND");
    for p in all {
        let age = p.started.map(|s| ago(now().saturating_sub(s))).unwrap_or_default();
        let cmd = if p.cmdline.is_empty() { format!("[{}]", p.name) } else { short(&p.cmdline.join(" "), 70) };
        out.push_str(&format!("{:<8} {:<8} {:<14} {:<12} {:<22} {cmd}\n", p.pid, p.ppid, short(&p.user, 13), age, short(&p.name, 21)));
    }
    out
}
