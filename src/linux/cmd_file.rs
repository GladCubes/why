//! `why file <path>`: where a file comes from and what uses it: package, owner, who has it open or loaded, which units and cron jobs name it.
use super::{pkg, process};
use crate::graph::Node;
use crate::util::{ago, date, group_name, now, short, user_name};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

pub fn explain(arg: &str) -> Node {
    let path = PathBuf::from(arg);
    let Ok(meta) = fs::symlink_metadata(&path) else {
        return deleted_but_open(&path).unwrap_or_else(|| Node::new(format!("FILE {arg}: does not exist")).unknown().proof("lstat failed"));
    };
    let real = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
    let mut root = Node::new(format!("FILE {}", path.display())).proof(kind(&meta));
    if meta.file_type().is_symlink() {
        let t = fs::read_link(&path).map(|t| t.display().to_string()).unwrap_or_default();
        let r = root.add(Node::new(format!("symbolic link to {t}")).proof("readlink"));
        if real != path {
            r.add(Node::new(format!("which resolves to {}", real.display())));
        }
    }
    let m = fs::metadata(&real).unwrap_or(meta.clone());
    root.add(Node::new(format!("owner {}:{} mode {:04o}, {} bytes", user_name(m.uid()), group_name(m.gid()), m.mode() & 0o7777, m.len())).proof("stat"));
    let mut when = format!("modified {} ago ({})", ago(now().saturating_sub(m.mtime() as u64)), date(m.mtime() as u64));
    if let Ok(c) = m.created() {
        let c = c.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        when.push_str(&format!(", created {}", date(c)));
    }
    root.add(Node::new(when).proof("stat"));
    if let Some(mt) = mount_of(&real) {
        root.add(Node::new(format!("on {mt}")).proof("/proc/self/mountinfo"));
    }
    root.add(owner_node(&real, &m));
    if m.is_dir() {
        let users: Vec<_> = process::all().into_iter().filter(|p| p.cwd.as_deref().is_some_and(|c| c.starts_with(&real))).collect();
        if !users.is_empty() {
            let l = users.iter().take(8).map(|p| format!("{} ({})", p.name, p.pid)).collect::<Vec<_>>().join(", ");
            root.add(Node::new(format!("working directory of: {l}")).proof("/proc/<pid>/cwd"));
        }
    } else {
        root.children.extend(users_nodes(&real));
    }
    root.children.extend(references(&real));
    root
}

fn kind(m: &fs::Metadata) -> &'static str {
    let t = m.file_type();
    if t.is_symlink() { "symbolic link" } else if t.is_dir() { "directory" } else if t.is_socket() { "socket" } else if t.is_fifo() { "named pipe" } else if t.is_block_device() || t.is_char_device() { "device" } else if m.mode() & 0o111 != 0 { "executable file" } else { "regular file" }
}

/// A file that was deleted but a process still holds open (the classic "disk is full but I deleted it").
fn deleted_but_open(path: &Path) -> Option<Node> {
    let want = format!("{} (deleted)", path.display());
    let holders: Vec<String> = process::all()
        .into_iter()
        .filter(|p| fs::read_dir(format!("/proc/{}/fd", p.pid)).into_iter().flatten().flatten().any(|fd| fs::read_link(fd.path()).is_ok_and(|t| t.to_string_lossy() == want)))
        .map(|p| format!("{} ({})", p.name, p.pid))
        .collect();
    (!holders.is_empty()).then(|| {
        let mut n = Node::new(format!("FILE {}: deleted, but still open", path.display())).proof("/proc/<pid>/fd links marked (deleted)");
        n.add(Node::new(format!("held open by: {}", holders.join(", "))).proof("its disk space is only freed when they close it or exit"));
        n
    })
}

fn mount_of(path: &Path) -> Option<String> {
    let info = fs::read_to_string("/proc/self/mountinfo").ok()?;
    info.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let dash = f.iter().position(|x| *x == "-")?;
            let mp = f.get(4)?.replace("\\040", " ");
            path.starts_with(&mp).then(|| (mp.len(), format!("{} ({}, mounted at {mp})", f.get(dash + 2).unwrap_or(&"?"), f.get(dash + 1).unwrap_or(&"?"))))
        })
        .max_by_key(|(len, _)| *len)
        .map(|(_, s)| s)
}

fn owner_node(real: &Path, m: &fs::Metadata) -> Node {
    if m.is_dir() {
        return Node::new("directory: ownership by package not checked").unknown();
    }
    match pkg::owner_of(real) {
        Some((tool, who)) => Node::new(format!("belongs to package {who}")).proof(tool),
        None if pkg::detect().is_some() => Node::new("not owned by any package: created locally, by a program, or installed by hand").probable().proof("package manager query"),
        None => Node::new("no known package manager on this system").unknown(),
    }
}

/// Who runs it, has it open, or has it loaded as a library.
fn users_nodes(real: &Path) -> Vec<Node> {
    let target = real.to_string_lossy().into_owned();
    let (mut running, mut open, mut mapped): (Vec<String>, Vec<String>, Vec<String>) = (vec![], vec![], vec![]);
    let mut unreadable = 0;
    for p in process::all() {
        let tag = format!("{} ({})", p.name, p.pid);
        if p.exe.as_deref() == Some(real) {
            running.push(tag.clone());
        }
        match fs::read_dir(format!("/proc/{}/fd", p.pid)) {
            Ok(fds) => {
                if fds.flatten().any(|fd| fs::read_link(fd.path()).is_ok_and(|t| t == real)) {
                    open.push(tag.clone());
                }
            }
            Err(_) => unreadable += 1,
        }
        if fs::read_to_string(format!("/proc/{}/maps", p.pid)).is_ok_and(|m| m.lines().any(|l| l.ends_with(&target))) && !running.contains(&tag) {
            mapped.push(tag);
        }
    }
    let mut out = vec![];
    for (label, v, proof) in [("being run by", running, "/proc/<pid>/exe"), ("open by", open, "/proc/<pid>/fd"), ("loaded as a library or mapped by", mapped, "/proc/<pid>/maps")] {
        if !v.is_empty() {
            out.push(Node::new(format!("{label}: {}", v.iter().take(8).cloned().collect::<Vec<_>>().join(", "))).proof(proof));
        }
    }
    if out.is_empty() {
        out.push(Node::new("not in use by any process I can read").proof(if unreadable > 0 { format!("{unreadable} processes unreadable: use sudo to see them all") } else { "all processes checked".into() }));
    }
    out
}

/// Units and cron jobs that name the file.
fn references(real: &Path) -> Vec<Node> {
    let needle = real.to_string_lossy().into_owned();
    let mut n = Node::new("named by");
    let mut files: Vec<PathBuf> = vec![];
    for d in ["/etc/systemd/system", "/usr/lib/systemd/system", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/var/spool/cron/crontabs", "/var/spool/cron", "/etc/ld.so.conf.d", "/etc/profile.d"] {
        for e in fs::read_dir(d).into_iter().flatten().flatten().take(2000) {
            let p = e.path();
            if p.is_dir() {
                files.extend(fs::read_dir(&p).into_iter().flatten().flatten().map(|x| x.path()));
            } else {
                files.push(p);
            }
        }
    }
    files.extend(["/etc/crontab", "/etc/rc.local", "/etc/fstab"].map(PathBuf::from));
    for f in files {
        let Ok(text) = fs::read_to_string(&f) else { continue };
        if let Some((i, l)) = text.lines().enumerate().find(|(_, l)| !l.trim_start().starts_with('#') && l.contains(&needle)) {
            n.add(Node::new(format!("{}:{}: {}", f.display(), i + 1, short(l.trim(), 110))).probable().proof("text match"));
        }
    }
    if n.children.is_empty() { vec![] } else { vec![n] }
}

/// Completion is the shell's own file completion.
pub fn complete() -> String {
    String::new()
}
