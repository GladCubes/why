use crate::graph::Node;
use crate::util::home;
use std::fs;
use std::path::{Path, PathBuf};

fn list(dir: &str, keep: impl Fn(&str) -> bool) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.file_name().is_some_and(|n| keep(&n.to_string_lossy()))).collect();
    v.sort();
    v
}

pub fn shell_files() -> Vec<PathBuf> {
    let mut f: Vec<PathBuf> = ["/etc/environment", "/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshenv", "/etc/zsh/zprofile", "/etc/zsh/zshrc", "/etc/fish/config.fish"].map(PathBuf::from).to_vec();
    f.extend(list("/etc/profile.d", |n| n.ends_with(".sh")));
    f.extend(list("/etc/environment.d", |n| n.ends_with(".conf")));
    f.extend(list("/usr/lib/environment.d", |n| n.ends_with(".conf")));
    if let Some(h) = home() {
        for n in [".profile", ".bash_profile", ".bashrc", ".zshenv", ".zprofile", ".zshrc", ".pam_environment", ".config/fish/config.fish", ".config/fish/fish_variables"] {
            f.push(h.join(n));
        }
        f.extend(list(&h.join(".config/fish/conf.d").to_string_lossy(), |n| n.ends_with(".fish")));
        f.extend(list(&h.join(".config/environment.d").to_string_lossy(), |n| n.ends_with(".conf")));
    }
    f
}

pub fn wide_roots() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = ["/opt", "/srv", "/var/www", "/root"].map(PathBuf::from).to_vec();
    roots.extend(fs::read_dir("/home").into_iter().flatten().flatten().map(|e| e.path()));
    roots
}

pub fn service_env_files() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = vec![];
    for e in fs::read_dir("/etc/systemd/system").into_iter().flatten().flatten() {
        let (path, n) = (e.path(), e.file_name().to_string_lossy().into_owned());
        let mut units = vec![];
        if n.ends_with(".service") && path.is_file() {
            units.push(path.clone());
        }
        if n.ends_with(".service.d") {
            units.extend(fs::read_dir(&path).into_iter().flatten().flatten().map(|x| x.path()));
        }
        for u in units {
            for l in fs::read_to_string(&u).unwrap_or_default().lines() {
                if let Some(f) = l.trim().strip_prefix("EnvironmentFile=") {
                    out.push(PathBuf::from(f.trim_start_matches('-')));
                }
            }
            out.push(u);
        }
    }
    out
}

pub fn service_consumers(dir: &Path, file: &Path) -> Vec<Node> {
    let mut out: Vec<Node> = vec![];
    for e in fs::read_dir("/etc/systemd/system").into_iter().flatten().flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if !n.ends_with(".service") {
            continue;
        }
        let text = fs::read_to_string(e.path()).unwrap_or_default();
        let hit = text.lines().map(str::trim).find(|l| {
            (l.starts_with("WorkingDirectory=") || l.starts_with("ExecStart=")) && l.contains(dir.to_string_lossy().as_ref())
                || l.strip_prefix("EnvironmentFile=").is_some_and(|f| Path::new(f.trim_start_matches('-')) == file)
        });
        if let Some(l) = hit {
            out.push(Node::new(format!("systemd service {n} points at it: {l}")).proof(e.path().display().to_string()));
        }
    }
    out
}

pub fn environ_value(pid: u32, name: &str) -> Option<String> {
    let raw = fs::read(format!("/proc/{pid}/environ")).ok()?;
    let key = format!("{name}=");
    raw.split(|b| *b == 0).find_map(|e| String::from_utf8_lossy(e).strip_prefix(&key).map(String::from))
}

pub fn extra_env(_name: &str) -> Vec<Node> {
    vec![]
}

pub fn extra_env_names() -> Vec<(String, String)> {
    vec![]
}
