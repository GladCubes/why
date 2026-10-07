//! `why env NAME`: where a variable is defined (shell files, system, .env, compose) and which value it has now.
use crate::graph::Node;
use crate::util::{home, short};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// `(name, value)` if the line defines a variable (shell, fish, systemd, .env, yaml).
pub fn parse_def(line: &str) -> Option<(String, String)> {
    let mut l = line.trim();
    if l.starts_with('#') {
        return None;
    }
    for p in ["export ", "declare -x ", "set -gx ", "set -Ux ", "set -x ", "set -g ", "set -U ", "- ", "Environment=", "SETUVAR "] {
        if let Some(r) = l.strip_prefix(p) {
            l = r.trim_start();
            break;
        }
    }
    let l = l.trim_matches('"');
    let end = l.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(l.len());
    let (name, rest) = l.split_at(end);
    if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    // NAME=value (shell, .env, systemd), NAME: value (yaml, fish_variables), NAME value (fish)
    let v = rest.strip_prefix('=').or_else(|| rest.strip_prefix(':')).or_else(|| rest.strip_prefix(' '))?;
    Some((name.to_string(), v.trim().trim_matches(|c| c == '"' || c == '\'').to_string()))
}

fn secret(name: &str) -> bool {
    let n = name.to_uppercase();
    ["KEY", "TOKEN", "SECRET", "PASS", "PWD", "AUTH"].iter().any(|k| n.contains(k))
}

/// Sensitive values never reach the screen: two characters and the length; in URLs only the password is hidden.
fn show(name: &str, v: &str) -> String {
    if secret(name) && !v.is_empty() {
        return format!("{}… ({} characters, hidden)", v.chars().take(2).collect::<String>(), v.chars().count());
    }
    if let (Some(s), Some(at)) = (v.find("://"), v.rfind('@')) {
        if let Some(c) = v[s + 3..at].find(':') {
            return short(&format!("{}***{}", &v[..s + 3 + c + 1], &v[at..]), 100);
        }
    }
    short(v, 100)
}

fn shell_files() -> Vec<PathBuf> {
    let mut f: Vec<PathBuf> = ["/etc/environment", "/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshenv", "/etc/zsh/zprofile", "/etc/zsh/zshrc", "/etc/fish/config.fish"].map(PathBuf::from).to_vec();
    f.extend(list("/etc/profile.d", |n| n.ends_with(".sh")));
    if let Some(h) = home() {
        for n in [".profile", ".bash_profile", ".bashrc", ".zshenv", ".zprofile", ".zshrc", ".pam_environment", ".config/fish/config.fish", ".config/fish/fish_variables"] {
            f.push(h.join(n));
        }
        f.extend(list(&h.join(".config/fish/conf.d").to_string_lossy(), |n| n.ends_with(".fish")));
        f.extend(list(&h.join(".config/environment.d").to_string_lossy(), |n| n.ends_with(".conf")));
    }
    f
}

fn list(dir: &str, keep: impl Fn(&str) -> bool) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.file_name().is_some_and(|n| keep(&n.to_string_lossy()))).collect();
    v.sort();
    v
}

fn is_project_file(n: &str) -> bool {
    let compose = (n.starts_with("docker-compose") || n.starts_with("compose.")) && (n.ends_with(".yml") || n.ends_with(".yaml"));
    // backups and templates are not loaded by anything
    let spare = [".example", ".sample", ".orig", ".old", ".save", "~"].iter().any(|s| n.ends_with(s)) || n.contains(".bak");
    (n.starts_with(".env") && !spare) || compose
}

/// Skipped when walking down: huge or generated directories.
const SKIP: [&str; 6] = ["node_modules", ".git", "target", "venv", ".venv", "__pycache__"];

fn scan_dir(dir: &Path, depth: u8, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).into_iter().flatten().flatten().take(500) {
        let (path, n) = (e.path(), e.file_name().to_string_lossy().into_owned());
        if path.is_file() && is_project_file(&n) && !out.contains(&path) {
            out.push(path);
        } else if depth > 0 && path.is_dir() && !SKIP.contains(&n.as_str()) && !n.starts_with('.') {
            scan_dir(&path, depth - 1, out);
        }
    }
}

/// .env and compose files: in the current directory and two levels below it, then in every directory above it up to home.
fn project_files() -> Vec<PathBuf> {
    let mut out = vec![];
    let Ok(mut dir) = std::env::current_dir() else { return out };
    scan_dir(&dir, 2, &mut out);
    let stop = home();
    while Some(&dir) != stop.as_ref() && dir.pop() && dir != Path::new("/") {
        scan_dir(&dir, 0, &mut out);
    }
    out
}

const SHELL_NOTE: &str = "read when the shell starts or at login";
const PROJECT_NOTE: &str = "NOT read by the shell: only applies to programs that load it (dotenv, docker compose, ...)";

struct Def {
    note: &'static str,
    file: PathBuf,
    line: usize,
    name: String,
    value: String,
}

/// Every definition found in the known files (only `name` if given).
fn definitions(name: Option<&str>) -> Vec<Def> {
    let mut out = vec![];
    for (note, files) in [(SHELL_NOTE, shell_files()), (PROJECT_NOTE, project_files())] {
        for file in files {
            let Ok(text) = fs::read_to_string(&file) else { continue };
            for (i, l) in text.lines().enumerate() {
                let Some((n, value)) = parse_def(l) else { continue };
                // when listing, only names that look like environment variables (the rest is YAML noise)
                let keep = match name {
                    Some(w) => n == w,
                    None => n.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'),
                };
                if keep {
                    out.push(Def { note, file: file.clone(), line: i + 1, name: n, value });
                }
            }
        }
    }
    out
}

pub fn explain(name: &str) -> Node {
    let current = std::env::var(name).ok();
    let mut root = match &current {
        Some(v) => Node::new(format!("VARIABLE {name} = {}", show(name, v))).proof("environment of the `why` process, i.e. your shell's"),
        None => Node::new(format!("VARIABLE {name}: not set in the current environment")).proof("environment of the `why` process"),
    };
    let defs = definitions(Some(name));
    for note in [SHELL_NOTE, PROJECT_NOTE] {
        let mut g = Node::new(if note == SHELL_NOTE { "shell and system files" } else { "project files" });
        for d in defs.iter().filter(|d| d.note == note) {
            let same = current.as_deref() == Some(d.value.as_str());
            let label = format!("{}:{}  =  {}{}", d.file.display(), d.line, show(name, &d.value), if same { "   ← same value as the current environment" } else { "" });
            let n = g.add(Node::new(label).probable().proof(note));
            if !same && current.is_some() {
                n.add(Node::new("different value: overridden, not loaded, or redefined further down").probable());
            }
        }
        if !g.children.is_empty() {
            root.add(g);
        }
    }
    if defs.is_empty() {
        root.add(Node::new("no definition found in the files checked").unknown().proof("shell files, /etc, ~/.config/fish, .env and compose from here up to home"));
        if current.is_some() {
            root.add(Node::new("yet the variable exists: it comes from a program that started the shell (terminal, graphical session, systemd --user) or from a manual `export`").probable());
        }
    }
    root
}

/// name → (current value if set, where it appears)
fn all_names() -> BTreeMap<String, (Option<String>, Vec<String>)> {
    let mut m: BTreeMap<String, (Option<String>, Vec<String>)> = BTreeMap::new();
    for (k, v) in std::env::vars() {
        m.entry(k).or_default().0 = Some(v);
    }
    for d in definitions(None) {
        m.entry(d.name.clone()).or_default().1.push(format!("{}:{}", d.file.display(), d.line));
    }
    m
}

/// `why env list`: the variables defined in project files (.env, compose); with `all`, also the shell and the system.
pub fn list_all(all: bool) -> String {
    if !all {
        return list_project();
    }
    let mut out = format!("{:<32} {:<40} {}\n", "NAME", "VALUE", "DEFINED IN");
    for (name, (value, files)) in all_names() {
        let v = value.map(|v| show(&name, &v).replace('\n', " ")).unwrap_or_else(|| "(not set now)".into());
        let w = match files.len() {
            0 => "environment only".to_string(),
            1..=2 => files.join(", "),
            n => format!("{}, +{} more", files[..2].join(", "), n - 2),
        };
        out.push_str(&format!("{:<32} {:<40} {w}\n", short(&name, 31), short(&v, 39)));
    }
    out
}

fn project_names() -> BTreeMap<String, Vec<Def>> {
    let mut m: BTreeMap<String, Vec<Def>> = BTreeMap::new();
    for d in definitions(None).into_iter().filter(|d| d.note == PROJECT_NOTE) {
        m.entry(d.name.clone()).or_default().push(d);
    }
    m
}

fn list_project() -> String {
    let names = project_names();
    if names.is_empty() {
        return "No .env or docker-compose files found here (two levels down, and in the directories above up to your home).\nRun it inside a project, or use `why env list all` for the shell and system variables.\n".into();
    }
    let mut out = format!("{:<28} {:<38} {}\n", "NAME", "VALUE", "DEFINED IN");
    for (name, defs) in names {
        let differ = defs.iter().any(|d| d.value != defs[0].value);
        let places = defs.iter().map(|d| format!("{}:{}", d.file.display(), d.line)).collect::<Vec<_>>();
        let w = if places.len() > 2 { format!("{}, +{} more", places[..2].join(", "), places.len() - 2) } else { places.join(", ") };
        out.push_str(&format!("{:<28} {:<38} {w}{}\n", short(&name, 27), short(&show(&name, &defs[0].value), 37), if differ { "   ≠ values differ between files" } else { "" }));
    }
    out.push_str("\nProject files only. `why env list all` adds the shell and system environment.\n");
    out
}

/// Names for shell completion: the project's variables if there are any, otherwise everything.
pub fn complete() -> String {
    let project = project_names();
    if !project.is_empty() {
        return project.keys().map(|n| format!("{n}\tproject file\n")).collect();
    }
    all_names().into_iter().map(|(n, (v, f))| format!("{n}\t{}\n", if v.is_some() { "environment" } else if f.is_empty() { "" } else { "defined in files" })).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def(line: &str, name: &str) -> Option<String> {
        parse_def(line).filter(|d| d.0 == name).map(|d| d.1)
    }

    #[test]
    fn finds_definitions() {
        assert_eq!(def("export FOO=bar", "FOO").as_deref(), Some("bar"));
        assert_eq!(def("FOO=\"a b\"", "FOO").as_deref(), Some("a b"));
        assert_eq!(def("set -gx FOO bar", "FOO").as_deref(), Some("bar"));
        assert_eq!(def("    - FOO=bar", "FOO").as_deref(), Some("bar"));
        assert_eq!(def("  FOO: bar", "FOO").as_deref(), Some("bar"));
        assert_eq!(def("# export FOO=bar", "FOO"), None);
        assert_eq!(def("export FOOBAR=1", "FOO"), None);
    }

    #[test]
    fn hides_secrets() {
        assert!(show("API_TOKEN", "abcdef").contains("hidden"));
        assert_eq!(show("PORT", "3000"), "3000");
        assert_eq!(show("DATABASE_URL", "postgres://u:pw@localhost/db"), "postgres://u:***@localhost/db");
    }
}
