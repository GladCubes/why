//! `why package <name>`: why a package is installed (who asked for it, who needs it, when) and, inside a project, why it is a dependency.
use super::pkg::{self, on_path, Manager};
use crate::graph::Node;
use crate::util::{run, short};
use std::fs;
use std::path::Path;

pub fn explain(name: &str) -> Node {
    let mut root = Node::new(format!("PACKAGE {name}"));
    let mut found = false;
    match pkg::detect() {
        Some(m) => found |= system(&mut root, m, name),
        None => {
            root.add(Node::new("no known system package manager (dpkg, pacman, rpm, apk) on this machine").unknown());
        }
    }
    found |= project(&mut root, name);
    if !found {
        root.add(Node::new("not installed on the system and not a dependency of the project in this directory").unknown().proof("checked the package manager and the lock files here"));
    }
    root
}

fn field(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| l.strip_prefix(key)?.trim_start().strip_prefix(':').map(|v| v.trim().to_string()))
}

fn names(v: Option<String>) -> Vec<String> {
    v.filter(|v| v != "None").map(|v| v.split_whitespace().map(|x| x.split(['>', '<', '=']).next().unwrap_or(x).to_string()).collect()).unwrap_or_default()
}

fn system(root: &mut Node, m: Manager, name: &str) -> bool {
    match m {
        Manager::Pacman => pacman(root, name),
        Manager::Dpkg => dpkg(root, name),
        Manager::Rpm => rpm(root, name),
        Manager::Apk => apk(root, name),
    }
}

fn list_node(label: &str, items: Vec<String>, proof: &str) -> Option<Node> {
    (!items.is_empty()).then(|| Node::new(format!("{label} ({}): {}", items.len(), short(&items.join(", "), 160))).proof(proof.to_string()))
}

fn pacman(root: &mut Node, name: &str) -> bool {
    let Some(info) = run("pacman", &["-Qi", name]) else {
        if let Some(s) = run("pacman", &["-Si", name]) {
            root.add(Node::new(format!("not installed; available in repository {}", field(&s, "Repository").unwrap_or_default())).proof("pacman -Si"));
        }
        return false;
    };
    root.add(Node::new(format!("installed: {} ({})", field(&info, "Version").unwrap_or_default(), field(&info, "Install Date").unwrap_or_default())).proof("pacman -Qi"));
    let reason = field(&info, "Install Reason").unwrap_or_default();
    let req = names(field(&info, "Required By"));
    let explicit = reason.contains("Explicitly");
    let mut why = Node::new(if explicit { "installed on purpose (you or a script asked for it by name)".to_string() } else { "installed only as a dependency".to_string() }).proof(format!("Install Reason: {reason}"));
    if !explicit && req.is_empty() && info.contains("Required By") {
        why.add(Node::new("nothing requires it any more: an orphan, safe to remove with `pacman -Rns`").probable());
    }
    root.add(why);
    root.children.extend(list_node("required by", req, "pacman -Qi: Required By"));
    root.children.extend(list_node("optional for", names(field(&info, "Optional For")), "pacman -Qi: Optional For"));
    root.children.extend(list_node("depends on", names(field(&info, "Depends On")), "pacman -Qi: Depends On"));
    if let Ok(log) = fs::read_to_string("/var/log/pacman.log") {
        let key = format!("] installed {name} (");
        if let Some(l) = log.lines().find(|l| l.contains(&key)) {
            root.add(Node::new(format!("first installed: {}", l.split(']').next().unwrap_or("").trim_start_matches('['))).proof("/var/log/pacman.log"));
        }
    }
    true
}

fn dpkg(root: &mut Node, name: &str) -> bool {
    let Some(st) = run("dpkg-query", &["-W", "-f", "${db:Status-Abbrev}|${Version}|${Depends}", name]).filter(|s| s.starts_with("ii")) else {
        return false;
    };
    let f: Vec<&str> = st.split('|').collect();
    root.add(Node::new(format!("installed: {}", f.get(1).unwrap_or(&""))).proof("dpkg-query"));
    let manual = run("apt-mark", &["showmanual", name]).is_some_and(|o| o.lines().any(|l| l.trim() == name));
    let mut why = Node::new(if manual { "installed on purpose (marked manual)".to_string() } else { "installed automatically, as a dependency".to_string() }).proof("apt-mark showmanual");
    let rdeps: Vec<String> = run("apt-cache", &["rdepends", "--installed", "--no-recommends", "--no-suggests", name])
        .map(|o| o.lines().skip_while(|l| !l.starts_with("Reverse Depends")).skip(1).map(|l| l.trim().trim_start_matches('|').to_string()).filter(|l| !l.is_empty()).collect())
        .unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    let rdeps: Vec<String> = rdeps.into_iter().map(|r| r.split(':').next().unwrap_or(&r).to_string()).filter(|r| seen.insert(r.clone())).collect();
    if !manual && rdeps.is_empty() {
        why.add(Node::new("nothing installed depends on it: removable with `apt autoremove`").probable());
    }
    root.add(why);
    root.children.extend(list_node("needed by installed packages", rdeps, "apt-cache rdepends --installed"));
    let deps: Vec<String> = f.get(2).map(|d| d.split(',').map(|x| x.split_whitespace().next().unwrap_or("").to_string()).filter(|x| !x.is_empty()).collect()).unwrap_or_default();
    root.children.extend(list_node("depends on", deps, "dpkg-query: Depends"));
    if let Some(h) = apt_history(name) {
        root.add(h);
    }
    true
}

/// The apt history entry that installed the package: when, with which command, asked by whom.
fn apt_history(name: &str) -> Option<Node> {
    let log = fs::read_to_string("/var/log/apt/history.log").ok()?;
    let block = log.split("\n\n").find(|b| b.lines().any(|l| l.starts_with("Install:") && l.split(|c: char| c == ',' || c == ' ').any(|w| w.split(':').next() == Some(name))))?;
    let get = |k: &str| block.lines().find_map(|l| l.strip_prefix(k)).map(|v| v.trim().to_string());
    let auto = block.lines().find(|l| l.starts_with("Install:")).is_some_and(|l| l.contains(&format!("{name}:")) && l.split(&format!("{name}:")).nth(1).is_some_and(|r| r.split(')').next().unwrap_or("").contains("automatic")));
    let mut n = Node::new(format!("installed {} by `{}`", get("Start-Date:").unwrap_or_default(), short(&get("Commandline:").unwrap_or_default(), 100))).proof("/var/log/apt/history.log");
    if let Some(u) = get("Requested-By:") {
        n.add(Node::new(format!("requested by {u}")));
    }
    if auto {
        n.add(Node::new("it was pulled in automatically by that command").probable());
    }
    Some(n)
}

fn rpm(root: &mut Node, name: &str) -> bool {
    let Some(info) = run("rpm", &["-qi", name]) else { return false };
    root.add(Node::new(format!("installed: {}-{} ({})", field(&info, "Version").unwrap_or_default(), field(&info, "Release").unwrap_or_default(), field(&info, "Install Date").unwrap_or_default())).proof("rpm -qi"));
    let req: Vec<String> = run("rpm", &["-q", "--whatrequires", name]).map(|o| o.lines().filter(|l| !l.contains("no package requires")).map(String::from).collect()).unwrap_or_default();
    if req.is_empty() {
        root.add(Node::new("nothing installed requires it").probable().proof("rpm -q --whatrequires"));
    }
    root.children.extend(list_node("required by", req, "rpm -q --whatrequires"));
    true
}

fn apk(root: &mut Node, name: &str) -> bool {
    if run("apk", &["info", "-e", name]).is_none() {
        return false;
    }
    let world = fs::read_to_string("/etc/apk/world").unwrap_or_default().lines().any(|l| l.trim() == name);
    root.add(Node::new(if world { "installed on purpose (listed in /etc/apk/world)" } else { "installed only as a dependency (not in /etc/apk/world)" }).proof("/etc/apk/world"));
    let req: Vec<String> = run("apk", &["info", "-r", name]).map(|o| o.lines().skip(1).map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()).unwrap_or_default();
    root.children.extend(list_node("required by", req, "apk info -r"));
    true
}

/// The package as a dependency of the project in the current directory (npm, cargo, pip, dotnet).
fn project(root: &mut Node, name: &str) -> bool {
    let mut found = false;
    let mut add = |tool: &str, out: Option<String>, proof: &str| {
        if let Some(o) = out.filter(|o| !o.trim().is_empty()) {
            let mut n = Node::new(format!("dependency in this project ({tool})")).proof(proof.to_string());
            for l in o.lines().take(14) {
                n.add(Node::new(short(l.trim_end(), 130)));
            }
            root.add(n);
            found = true;
        }
    };
    if Path::new("package-lock.json").exists() && on_path("npm") {
        add("npm", run("npm", &["explain", name]), "npm explain");
    }
    if Path::new("Cargo.lock").exists() && on_path("cargo") {
        add("cargo", run("cargo", &["tree", "--offline", "-i", name]), "cargo tree -i");
    }
    if (Path::new("requirements.txt").exists() || Path::new("pyproject.toml").exists()) && on_path("pip") {
        add("pip", run("pip", &["show", name]).map(|s| format!("{}\n{}", field(&s, "Version").map(|v| format!("version {v}")).unwrap_or_default(), field(&s, "Required-by").map(|r| format!("required by: {r}")).unwrap_or_default())), "pip show");
    }
    if on_path("dotnet") {
        if let Some(proj) = fs::read_dir(".").ok().and_then(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).find(|n| n.ends_with(".csproj") || n.ends_with(".sln"))) {
            add("dotnet", run("dotnet", &["nuget", "why", &proj, name]), "dotnet nuget why (needs the .NET 10 SDK)");
        }
    }
    found
}

/// Names for shell completion: installed packages.
pub fn complete() -> String {
    pkg::installed().into_iter().map(|(n, _)| format!("{n}\n")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_pacman_fields() {
        let info = "Name            : openssl\nVersion         : 3.5.0-1\nInstall Reason  : Installed as a dependency for another package\nRequired By     : curl  git  python\nOptional For    : None\n";
        assert_eq!(field(info, "Version").as_deref(), Some("3.5.0-1"));
        assert_eq!(names(field(info, "Required By")), vec!["curl", "git", "python"]);
        assert!(names(field(info, "Optional For")).is_empty());
        assert_eq!(names(Some("glibc>=2.40  zlib".into())), vec!["glibc", "zlib"]);
    }
}
