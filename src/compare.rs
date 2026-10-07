//! `why compare A B`: what differs between two machines (or two saved snapshots), grouped by kind.
//! A snapshot is plain text, one `key<TAB>value` per line; keys look like `tool/node`, `env/PORT`, `port/tcp/7777`, `pkg/openssl`.
use crate::graph::Node;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

pub type Snapshot = BTreeMap<String, String>;

pub fn serialize(s: &Snapshot) -> String {
    let mut out = String::from("# why-snapshot 1\n");
    for (k, v) in s {
        out.push_str(&format!("{k}\t{}\n", v.replace(['\n', '\t'], " ")));
    }
    out
}

pub fn parse(text: &str) -> Snapshot {
    text.lines().filter(|l| !l.starts_with('#')).filter_map(|l| l.split_once('\t')).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// A snapshot from a file, from this machine (`local`), or from another one over ssh (`why snapshot` must be installed there).
pub fn fetch(arg: &str, local: impl Fn() -> Snapshot) -> Result<Snapshot, String> {
    if arg == "local" || arg == "." {
        return Ok(local());
    }
    if Path::new(arg).is_file() {
        return std::fs::read_to_string(arg).map(|t| parse(&t)).map_err(|e| format!("{arg}: {e}"));
    }
    if arg.starts_with('-') {
        return Err(format!("`{arg}` is not a file or a host"));
    }
    let out = Command::new("ssh").args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", arg, "why", "snapshot"]).output().map_err(|e| format!("cannot run ssh: {e}"))?;
    if !out.status.success() {
        return Err(format!("{arg}: ssh failed or `why` is not installed there ({})", String::from_utf8_lossy(&out.stderr).trim().lines().last().unwrap_or("no details")));
    }
    let s = parse(&String::from_utf8_lossy(&out.stdout));
    if s.is_empty() { Err(format!("{arg}: no snapshot came back")) } else { Ok(s) }
}

fn name_of(s: &Snapshot, arg: &str) -> String {
    match s.get("meta/hostname") {
        Some(h) if h != arg => format!("{arg} ({h})"),
        _ => arg.to_string(),
    }
}

const TITLES: [(&str, &str); 8] = [
    ("meta", "system"),
    ("tool", "tools and versions"),
    ("env", "environment variables"),
    ("port", "listening ports"),
    ("service", "services"),
    ("container", "containers"),
    ("pkg", "packages"),
    ("net", "network"),
];

pub fn compare(a: &Snapshot, an: &str, b: &Snapshot, bn: &str) -> Node {
    let (an, bn) = (name_of(a, an), name_of(b, bn));
    let mut root = Node::new(format!("WHY DOES IT WORK ON {an} BUT NOT ON {bn}?")).proof("A = first argument, B = second");
    let keys: BTreeSet<&String> = a.keys().chain(b.keys()).filter(|k| k.as_str() != "meta/hostname").collect();
    let (mut diffs, mut same_total) = (0, 0);
    for (prefix, title) in TITLES {
        let mine: Vec<&&String> = keys.iter().filter(|k| k.split('/').next() == Some(prefix)).collect();
        let (mut g, mut same) = (Node::new(title.to_string()), 0);
        let max = if prefix == "pkg" { 25 } else { 40 };
        // (priority, line): a value that differs on both sides matters more than something present on one side only
        let mut lines: Vec<(u8, String)> = vec![];
        for k in mine {
            let name = k.split_once('/').map(|x| x.1).unwrap_or(k);
            let short = |s: &String, n| crate::util::short(s, n);
            match (a.get(k.as_str()), b.get(k.as_str())) {
                (Some(x), Some(y)) if x == y => same += 1,
                (Some(x), Some(y)) => lines.push((0, format!("{name}:   A = {}   B = {}", short(x, 60), short(y, 60)))),
                (Some(x), None) => lines.push((1, format!("{name}:   only on A ({})", short(x, 50)))),
                (None, Some(y)) => lines.push((1, format!("{name}:   only on B ({})", short(y, 50)))),
                (None, None) => {}
            }
        }
        lines.sort_by_key(|l| l.0);
        diffs += lines.len();
        for (_, l) in lines.iter().take(max) {
            g.add(Node::new(l.clone()).probable().proof("different"));
        }
        if lines.len() > max {
            g.add(Node::new(format!("... and {} more differences in this group", lines.len() - max)).unknown());
        }
        same_total += same;
        if !g.children.is_empty() {
            g.proof = Some(format!("{same} identical"));
            root.add(g);
        }
    }
    if diffs == 0 {
        root.add(Node::new("no differences found in what I compare").proof(format!("{same_total} items identical")));
    } else {
        root.add(Node::new(format!("everything else is identical ({same_total} items)")));
    }
    root.add(Node::new("I compare tools, environment, ports, services, containers and packages: a difference outside these (a file's contents, a firewall, DNS) is not visible here").unknown());
    root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(items: &[(&str, &str)]) -> Snapshot {
        items.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn reports_only_differences() {
        let a = snap(&[("tool/node", "v24"), ("env/HOME", "/a"), ("port/tcp/80", "nginx"), ("pkg/openssl", "3.5")]);
        let b = snap(&[("tool/node", "v22"), ("env/HOME", "/a"), ("pkg/openssl", "3.4"), ("pkg/curl", "8")]);
        let t = compare(&a, "A", &b, "B");
        let text: Vec<String> = t.children.iter().flat_map(|g| g.children.iter().map(|c| c.label.clone())).collect();
        assert!(text.iter().any(|l| l.contains("node") && l.contains("v24") && l.contains("v22")));
        assert!(text.iter().any(|l| l.contains("80") && l.contains("only on A")));
        assert!(text.iter().any(|l| l.contains("curl") && l.contains("only on B")));
        assert!(!text.iter().any(|l| l.contains("HOME")));
    }

    #[test]
    fn round_trips() {
        let a = snap(&[("tool/git", "2.4"), ("env/X", "a b")]);
        assert_eq!(parse(&serialize(&a)), a);
    }
}
