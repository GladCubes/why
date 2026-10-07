//! Package managers: who owns a file, why a package is installed. Only reads, only through each tool's query commands.
use crate::util::{on_path, run};
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Manager {
    Dpkg,
    Pacman,
    Rpm,
    Apk,
}

pub fn detect() -> Option<Manager> {
    [("dpkg-query", Manager::Dpkg), ("pacman", Manager::Pacman), ("rpm", Manager::Rpm), ("apk", Manager::Apk)]
        .into_iter()
        .find(|(bin, _)| on_path(bin))
        .map(|(_, m)| m)
}

/// The package that owns `path`, with the tool that said so: `(tool, "pkg version")`.
pub fn owner_of(path: &Path) -> Option<(&'static str, String)> {
    let real = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let p = real.to_string_lossy();
    match detect()? {
        Manager::Dpkg => {
            // "coreutils: /usr/bin/ls"
            let out = run("dpkg", &["-S", &p])?;
            let pkg = out.lines().next()?.split(':').next()?.trim().to_string();
            let ver = run("dpkg-query", &["-W", "-f", "${Version}", &pkg]).unwrap_or_default();
            Some(("dpkg -S", format!("{pkg} {ver}").trim().to_string()))
        }
        Manager::Pacman => {
            // "/usr/bin/ls is owned by coreutils 9.5-1"
            let out = run("pacman", &["-Qoq", &p])?;
            let pkg = out.lines().next()?.trim().to_string();
            let ver = run("pacman", &["-Q", &pkg]).and_then(|s| s.split_whitespace().nth(1).map(String::from)).unwrap_or_default();
            Some(("pacman -Qo", format!("{pkg} {ver}").trim().to_string()))
        }
        Manager::Rpm => Some(("rpm -qf", run("rpm", &["-qf", &p])?.lines().next()?.trim().to_string())),
        Manager::Apk => {
            // "/bin/ls resolves to a symlink... " / "<path> is owned by busybox-1.36"
            let out = run("apk", &["info", "-W", &p])?;
            Some(("apk info -W", out.lines().find(|l| l.contains("owned by"))?.rsplit("owned by ").next()?.trim().to_string()))
        }
    }
}

/// Every installed package as `(name, version)`.
pub fn installed() -> Vec<(String, String)> {
    let (cmd, args): (&str, &[&str]) = match detect() {
        Some(Manager::Dpkg) => ("dpkg-query", &["-W", "-f", "${Package}\t${Version}\n"]),
        Some(Manager::Pacman) => ("pacman", &["-Q"]),
        Some(Manager::Rpm) => ("rpm", &["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"]),
        Some(Manager::Apk) => ("apk", &["info", "-v"]),
        None => return vec![],
    };
    run(cmd, args)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let (n, v) = l.split_once(['\t', ' ']).or_else(|| l.rsplit_once('-'))?;
            Some((n.to_string(), v.trim().to_string()))
        })
        .collect()
}
