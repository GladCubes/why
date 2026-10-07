//! Windows specifics for `why env`: PowerShell profiles, directories to search, and the registry layers (user and machine).
use super::ps::{ps, q, rows};
use crate::graph::Node;
use crate::util::{home, short};
use std::path::{Path, PathBuf};

pub fn shell_files() -> Vec<PathBuf> {
    let mut f: Vec<PathBuf> = vec![PathBuf::from(r"C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1")];
    if let Some(h) = home() {
        for n in [r"Documents\WindowsPowerShell\profile.ps1", r"Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1", r"Documents\PowerShell\profile.ps1", r"Documents\PowerShell\Microsoft.PowerShell_profile.ps1", ".bashrc", ".bash_profile", ".profile"] {
            f.push(h.join(n));
        }
    }
    f
}

pub fn wide_roots() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = [r"C:\inetpub", r"C:\ProgramData", r"C:\Projects", r"C:\src", r"C:\dev", r"C:\git", r"C:\repos", r"C:\www"].map(PathBuf::from).to_vec();
    roots.extend(std::fs::read_dir(r"C:\Users").into_iter().flatten().flatten().map(|e| e.path()));
    roots
}

pub fn service_env_files() -> Vec<PathBuf> {
    vec![]
}

/// Windows services whose command line points into the file's folder.
pub fn service_consumers(dir: &Path, _file: &Path) -> Vec<Node> {
    let d = dir.to_string_lossy().into_owned();
    let out = ps(&format!(r#"$d={}; Get-CimInstance Win32_Service | ? {{ $_.PathName -like "*$d*" }} | % {{ "svc`t$($_.Name)`t$($_.State)`t$($_.PathName)" }}"#, q(&d))).unwrap_or_default();
    rows(&out).into_iter().filter(|r| r.len() >= 4).map(|r| Node::new(format!("Windows service {} ({}) runs from there: {}", r[1], r[2], short(&r[3], 100))).proof("WMI Win32_Service.PathName")).collect()
}

pub fn environ_value(_pid: u32, _name: &str) -> Option<String> {
    None
}

/// The two persistent layers Windows builds every process's environment from.
pub fn extra_env(name: &str) -> Vec<Node> {
    let n = q(name);
    let out = ps(&format!(r#"$u=[Environment]::GetEnvironmentVariable({n},'User'); $m=[Environment]::GetEnvironmentVariable({n},'Machine'); if($u -ne $null){{ "user`t$u" }}; if($m -ne $null){{ "machine`t$m" }}"#)).unwrap_or_default();
    let current = std::env::var(name).ok();
    let mut g = Node::new("Windows environment (registry)").proof("a process starts with the machine values, then the user values on top (PATH is joined)");
    for r in rows(&out).iter().filter(|r| r.len() >= 2) {
        let (key, label) = if r[0] == "user" { (r"HKCU\Environment", "user") } else { (r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment", "machine") };
        // PATH-like variables are joined from both layers: the current value just has to contain each part
        let joined = name.eq_ignore_ascii_case("path") || name.eq_ignore_ascii_case("pathext") || name.eq_ignore_ascii_case("psmodulepath");
        let same = current.as_deref() == Some(r[1].as_str()) || (joined && current.as_deref().is_some_and(|c| c.to_lowercase().contains(&r[1].trim_end_matches(';').to_lowercase())));
        let mut x = Node::new(format!("{label} value = {}{}", crate::env::show(name, &r[1]), if same { if joined { "   ← included in the current value" } else { "   ← same as the current environment" } } else { "" })).proof(key);
        if !same && current.is_some() {
            x.add(Node::new("different from the current environment: the program was started before the change, or something overrides it").probable());
        }
        g.add(x);
    }
    if g.children.is_empty() { vec![] } else { vec![g] }
}

pub fn extra_env_names() -> Vec<(String, String)> {
    let out = ps(r#"[Environment]::GetEnvironmentVariables('User').Keys | % { "user`t$_" }; [Environment]::GetEnvironmentVariables('Machine').Keys | % { "machine`t$_" }"#).unwrap_or_default();
    rows(&out).into_iter().filter(|r| r.len() >= 2).map(|r| (r[1].clone(), if r[0] == "user" { r"HKCU\Environment".to_string() } else { "machine environment (registry)".to_string() })).collect()
}
