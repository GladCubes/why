//! `why file <path>` on Windows: owner, signature, where it was downloaded from, which program it belongs to, who runs or names it.
use super::describe;
use super::ps::{ps, q, rows};
use crate::graph::Node;
use crate::proc;
use crate::util::short;
use std::path::Path;

pub fn explain(arg: &str) -> Node {
    let path = Path::new(arg);
    if !path.exists() {
        return Node::new(format!("FILE {arg}: does not exist")).unknown().proof("path lookup failed");
    }
    let full = std::fs::canonicalize(path).map(|p| p.to_string_lossy().trim_start_matches(r"\\?\").to_string()).unwrap_or_else(|_| arg.to_string());
    let is_dir = path.is_dir();
    let mut root = Node::new(format!("{} {full}", if is_dir { "FOLDER" } else { "FILE" })).proof(if is_dir { "directory" } else { "file" });
    let p = q(&full);
    // owner, dates, size
    let info = ps(&format!(r#"$f=Get-Item -LiteralPath {p} -Force; $o=(Get-Acl -LiteralPath {p}).Owner; "info`t$o`t$($f.Length)`t$($f.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm'))`t$($f.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm'))`t$($f.Attributes)""#)).unwrap_or_default();
    if let Some(r) = rows(&info).into_iter().find(|r| r[0] == "info" && r.len() >= 6) {
        root.add(Node::new(if is_dir { format!("owner {}, attributes {}", r[1], r[5]) } else { format!("owner {}, {} bytes, attributes {}", r[1], r[2], r[5]) }).proof("Get-Acl / Get-Item"));
        root.add(Node::new(format!("created {} UTC, modified {} UTC", r[3], r[4])).proof("file system timestamps"));
    }
    if is_dir {
        return root;
    }
    // Mark of the Web: where a downloaded file came from
    let zone = ps(&format!("Get-Content -LiteralPath {p} -Stream Zone.Identifier | Out-String")).unwrap_or_default();
    if let Some(z) = zone.lines().find_map(|l| l.strip_prefix("ZoneId=")) {
        let host = zone.lines().find_map(|l| l.strip_prefix("HostUrl=")).unwrap_or("");
        let refr = zone.lines().find_map(|l| l.strip_prefix("ReferrerUrl=")).unwrap_or("");
        let mut n = Node::new(format!("downloaded from outside this PC (zone {})", z.trim())).proof("Zone.Identifier stream (Mark of the Web)");
        if !host.trim().is_empty() && host.trim() != "about:internet" {
            n.add(Node::new(format!("downloaded from {}", short(host.trim(), 150))).proof("HostUrl"));
        }
        if !refr.trim().is_empty() {
            n.add(Node::new(format!("from the page {}", short(refr.trim(), 150))).proof("ReferrerUrl"));
        }
        root.add(n);
    }
    root.children.extend(describe::identity(&full));
    root.children.extend(belongs_to(&full));
    root.children.extend(users(&full));
    root.children.extend(references(&full));
    root
}

/// The installed program or app package whose folder holds the file.
fn belongs_to(full: &str) -> Vec<Node> {
    if full.to_lowercase().starts_with("c:\\windows\\") {
        return vec![Node::new("part of Windows itself (it lives in the Windows folder)").probable().proof("location")];
    }
    let out = ps(&format!(r#"$p={}; $keys='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
Get-ItemProperty $keys | ? {{ $_.DisplayName -and $_.InstallLocation -and $p.StartsWith(($_.InstallLocation.TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase) }} | % {{ "prog`t$($_.DisplayName)`t$($_.DisplayVersion)`t$($_.Publisher)`t$($_.InstallDate)" }}
Get-AppxPackage | ? {{ $_.InstallLocation -and $p.StartsWith($_.InstallLocation,[StringComparison]::OrdinalIgnoreCase) }} | % {{ "appx`t$($_.Name)`t$($_.Version)`t$($_.Publisher)`t" }}"#, q(full))).unwrap_or_default();
    let rs = rows(&out);
    if rs.is_empty() {
        let low = full.to_lowercase();
        let msg = if low.starts_with("c:\\windows\\") { "part of Windows itself (it lives in the Windows folder)" } else { "not part of any installed program or Store app I can find: copied, downloaded or created by hand" };
        return vec![Node::new(msg).probable().proof("Uninstall registry keys and Store packages")];
    }
    rs.iter().filter(|r| r.len() >= 4).map(|r| Node::new(format!("belongs to {} {} ({}){}", r[1], r[2], r[3], if r.get(4).is_some_and(|d| !d.is_empty()) { format!(", installed {}", r[4]) } else { String::new() })).proof(if r[0] == "appx" { "Get-AppxPackage" } else { "Uninstall registry key" })).collect()
}

/// Running programs from this file, and programs that have it loaded.
fn users(full: &str) -> Vec<Node> {
    let mut out = vec![];
    let running: Vec<String> = proc::all().into_iter().filter(|p| p.exe.as_ref().is_some_and(|e| e.to_string_lossy().eq_ignore_ascii_case(full))).map(|p| format!("{} ({})", p.name, p.pid)).collect();
    if !running.is_empty() {
        out.push(Node::new(format!("being run by: {}", running.join(", "))).proof("WMI Win32_Process.ExecutablePath"));
    }
    let low = full.to_lowercase();
    // a running .exe is already covered above; scanning every process's modules is slow, so only for libraries
    if [".dll", ".ocx", ".sys"].iter().any(|e| low.ends_with(e)) {
        let loaded = ps(&format!(r#"$p={}; Get-Process | % {{ $n=$_.ProcessName; $i=$_.Id; try {{ if ($_.Modules | ? {{ $_.FileName -eq $p }}) {{ "$n ($i)" }} }} catch {{}} }}"#, q(full))).unwrap_or_default();
        let l: Vec<&str> = loaded.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        if !l.is_empty() {
            out.push(Node::new(format!("loaded by: {}", l.iter().take(8).cloned().collect::<Vec<_>>().join(", "))).proof("Get-Process modules (processes you can't inspect are skipped)"));
        } else {
            out.push(Node::new("not loaded by any process I can inspect (protected processes are skipped; use an administrator terminal)").unknown());
        }
    }
    out
}

/// Services, scheduled tasks, Run keys and Startup items that name the file.
fn references(full: &str) -> Vec<Node> {
    let rs = super::process::autostart(full);
    let svc = rows(&ps(&format!(r#"$p={}; Get-CimInstance Win32_Service | ? {{ $_.PathName -like "*$p*" }} | % {{ "svc`t$($_.Name)`t$($_.State)`t$($_.StartMode)`t$($_.PathName)" }}"#, q(full))).unwrap_or_default());
    let mut n = Node::new("named by");
    for r in svc.iter().filter(|r| r.len() >= 5) {
        n.add(Node::new(format!("Windows service {} ({}, {}): {}", r[1], r[2], r[3], short(&r[4], 110))).proof("WMI Win32_Service.PathName"));
    }
    for r in rs.iter().filter(|r| r.len() >= 3) {
        let label = match r[0].as_str() {
            "run" => format!("registry Run key {} = {}", r[1], short(&r[2], 100)),
            "task" => format!("scheduled task {}: {}", r[1], short(&r[2], 110)),
            _ => format!("Startup folder item {}", r[1]),
        };
        n.add(Node::new(label).probable().proof("matches the file name"));
    }
    if n.children.is_empty() { vec![] } else { vec![n] }
}
