//! `why package <name>` on Windows: installed programs and Store apps by that name, and the project dependency of the same name.
use super::ps::{ps, q, rows};
use crate::graph::Node;
use crate::util::{on_path, run, short};

pub fn explain(name: &str) -> Node {
    let mut root = Node::new(format!("PACKAGE {name}"));
    let mut found = false;
    let n = q(name);
    let out = ps(&format!(r#"$n={n}; $keys='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
Get-ItemProperty $keys | ? {{ $_.DisplayName -like "*$n*" }} | % {{ "prog`t$($_.DisplayName)`t$($_.DisplayVersion)`t$($_.Publisher)`t$($_.InstallDate)`t$($_.InstallLocation)`t$($_.WindowsInstaller)`t$($_.UninstallString)" }}
Get-AppxPackage "*$n*" | % {{ "appx`t$($_.Name)`t$($_.Version)`t$($_.Publisher)`t`t$($_.InstallLocation)`t`t$($_.PackageFamilyName)" }}"#)).unwrap_or_default();
    for r in rows(&out).iter().filter(|r| r.len() >= 6) {
        found = true;
        let appx = r[0] == "appx";
        let mut p = Node::new(format!("{} {} {}", if appx { "Store app" } else { "installed program" }, r[1], r[2])).proof(if appx { "Get-AppxPackage" } else { "Uninstall registry key" });
        if !r[3].is_empty() {
            p.add(Node::new(format!("publisher: {}", short(&r[3], 100))));
        }
        if r[4].len() == 8 {
            p.add(Node::new(format!("installed on {}-{}-{}", &r[4][..4], &r[4][4..6], &r[4][6..])).proof("InstallDate in the registry"));
        }
        if !r[5].is_empty() {
            p.add(Node::new(format!("location: {}", r[5])));
        }
        if r.get(6).is_some_and(|w| w == "1") {
            p.add(Node::new("installed with Windows Installer (an .msi)").proof("WindowsInstaller=1"));
        }
        if let Some(u) = r.get(7).filter(|u| !u.is_empty()) {
            p.add(Node::new(format!("removed with: {}", short(u, 120))).proof("UninstallString"));
        }
        root.add(p);
    }
    if on_path("choco") {
        if let Some(o) = run("choco", &["list", "--local-only", name]) {
            let hits: Vec<&str> = o.lines().filter(|l| l.to_lowercase().contains(&name.to_lowercase()) && !l.contains("packages installed")).collect();
            for h in hits.iter().take(5) {
                found = true;
                root.add(Node::new(format!("Chocolatey package: {}", h.trim())).proof("choco list --local-only"));
            }
        }
    }
    found |= crate::projdeps::project(&mut root, name);
    if found {
        root.add(Node::new("Windows does not record which program needed which: only the install itself is known").unknown().proof("no dependency database for installed programs"));
    } else {
        root.add(Node::new("no installed program, Store app, Chocolatey package or project dependency has that name").unknown().proof("Uninstall registry keys, Get-AppxPackage, choco, lock files here"));
    }
    root
}

pub fn complete() -> String {
    ps(r#"$keys='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; Get-ItemProperty $keys | ? { $_.DisplayName } | % { ($_.DisplayName -replace ' ','_') }"#).unwrap_or_default().lines().map(|l| format!("{}\n", l.trim())).collect()
}
