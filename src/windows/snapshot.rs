use super::cmd_port::listeners;
use super::ps::{ps, rows};
use crate::compare::Snapshot;
use crate::proc;
use crate::util::{on_path, run};
use std::process::Command;

fn both(tool: &str, args: &[&str]) -> Option<String> {
    let o = Command::new("cmd.exe").arg("/C").arg(tool).args(args).output().ok()?;
    o.status.success().then(|| format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

pub fn collect() -> Snapshot {
    let mut s = Snapshot::new();
    s.insert("meta/hostname".into(), std::env::var("COMPUTERNAME").unwrap_or_default());
    let sys = ps(r#"$o=Get-CimInstance Win32_OperatingSystem; "$($o.Caption) $($o.Version)`t$($o.OSArchitecture)`t$([math]::Round($o.TotalVisibleMemorySize/1MB))`t$($o.BuildNumber)""#).unwrap_or_default();
    if let Some(r) = rows(&sys).first().filter(|r| r.len() >= 4) {
        s.insert("meta/os".into(), r[0].clone());
        s.insert("meta/arch".into(), r[1].clone());
        s.insert("meta/memory".into(), format!("{} GB", r[2]));
        s.insert("meta/build".into(), r[3].clone());
    }
    s.insert("meta/cpus".into(), std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0).to_string());
    for (tool, args) in crate::snapcommon::TOOLS {
        if on_path(tool) {
            if let Some(v) = both(tool, args).and_then(|o| o.lines().find(|l| !l.trim().is_empty()).map(|l| l.trim().chars().take(90).collect::<String>())) {
                s.insert(format!("tool/{tool}"), v);
            }
        }
    }
    crate::snapcommon::env_items(&mut s);
    let all = proc::all();
    for l in listeners(None, None) {
        let who = all.iter().find(|p| p.pid == l.pid).map(|p| p.name.clone()).unwrap_or_else(|| "?".into());
        s.insert(format!("port/{}/{}", l.proto, l.port), who);
    }
    for r in rows(&ps(r#"Get-CimInstance Win32_Service | % { "{0}`t{1}`t{2}" -f $_.Name,$_.State,$_.StartMode }"#).unwrap_or_default()).iter().filter(|r| r.len() >= 3) {
        if r[1] == "Running" {
            s.insert(format!("service/{}", r[0]), "running".into());
        } else if r[2] == "Auto" {
            s.insert(format!("service/{}", r[0]), "auto-start, not running".into());
        }
    }
    if let Some(o) = run("docker", &["ps", "--format", "{{.Names}}\t{{.Image}}"]) {
        for l in o.lines() {
            if let Some((n, i)) = l.split_once('\t') {
                s.insert(format!("container/{n}"), i.to_string());
            }
        }
    }
    let pk = ps(r#"$keys='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Get-ItemProperty $keys | ? { $_.DisplayName } | % { "{0}`t{1}" -f $_.DisplayName,$_.DisplayVersion }; Get-HotFix | % { "hotfix {0}`t{1}" -f $_.HotFixID,$_.InstalledOn }"#).unwrap_or_default();
    for r in rows(&pk).iter().filter(|r| r.len() >= 2) {
        s.insert(format!("pkg/{}", r[0]), r[1].clone());
    }
    s
}
