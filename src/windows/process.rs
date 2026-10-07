//! Processes on Windows, from WMI (Win32_Process) through one PowerShell call, cached for the run.
use super::ps::{ps, q, rows, split_cmd};
use crate::proc::Proc;
use std::path::PathBuf;
use std::sync::OnceLock;

static CACHE: OnceLock<Vec<Proc>> = OnceLock::new();

fn load() -> Vec<Proc> {
    let out = ps(r#"Get-CimInstance Win32_Process | % { $t=''; try { $t=[int64]([DateTimeOffset]$_.CreationDate).ToUnixTimeSeconds() } catch {}; "{0}`t{1}`t{2}`t{3}`t{4}`t{5}" -f $_.ProcessId,$_.ParentProcessId,$_.Name,$_.ExecutablePath,($_.CommandLine -replace "[`t`r`n]",' '),$t }"#).unwrap_or_default();
    rows(&out)
        .into_iter()
        .filter(|r| r.len() >= 3)
        .filter_map(|r| {
            Some(Proc {
                pid: r[0].parse().ok()?,
                ppid: r[1].parse().ok()?,
                name: r[2].clone(),
                cmdline: r.get(4).map(|c| split_cmd(c)).unwrap_or_default(),
                cwd: None,
                exe: r.get(3).filter(|e| !e.is_empty()).map(PathBuf::from),
                user: String::new(),
                started: r.get(5).and_then(|t| t.parse().ok()),
            })
        })
        .collect()
}

pub fn all() -> Vec<Proc> {
    CACHE.get_or_init(load).clone()
}

/// One process, with its owner filled in (an extra WMI call).
pub fn read(pid: u32) -> Option<Proc> {
    let mut p = all().into_iter().find(|p| p.pid == pid)?;
    p.user = ps(&format!("$p=Get-CimInstance Win32_Process -Filter 'ProcessId={pid}'; $o=Invoke-CimMethod -InputObject $p -MethodName GetOwner; if($o.User){{ \"$($o.Domain)\\$($o.User)\" }}")).unwrap_or_default().trim().to_string();
    if p.user.is_empty() {
        p.user = "?".into();
    }
    Some(p)
}

/// Parent chain, nearest first (at most 8 steps).
pub fn ancestors(pid: u32) -> Vec<Proc> {
    let all = all();
    let mut out = vec![];
    let mut cur = all.iter().find(|p| p.pid == pid).map(|p| p.ppid).unwrap_or(0);
    while cur > 0 && out.len() < 8 {
        let Some(p) = all.iter().find(|p| p.pid == cur && !out.iter().any(|o: &Proc| o.pid == p.pid)) else { break };
        cur = p.ppid;
        out.push(p.clone());
    }
    out
}

pub fn children(pid: u32) -> Vec<Proc> {
    all().into_iter().filter(|p| p.ppid == pid && p.pid != pid).collect()
}

/// Services hosted by a process (`svchost.exe` hosts many): `(name, display name, start mode, state, account, path)`.
pub fn services_of(pid: u32) -> Vec<Vec<String>> {
    rows(&ps(&format!(r#"Get-CimInstance Win32_Service -Filter 'ProcessId={pid}' | % {{ "{{0}}`t{{1}}`t{{2}}`t{{3}}`t{{4}}`t{{5}}" -f $_.Name,$_.DisplayName,$_.StartMode,$_.State,$_.StartName,$_.PathName }}"#)).unwrap_or_default())
}

/// Where a program is started from at boot or login: Run keys, scheduled tasks, Startup folders. Rows: `(kind, where, detail)`.
pub fn autostart(exe: &str) -> Vec<Vec<String>> {
    let leaf = exe.rsplit(['\\', '/']).next().unwrap_or(exe);
    let script = format!(r#"$leaf={}
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce') {{ $p=Get-ItemProperty $k; $p.PSObject.Properties | ? {{ $_.Name -notmatch '^PS' -and "$($_.Value)" -like "*$leaf*" }} | % {{ "run`t$k\$($_.Name)`t$($_.Value)" }} }}
Get-ScheduledTask | ? {{ (($_.Actions | % {{ "$($_.Execute) $($_.Arguments)" }}) -join ' ') -like "*$leaf*" }} | % {{ "task`t$($_.TaskPath)$($_.TaskName)`t$($_.State): " + (($_.Actions | % {{ $_.Execute + ' ' + $_.Arguments }}) -join ' ; ') }}
foreach ($d in "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") {{ Get-ChildItem $d | % {{ $t=''; try {{ $t=(New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName).TargetPath }} catch {{}}; if ($_.Name -like "*$leaf*" -or $t -like "*$leaf*") {{ "startup`t$($_.FullName)`t$t" }} }} }}"#, q(leaf));
    rows(&ps(&script).unwrap_or_default())
}
