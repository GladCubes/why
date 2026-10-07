//! `why service <name>` on Windows: state, how it starts, what it depends on, what runs it.
use super::cmd_port::listeners;
use super::ps::{ps, q, rows};
use crate::graph::Node;
use crate::proc;
use crate::util::short;

pub fn explain(arg: &str) -> Node {
    let n = q(arg);
    let out = ps(&format!(r#"$s=Get-CimInstance Win32_Service -Filter ("Name={n}") ; if(-not $s){{ $s=Get-CimInstance Win32_Service | ? {{ $_.DisplayName -eq {n} }} | select -First 1 }}
if($s){{ "svc`t$($s.Name)`t$($s.DisplayName)`t$($s.State)`t$($s.StartMode)`t$($s.DelayedAutoStart)`t$($s.StartName)`t$($s.ProcessId)`t$($s.PathName)`t$($s.Description)"
$g=Get-Service -Name $s.Name; $g.ServicesDependedOn | % {{ "needs`t$($_.Name)`t$($_.Status)" }}; $g.DependentServices | % {{ "neededby`t$($_.Name)`t$($_.Status)" }}
$t=sc.exe qtriggerinfo $s.Name | Out-String; if($t -match 'START SERVICE'){{ "trigger`t" + (($t -split "`n" | ? {{ $_ -match 'START SERVICE|DEVICE INTERFACE|NETWORK|DOMAIN|IP ADDRESS|CUSTOM|GROUP POLICY' }} | % {{ $_.Trim() }}) -join ' | ') }} }}"#, n = n)).unwrap_or_default();
    let rs = rows(&out);
    let Some(s) = rs.iter().find(|r| r[0] == "svc" && r.len() >= 9) else {
        return Node::new(format!("SERVICE {arg}: no such Windows service")).unknown().proof("WMI Win32_Service has no service with that name or display name");
    };
    let mut root = Node::new(format!("SERVICE {} ({})", s[1], short(&s[2], 60))).proof("WMI Win32_Service");
    root.add(Node::new(format!("state: {}", s[3])).proof("Win32_Service.State"));
    let delayed = if s[5] == "True" { " (delayed)" } else { "" };
    let mut start = Node::new(format!("start mode: {}{delayed}", s[4])).proof("Win32_Service.StartMode");
    match s[4].as_str() {
        "Auto" => {
            start.add(Node::new("starts by itself when Windows boots").probable());
        }
        "Disabled" => {
            start.add(Node::new("disabled: it cannot start").probable());
        }
        "Manual" => {
            start.add(Node::new("starts only when something asks for it (a program, a trigger or you)").probable());
        }
        _ => {}
    }
    root.add(start);
    if let Some(t) = rs.iter().find(|r| r[0] == "trigger" && r.len() >= 2) {
        root.add(Node::new(format!("started on demand by: {}", short(&t[1], 140))).proof("sc qtriggerinfo"));
    }
    root.add(Node::new(format!("runs as {}", s[6])).proof("Win32_Service.StartName"));
    if !s[9.min(s.len() - 1)].is_empty() && s.len() > 9 {
        root.add(Node::new(format!("description: {}", short(&s[9], 130))).proof("service description"));
    }
    root.add(Node::new(format!("command: {}", short(&s[8], 150))).proof("Win32_Service.PathName"));
    let needs: Vec<String> = rs.iter().filter(|r| r[0] == "needs" && r.len() >= 3).map(|r| format!("{} ({})", r[1], r[2])).collect();
    if !needs.is_empty() {
        root.add(Node::new(format!("needs: {}", needs.join(", "))).proof("Get-Service ServicesDependedOn"));
    }
    let by: Vec<String> = rs.iter().filter(|r| r[0] == "neededby" && r.len() >= 3).map(|r| format!("{} ({})", r[1], r[2])).collect();
    if !by.is_empty() {
        root.add(Node::new(format!("needed by: {}", by.join(", "))).proof("Get-Service DependentServices"));
    }
    if let Some(pid) = s[7].parse::<u32>().ok().filter(|p| *p > 0) {
        if let Some(p) = proc::all().into_iter().find(|p| p.pid == pid) {
            let mut pn = Node::new(format!("process {} (pid {})", p.name, p.pid)).proof("Win32_Service.ProcessId");
            let ports = listeners(None, None).into_iter().filter(|l| l.pid == pid).collect::<Vec<_>>();
            if !ports.is_empty() {
                pn.add(Node::new(format!("listens on: {}", ports.iter().map(|x| format!("{} {}", x.proto, x.addr)).collect::<Vec<_>>().join(", "))).proof("netstat -ano"));
            }
            root.add(pn);
        }
    }
    root
}

pub fn complete() -> String {
    ps("Get-Service | % { $_.Name }").unwrap_or_default().lines().map(|l| format!("{}\n", l.trim())).filter(|l| l.trim().len() > 0).collect()
}
