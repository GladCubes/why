//! Tunnels and forwards that may carry a port: ssh -L/-R/-D, cloudflared, ngrok & co, tailscale, WireGuard.
use super::process;
use crate::graph::Node;
use crate::util::{has_token, home, run, short};
use std::fs;

const OTHERS: [&str; 7] = ["ngrok", "frpc", "frps", "chisel", "bore", "rathole", "zrok"];

/// WireGuard interface named by an nft rule fragment (`iifname "wg0"`).
pub fn wireguard_in(rule: &str) -> Option<String> {
    let rest = rule.split("iifname ").nth(1)?.trim_start_matches(['!', '=', ' ']);
    let name = rest.trim_start_matches('"').split('"').next()?;
    is_wireguard(name).then(|| name.to_string())
}

fn is_wireguard(name: &str) -> bool {
    fs::read_to_string(format!("/sys/class/net/{name}/uevent")).is_ok_and(|u| u.contains("DEVTYPE=wireguard"))
}

pub fn explain(port: u16, via_wg: &[String]) -> Node {
    let p = port.to_string();
    let mut n = Node::new("tunnels and forwards");
    for w in via_wg {
        let mut x = Node::new(format!("traffic arrives through WireGuard interface {w}")).probable().proof("an nft rule for this port matches that incoming interface");
        match run("wg", &["show", w, "endpoints"]) {
            Some(e) if !e.trim().is_empty() => {
                x.add(Node::new(format!("peer endpoints: {}", e.split_whitespace().filter(|s| s.contains(':')).collect::<Vec<_>>().join(", "))).proof("wg show"));
            }
            _ => {
                x.add(Node::new("peers not readable (needs root, or wg is missing)").unknown());
            }
        }
        n.add(x);
    }
    for pr in process::all() {
        let cmd = pr.cmdline.join(" ");
        match pr.name.as_str() {
            "ssh" => ssh_forwards(&pr, &p, &mut n),
            "cloudflared" => cloudflared(&pr, &cmd, &p, &mut n),
            name if OTHERS.contains(&name) && cmd.split_whitespace().any(|a| has_token(a, &p)) => {
                n.add(Node::new(format!("{name} (pid {}) mentions the port: {}", pr.pid, short(&cmd, 120))).probable().proof(format!("/proc/{}/cmdline", pr.pid)));
            }
            _ => {}
        }
    }
    if let Some(s) = run("tailscale", &["serve", "status"]) {
        for l in s.lines().filter(|l| has_token(l, &p)) {
            n.add(Node::new(short(l.trim(), 120)).proof("tailscale serve status"));
        }
    }
    if n.children.is_empty() {
        n.add(Node::new("no tunnel or forward found on this machine").unknown().proof("ssh -L/-R, cloudflared, ngrok/frp/chisel, tailscale, WireGuard"));
        n.add(Node::new("a tunnel can still exist on another machine (e.g. a VPS forwarding to this one): I can only see this host").unknown());
    }
    n
}

/// Adds the node unless an identical one is already there (several processes can report the same tunnel).
fn add_unique(n: &mut Node, c: Node) {
    if !n.children.iter().any(|x| x.label == c.label) {
        n.add(c);
    }
}

fn ssh_forwards(pr: &process::Proc, port: &str, n: &mut Node) {
    let a = &pr.cmdline;
    for (i, arg) in a.iter().enumerate() {
        let (kind, spec) = match arg.as_str() {
            "-L" | "-R" | "-D" => (arg.as_str(), a.get(i + 1).map(String::as_str).unwrap_or("")),
            s if s.len() > 2 && ["-L", "-R", "-D"].contains(&&s[..2]) => (&s[..2], &s[2..]),
            _ => continue,
        };
        if has_token(spec, port) {
            let what = match kind { "-L" => "forwards a local port", "-R" => "forwards a remote port back here", _ => "SOCKS proxy" };
            add_unique(n, Node::new(format!("ssh (pid {}) {what}: {kind} {spec}", pr.pid)).proof(format!("/proc/{}/cmdline", pr.pid)));
        }
    }
}

fn cloudflared(pr: &process::Proc, cmd: &str, port: &str, n: &mut Node) {
    let mut paths: Vec<String> = pr.cmdline.iter().position(|a| a == "--config").and_then(|i| pr.cmdline.get(i + 1)).cloned().into_iter().collect();
    paths.extend(["/etc/cloudflared/config.yml", "/etc/cloudflared/config.yaml", "/root/.cloudflared/config.yml"].map(String::from));
    if let Some(h) = home() {
        paths.push(h.join(".cloudflared/config.yml").to_string_lossy().into_owned());
    }
    let mut hostname = String::new();
    let mut found = false;
    for path in &paths {
        let Ok(text) = fs::read_to_string(path) else { continue };
        found = true;
        for l in text.lines().map(str::trim) {
            if let Some(h) = l.trim_start_matches("- ").strip_prefix("hostname:") {
                hostname = h.trim().to_string();
            }
            if l.starts_with("service:") && has_token(l, port) {
                add_unique(n, Node::new(format!("cloudflared tunnel: {} → {}", if hostname.is_empty() { "?" } else { &hostname }, l.trim_start_matches("service:").trim())).probable().proof(format!("ingress rule in {path}")));
            }
        }
    }
    if !found && (cmd.contains("--token") || cmd.contains(" run")) {
        n.add(Node::new(format!("cloudflared (pid {}) is running with no readable config: if it is remotely managed, its routes live in the Cloudflare dashboard and I can't see them", pr.pid)).unknown());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_wireguard_name_in_rule() {
        assert_eq!(wireguard_in("iifname \"nonexistent0\" udp dport 7777 accept"), None);
        assert_eq!(wireguard_in("udp dport 7777 accept"), None);
    }
}
