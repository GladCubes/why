//! why: why is this port open, where does this variable come from? Every step comes with its proof.
mod compare;
mod completions;
mod env;
mod graph;
mod kubernetes;
mod proc;
mod tunnel;
#[cfg(target_os = "linux")]
mod linux;
mod util;

const HELP: &str = "why: rebuilds where something comes from, with the proof of every step

USAGE
  why port <N>              who listens on a port, how it was started, which config names it,
                            what sits in front of it (firewall, containers, tunnels)
  why port udp <N>          only that protocol; also `tcp 7777`, `7777/udp`, `udp:7777`
  why port list [tcp|udp]   every listening port and its process
  why process <pid|name>    why a process exists: what runs it, since when, who started it, what it listens on
  why file <path>           where a file comes from (package, owner) and what uses it (processes, libraries, units, cron)
  why package <name>        why a package is installed: on purpose or as a dependency, who needs it, when and by which command
  why service <name>        why a systemd service is running: state, how it is enabled, who wants it, what it runs
  why snapshot              a picture of this machine (tools, env, ports, services, packages) as text
  why compare <A> <B>       what differs between two machines: a snapshot file, `local`, or a host reachable
                            over ssh that also has why (`why compare local web01`)
  why env <NAME>            where a variable is defined and which value it has now
  why env <file>[:line]     the variables a file defines; or the variable a given line defines, and where else it is set
  why env list              variables defined in the project (.env, docker-compose), with where
  why env list all          the same plus the shell and system environment
  why completions <shell>   completion script for fish, bash or zsh

LEGEND
  plain line   read directly from the system
  ≈ line       text match: probable, not proven
  ? line       I could not verify it

Seeing other users' processes and the firewall needs sudo. why only reads: it changes nothing.";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let is_list = |x: &str| matches!(x, "list" | "ls" | "l" | "-l" | "--list");
    match a.as_slice() {
        [] | ["-h"] | ["--help"] | ["help"] => println!("{HELP}"),
        ["-V"] | ["--version"] => println!("why {}", env!("CARGO_PKG_VERSION")),
        ["completions", sh] => match completions::script(sh) {
            Some(s) => print!("{s}"),
            None => fail("supported shells: fish, bash, zsh"),
        },
        ["__complete", what] => print!("{}", complete(what)),
        ["port"] => print!("{}", list_ports(None)),
        ["port", x, rest @ ..] if is_list(x) => match rest {
            [] => print!("{}", list_ports(None)),
            [pr] if proto_of(pr).is_some() => print!("{}", list_ports(proto_of(pr))),
            _ => fail("usage: why port list [tcp|udp]"),
        },
        ["port", rest @ ..] => match parse_port(rest) {
            Ok((proto, p)) => graph::print(&explain_port(p, proto)),
            Err(e) => fail(&e),
        },
        ["process", x] => graph::print(&platform::explain_process(x)),
        ["file", x] => graph::print(&platform::explain_file(x)),
        ["snapshot"] => print!("{}", compare::serialize(&platform::snapshot())),
        ["compare", a, b] => match (compare::fetch(a, platform::snapshot), compare::fetch(b, platform::snapshot)) {
            (Ok(x), Ok(y)) => graph::print(&compare::compare(&x, a, &y, b)),
            (Err(e), _) | (_, Err(e)) => fail(&e),
        },
        ["package", x] => graph::print(&platform::explain_package(x)),
        ["service", x] => graph::print(&platform::explain_service(x)),
        ["env"] => print!("{}", list_env(false)),
        ["env", x] if is_list(x) => print!("{}", list_env(false)),
        ["env", x, "all" | "--all" | "-a"] if is_list(x) => print!("{}", list_env(true)),
        ["env", "all" | "--all" | "-a"] => print!("{}", list_env(true)),
        ["env", name] => graph::print(&explain_env(name)),
        _ => fail("unknown command, try `why --help`"),
    }
}

fn proto_of(s: &str) -> Option<&'static str> {
    match s.to_ascii_lowercase().as_str() {
        "tcp" => Some("tcp"),
        "udp" => Some("udp"),
        _ => None,
    }
}

/// `7777`, `udp 7777`, `7777/udp`, `udp/7777`, `tcp:7777`, `:7777` -> (protocol, port)
fn parse_port(args: &[&str]) -> Result<(Option<&'static str>, u16), String> {
    let (mut proto, mut port) = (None, None);
    for tok in args.iter().flat_map(|a| a.split(['/', ':', ' '])).filter(|t| !t.is_empty()) {
        match (proto_of(tok), tok.parse::<u16>()) {
            (Some(p), _) if proto.is_none() => proto = Some(p),
            (None, Ok(n)) if n > 0 && port.is_none() => port = Some(n),
            _ => return Err(format!("`{}` is not a port: try `why port 7777`, `why port udp 7777` or `why port 7777/tcp`", args.join(" "))),
        }
    }
    port.map(|p| (proto, p)).ok_or_else(|| "usage: why port <N> (or `why port list`)".to_string())
}

fn fail(msg: &str) {
    eprintln!("why: {msg}");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
mod platform {
    pub use super::env::{complete as complete_env, explain_arg as explain_env, list_all as list_env};
    pub use super::linux::hooks::{environ_value, service_consumers, service_env_files, shell_files, wide_roots};
    pub use super::linux::port::{complete as complete_port, explain as explain_port, list as list_ports};
    pub use super::linux::cmd_file::explain as explain_file;
    pub use super::linux::snapshot::collect as snapshot;
    pub use super::linux::cmd_package::{complete as complete_package, explain as explain_package};
    pub use super::linux::cmd_process::{complete as complete_process, explain as explain_process};
    pub use super::linux::cmd_service::{complete as complete_service, explain as explain_service};
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use crate::graph::Node;
    const MSG: &str = "this platform is not supported yet";
    pub fn explain_port(_: u16, _: Option<&str>) -> Node { Node::new(MSG).unknown() }
    pub fn explain_env(_: &str) -> Node { Node::new(MSG).unknown() }
    pub fn list_ports(_: Option<&str>) -> String { format!("{MSG}\n") }
    pub fn list_env(_: bool) -> String { format!("{MSG}\n") }
    pub fn explain_process(_: &str) -> Node { Node::new(MSG).unknown() }
    pub fn explain_file(_: &str) -> Node { Node::new(MSG).unknown() }
    pub fn explain_service(_: &str) -> Node { Node::new(MSG).unknown() }
    pub fn explain_package(_: &str) -> Node { Node::new(MSG).unknown() }
    pub fn snapshot() -> crate::compare::Snapshot { Default::default() }
    pub fn complete_package() -> String { String::new() }
    pub fn complete_process() -> String { String::new() }
    pub fn complete_service() -> String { String::new() }
    pub fn complete_port() -> String { String::new() }
    pub fn complete_env() -> String { String::new() }
}

use platform::{explain_env, explain_port, list_env, list_ports};

fn complete(what: &str) -> String {
    match what {
        "port" => platform::complete_port(),
        "env" => platform::complete_env(),
        "process" => platform::complete_process(),
        "service" => platform::complete_service(),
        "package" => platform::complete_package(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_port_syntaxes() {
        assert_eq!(parse_port(&["7777"]), Ok((None, 7777)));
        assert_eq!(parse_port(&["udp", "7777"]), Ok((Some("udp"), 7777)));
        assert_eq!(parse_port(&["7777/tcp"]), Ok((Some("tcp"), 7777)));
        assert_eq!(parse_port(&["UDP:7777"]), Ok((Some("udp"), 7777)));
        assert_eq!(parse_port(&[":8080"]), Ok((None, 8080)));
        assert!(parse_port(&["tcp"]).is_err());
        assert!(parse_port(&["0"]).is_err());
        assert!(parse_port(&["70000"]).is_err());
        assert!(parse_port(&["7777", "8888"]).is_err());
        assert!(parse_port(&["http"]).is_err());
    }
}
