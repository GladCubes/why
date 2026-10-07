//! why: why is this port open, where does this variable come from? Every step comes with its proof.
mod completions;
mod graph;
#[cfg(target_os = "linux")]
mod linux;
mod util;

const HELP: &str = "why: rebuilds where something comes from, with the proof of every step

USAGE
  why port <N>              who listens on a port, how it was started, which config names it,
                            what sits in front of it (firewall, containers, tunnels)
  why port list             every listening port and its process
  why env <NAME>            where a variable is defined and which value it has now
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
        ["port"] => print!("{}", list_ports()),
        ["port", x] if is_list(x) => print!("{}", list_ports()),
        ["port", n] => match n.parse::<u16>() {
            Ok(p) if p > 0 => graph::print(&explain_port(p)),
            _ => fail(&format!("`{n}` is not a valid port (1-65535)")),
        },
        ["env"] => print!("{}", list_env(false)),
        ["env", x] if is_list(x) => print!("{}", list_env(false)),
        ["env", x, "all" | "--all" | "-a"] if is_list(x) => print!("{}", list_env(true)),
        ["env", "all" | "--all" | "-a"] => print!("{}", list_env(true)),
        ["env", name] => graph::print(&explain_env(name)),
        _ => fail("unknown command, try `why --help`"),
    }
}

fn fail(msg: &str) {
    eprintln!("why: {msg}");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
mod platform {
    pub use super::linux::env::{complete as complete_env, explain as explain_env, list_all as list_env};
    pub use super::linux::port::{complete as complete_port, explain as explain_port, list as list_ports};
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use crate::graph::Node;
    const MSG: &str = "this platform is not supported yet";
    pub fn explain_port(_: u16) -> Node { Node::new(MSG).unknown() }
    pub fn explain_env(_: &str) -> Node { Node::new(MSG).unknown() }
    pub fn list_ports() -> String { format!("{MSG}\n") }
    pub fn list_env(_: bool) -> String { format!("{MSG}\n") }
    pub fn complete_port() -> String { String::new() }
    pub fn complete_env() -> String { String::new() }
}

use platform::{explain_env, explain_port, list_env, list_ports};

fn complete(what: &str) -> String {
    match what {
        "port" => platform::complete_port(),
        "env" => platform::complete_env(),
        _ => String::new(),
    }
}
