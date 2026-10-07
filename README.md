# why

*Why is this port open? Where does this variable come from?* `why` rebuilds the chain and **shows the proof of every step**.

```
$ sudo why port 8080
PORT 8080
└── process docker-proxy (pid 3173, user root)  ← holds the socket open in /proc/3173/fd
    ├── listens on: tcp 0.0.0.0:8080            ← /proc/net/* tables
    ├── forwards to container 172.17.0.2:80     ← docker-proxy arguments
    │   └── container web (image nginx:1.27)    ← docker inspect: same IP
    ├── systemd service: docker.service         ← cgroup in /proc/3173/cgroup
    └── network in front of the process
        └── ≈ tcp dport 8080 dnat to 172.17.0.2:80  ← nft list ruleset
```

## Commands

| command | what it rebuilds |
|---|---|
| `why port <N>` | who listens, how it was started (service, container, tmux, terminal), the config that names the port, the firewall rules, port forwards and tunnels in front of it. `why port udp 7777`, `7777/tcp`, `tcp:7777` filter by protocol |
| `why port list [tcp\|udp]` | every listening port with its process |
| `why process <pid\|name>` | why a process exists: command, since when, executable (package or publisher, signature), who started it, what manages it, what it listens on, children |
| `why file <path>` | where a file comes from and what uses it: owner, package or installed program, signature, **where it was downloaded from** (Windows), processes running or loading it, services, cron jobs and startup entries that name it. Also finds files deleted but still held open |
| `why service <name>` | why a service is running: state, how it is enabled, who wants it, what it needs, the unit/command, its main process and ports |
| `why package <name>` | why a package is installed: on purpose or as a dependency, who needs it, when and by which command; inside a project, why it is a dependency (npm, cargo, pip, dotnet) |
| `why env <NAME>` | the current value, every definition found and who probably loads each file (a running program started from that directory, or a systemd unit pointing at it). On Windows also the user and machine registry layers |
| `why env <file>[:line]` | the variables a file defines, or the variable on a given line and everywhere else it is set |
| `why env list` | the variables defined in your project (`.env`, `docker-compose`), with where, and a flag when files disagree. If nothing is near you, it searches the whole machine |
| `why env list all` | the same plus the shell and system environment |
| `why snapshot` | a picture of this machine as text: tools and versions, environment, ports, services, containers, packages |
| `why compare <A> <B>` | what differs between two machines. `A` and `B` can be a snapshot file, `local`, or a host reachable over ssh that also has `why` (`why compare local web01`). Secrets are compared by fingerprint, never shown |
| `why completions <fish\|bash\|zsh>` | tab completion: `why port <TAB>` lists listening ports, `why service <TAB>` services, `why package <TAB>` installed packages |

```
why completions fish > ~/.config/fish/completions/why.fish
why completions bash | sudo tee /etc/bash_completion.d/why
```

## Reading the output

- plain line: **read directly** from the system
- `≈` line: **text match**, probable but not proven
- `?` line: **I could not verify it** (permissions, missing command, no result)

When it does not know, it says so. Values that look secret (`*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASS*`, passwords inside a URL) are never shown.

Seeing other users' processes and the firewall needs `sudo`. `why` **only reads**: it changes nothing.

Tunnels: it sees what runs *on this machine*. A tunnel on another machine (a VPS forwarding to this host) shows up at most as traffic arriving through an interface such as `wg0`; it says so instead of guessing.

## What it understands

| area | Linux | Windows |
|---|---|---|
| processes and ports | `/proc`, cgroups v1 and v2 | WMI and `netstat -ano` (any Windows language) |
| service manager | systemd (units, drop-ins, `EnvironmentFile=`, launched scripts); on OpenRC, runit, s6 it says it can't tell | Windows services (account, start mode, dependencies, triggers), `svchost` groups |
| started at boot by | units, cron, tmux | services, Run keys, scheduled tasks, Startup folders |
| containers | Docker, Podman, containerd, CRI-O, Kubernetes pods, LXC, Incus/LXD (including their port proxies) | Docker Desktop (`docker ps`), WSL relay noted |
| kubernetes | Services that expose a port (needs `kubectl` with a cluster) | same |
| firewall and forwards | nft, iptables, ip6tables | Windows Firewall rules, `netsh portproxy` |
| tunnels | ssh `-L/-R/-D`, cloudflared, WireGuard, ngrok, frp, chisel, bore, rathole, zrok, tailscale serve | same except WireGuard |
| packages | dpkg, pacman, rpm, apk | installed programs (registry), Store apps, Chocolatey |
| project dependencies | npm, cargo, pip, dotnet | same |
| variables | bash, zsh, fish, `/etc/environment(.d)`, `.env*`, docker-compose, systemd `Environment=` | user and machine registry, PowerShell profiles, `.env*`, docker-compose |
| files | package owner, mounts, open/mapped by processes, units and cron naming it | signature, version info, Mark-of-the-Web download URL, installed program, services and tasks naming it |

Tested on Arch Linux, Ubuntu 24.04 and Windows 10 22H2 (run from a normal user: some details, such as the command line of protected system processes, need an administrator terminal and are reported as `?` otherwise). It reads only what the system and the standard config locations expose, so on a very unusual setup the answer is "I don't know" (`?`), not a wrong answer.

The Kubernetes Service lookup is only tested against sample `kubectl` output, not a live cluster yet. macOS is not supported.

## Status

Linux and Windows. No external dependencies (on Windows it calls PowerShell, `netstat` and `netsh`, which every supported version has).

```
cargo build --release                                    # normal binary
cargo build --release --target x86_64-unknown-linux-musl # static, runs on any distro
cargo xwin build --release --target x86_64-pc-windows-msvc # Windows .exe, cross-compiled from Linux
```

MIT license.
