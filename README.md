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
| `why port <N>` | who listens, command and directory, who started it (tmux, systemd, container), the unit and the script it launches, config files naming the port, nft rules, ports published by Docker/Podman, and tunnels in front (ssh `-L/-R/-D`, cloudflared ingress rules, WireGuard, ngrok/frp/chisel, tailscale serve) |
| `why port udp 7777` | only that protocol; `tcp 7777`, `7777/udp`, `udp:7777` all work |
| `why port list [tcp\|udp]` | every listening port with its process |
| `why env <NAME>` | the current value, every definition found and who probably loads each file (a running program started from that directory, or a systemd unit pointing at it): shell files (bash, zsh, fish), `/etc`, `environment.d`, `.env` and `docker-compose` in the directories above yours |
| `why env <file>[:line]` | the variables a file defines (`why env .env`), or the variable on a given line and everywhere else it is set (`why env /var/www/app/.env:38`) |
| `why env list` | the variables defined in your project (`.env`, `docker-compose`, two levels down and up to home), with where, and a flag when files disagree. If nothing is near you, it searches the whole machine: `/opt`, `/srv`, `/var/www`, home directories, running services, systemd units and their `EnvironmentFile=` |
| `why env list all` | the same plus the shell and system environment |
| `why completions <fish\|bash\|zsh>` | tab completion; `why env <TAB>` lists the variables, `why port <TAB>` the listening ports |

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

| area | supported |
|---|---|
| init / service manager | systemd (units, drop-ins, `EnvironmentFile=`, the script `ExecStart=` launches); on OpenRC, runit, s6 it says it can't tell instead of guessing |
| Kubernetes | Services that expose the port (`kubectl get svc`, if `kubectl` can reach a cluster); pod and runtime names from the cgroup |
| containers | Docker, Podman, containerd, CRI-O, Kubernetes pods, LXC, Incus/LXD (including their port proxies), cgroup v1 and v2 |
| firewall | nft, iptables, ip6tables (`ufw` and `firewalld` show up as the rules they generate) |
| tunnels | ssh `-L/-R/-D`, cloudflared (config file), WireGuard, ngrok, frp, chisel, bore, rathole, zrok, tailscale serve |
| variables | bash, zsh, fish, `/etc/environment(.d)`, `.env*`, docker-compose, systemd `Environment=` |

Tested on Arch Linux and Ubuntu 24.04. It reads only what the kernel and standard config locations expose, so on a very unusual setup the answer is "I don't know" (`?`), not a wrong answer.

The Kubernetes Service lookup is only tested against sample `kubectl` output, not a live cluster yet.

Not covered yet: listeners inside other network namespaces (a container's private ports that are not published), macOS, Windows.

## Status

Linux (read from `/proc`). Windows, `why package` and `why compare` are next. No external dependencies.

```
cargo build --release                                    # normal binary
cargo build --release --target x86_64-unknown-linux-musl # static, runs on any distro
```

MIT license.
