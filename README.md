# why

*Why is this port open? Where does this variable come from?* `why` rebuilds the chain and **shows the proof of every step**.

```
$ why port 25565
PORT 25565
└── process docker-proxy (pid 3173, user root)  ← holds the socket open in /proc/3173/fd
    ├── listens on: tcp 10.0.35.2:25565         ← /proc/net/* tables
    ├── forwards to container 172.18.0.2:25565  ← docker-proxy arguments
    │   └── container 4301460e… (image ghcr.io/pterodactyl/yolks:java_25)  ← docker inspect: same IP
    ├── systemd service: docker.service         ← cgroup in /proc/3173/cgroup
    └── network in front of the process
        └── ≈ ip daddr 10.0.35.2 tcp dport 25565 dnat to 172.18.0.2:25565  ← nft list ruleset
```

## Commands

| command | what it rebuilds |
|---|---|
| `why port <N>` | who listens, command and directory, who started it (tmux, systemd, container), the unit and the script it launches, config files naming the port, nft rules, ports published by Docker/Podman, and tunnels in front (ssh `-L/-R/-D`, cloudflared ingress rules, WireGuard, ngrok/frp/chisel, tailscale serve) |
| `why port list` | every listening port with its process |
| `why env <NAME>` | the current value and every definition found: shell files (bash, zsh, fish), `/etc`, `environment.d`, `.env` and `docker-compose` in the directories above yours |
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

## Status

Linux (read from `/proc`). Windows, `why package` and `why compare` are next. No external dependencies.

```
cargo build --release                                    # normal binary
cargo build --release --target x86_64-unknown-linux-musl # static, runs on any distro
```

MIT license.
