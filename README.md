# why

Something is listening on port 8080 and you don't know what. A variable has the wrong value and you don't know which file sets it. `why` finds out, and next to every answer it tells you where it got it from.

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

It runs on Linux and Windows, has no dependencies, and only reads: it never changes anything on the machine.

## Install

Debian / Ubuntu: grab `why-cli_<version>_<arch>.deb` from the [releases page](https://github.com/GladCubes/why/releases) and run `sudo apt install ./why-cli_*.deb`. This also installs the tab completions.

Any other Linux:

```
curl -fsSL https://raw.githubusercontent.com/GladCubes/why/master/install.sh | sh
```

The script checks the SHA-256 before installing. You can also download `why-<version>-linux-<arch>.tar.gz` yourself; it is a static binary.

Windows: download `why-<version>-windows-x86_64.exe` (or the zip) and put it in your `PATH`.

From source: `cargo install --git https://github.com/GladCubes/why`

## Usage

```
why port 8080                 who listens, how it was started, what sits in front of it
why port udp 7777             same, only UDP (also 7777/udp, tcp:7777)
why process 3173              why a process exists: who started it, what manages it
why process nginx             same, by name
why file /usr/bin/foo         where a file comes from and what is using it
why service sshd              why a service is running
why package openssl           why a package is installed
why env DATABASE_URL          every place a variable is defined, and which one wins
why env .env:12               the variable on that line, and everywhere else it is set
```

Most of these take `list` to show what is there: `why port list`, `why process list`, `why service list`, `why package list`, `why env list`. `why env list` shows the variables from your project's `.env` and compose files and warns when two files disagree. Add `all` to include the shell and system environment.

Two more:

- `why snapshot` prints the machine as text: tools and versions, environment, ports, services, containers, packages.
- `why compare A B` shows what differs between two machines. A and B can be snapshot files, `local`, or an ssh host that also has `why`, e.g. `why compare local web01`. Secrets are compared by fingerprint and never printed.

Tab completion works for ports, services and packages (`why port <TAB>`):

```
why completions fish > ~/.config/fish/completions/why.fish
why completions bash | sudo tee /etc/bash_completion.d/why
```

## Reading the output

A plain line was read directly from the system. A line starting with `≈` is a text match: probably right, not proven. A line starting with `?` means it could not check (missing permission, missing command, no result). When `why` doesn't know something it says so instead of guessing.

Anything that looks like a secret (`*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASS*`, a password inside a URL) is never printed.

Seeing other users' processes and the firewall needs `sudo`. Tunnels are only seen if they run on this machine; a tunnel on another box (say a VPS forwarding to you) shows up at best as traffic arriving on an interface like `wg0`, and `why` says that.

## What it knows about

| | Linux | Windows |
|---|---|---|
| processes, ports | `/proc`, cgroups v1 and v2 | WMI, `netstat -ano` |
| services | systemd (units, drop-ins, `EnvironmentFile=`); on OpenRC, runit and s6 it says it can't tell | Windows services, `svchost` groups |
| started at boot by | units, cron, tmux | services, Run keys, scheduled tasks, Startup folders |
| containers | Docker, Podman, containerd, CRI-O, Kubernetes, LXC, Incus/LXD | Docker Desktop, WSL |
| firewall, forwards | nft, iptables, ip6tables | Windows Firewall, `netsh portproxy` |
| tunnels | ssh `-L/-R/-D`, cloudflared, WireGuard, ngrok, frp, chisel, bore, rathole, zrok, tailscale serve | same, minus WireGuard |
| packages | dpkg, pacman, rpm, apk | installed programs, Store apps, Chocolatey |
| project dependencies | npm, cargo, pip, dotnet | same |
| variables | bash, zsh, fish, `/etc/environment`, `.env*`, docker-compose, systemd `Environment=` | user and machine registry, PowerShell profiles, `.env*`, docker-compose |
| files | package owner, mounts, open or mapped by processes | signature, publisher, download URL (Mark of the Web), installed program |

I tested it on Arch Linux, Ubuntu 24.04 and Windows 10 22H2. On Windows, run it from an administrator terminal to see the command line of protected system processes; from a normal user those details show up as `?`.

The Kubernetes lookup has only been tried against sample `kubectl` output, not a real cluster. macOS isn't supported. On an unusual setup you'll get `?` rather than a wrong answer; if you hit one, open an issue.

## Building

```
cargo build --release
cargo build --release --target x86_64-unknown-linux-musl    # static, runs on any distro
cargo xwin build --release --target x86_64-pc-windows-msvc  # Windows exe, cross-compiled from Linux
```

On Windows it calls PowerShell, `netstat` and `netsh`, which every supported version has.

## License

MIT
