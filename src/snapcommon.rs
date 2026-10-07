//! Parts of a snapshot that are the same on every platform: the tool list and the environment.
use crate::compare::Snapshot;

pub const TOOLS: &[(&str, &[&str])] = &[
    ("node", &["--version"]), ("npm", &["--version"]), ("python3", &["--version"]), ("pip3", &["--version"]), ("java", &["-version"]),
    ("dotnet", &["--version"]), ("go", &["version"]), ("rustc", &["--version"]), ("cargo", &["--version"]), ("gcc", &["--version"]),
    ("clang", &["--version"]), ("make", &["--version"]), ("git", &["--version"]), ("docker", &["--version"]), ("podman", &["--version"]),
    ("kubectl", &["version", "--client"]), ("openssl", &["version"]), ("curl", &["--version"]), ("nginx", &["-v"]), ("php", &["--version"]),
    ("ruby", &["--version"]), ("psql", &["--version"]), ("mysql", &["--version"]), ("redis-server", &["--version"]), ("ssh", &["-V"]),
    ("systemctl", &["--version"]), ("bash", &["--version"]), ("sqlite3", &["--version"]), ("perl", &["--version"]), ("zsh", &["--version"]), ("fish", &["--version"]),
    ("pwsh", &["--version"]), ("winget", &["--version"]), ("choco", &["--version"]), ("wsl", &["--version"]),
];

/// Variables that differ on every login and say nothing about the machine.
pub const NOISE: &[&str] = &["_", "PWD", "OLDPWD", "SHLVL", "TERM", "COLORTERM", "LS_COLORS", "SSH_TTY", "SSH_CLIENT", "SSH_CONNECTION", "DISPLAY", "WINDOWID", "SESSIONNAME", "LOGONSERVER"];
pub const NOISE_PREFIX: &[&str] = &["INVOCATION_ID", "JOURNAL_STREAM", "MANAGERPID", "SYSTEMD_EXEC_PID", "MEMORY_PRESSURE", "GIO_", "GJS_", "PRESSURE_VESSEL", "QT_", "GDK_", "EGL_", "ELECTRON", "MCP_", "DESKTOP_SESSION", "SSH_AUTH", "XDG_SESSION", "DBUS_", "KITTY_", "WAYLAND_", "TMUX", "LC_", "CLAUDE", "ANTHROPIC", "AI_AGENT", "BAGGAGE", "SENTRY", "VSCODE", "TERM_", "GNOME_", "LIBVA", "NO_AT_BRIDGE", "MOTD", "WT_", "PSMODULEPATH", "CLAUDE_", "VSCODE_"];


/// Environment variables worth comparing (secrets become fingerprints, session noise is dropped).
pub fn env_items(s: &mut Snapshot) {
    for (k, v) in std::env::vars() {
        let up = k.to_ascii_uppercase();
        if k.starts_with('=') {
            continue;
        }
        if NOISE.contains(&up.as_str()) || NOISE_PREFIX.iter().any(|p| up.starts_with(p)) {
            continue;
        }
        s.insert(format!("env/{k}"), crate::env::comparable(&k, &v));
    }
}
