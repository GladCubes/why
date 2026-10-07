//! Small shared helpers: finding a number in a file, running commands, user names.
use std::fs;
use std::path::Path;
use std::process::Command;

/// `needle` as a whole number (not glued to digits, letters or dots: no "80" inside "1.80" or "8080").
/// The one exception is a leading "port" (`-port7777`), which is the normal way to write it.
pub fn has_token(line: &str, needle: &str) -> bool {
    let b = line.as_bytes();
    let low = line.to_ascii_lowercase();
    line.match_indices(needle).any(|(i, _)| {
        let edge = |c: u8| c.is_ascii_alphanumeric() || c == b'.' || c == b'_';
        (i == 0 || !edge(b[i - 1]) || low[..i].ends_with("port")) && (i + needle.len() >= b.len() || !edge(b[i + needle.len()]))
    })
}

/// Lines (number, shortened text) of a text file that contain the number as a whole word.
pub fn grep_token(path: &Path, needle: &str, max: usize) -> Vec<(usize, String)> {
    match fs::metadata(path) {
        Ok(m) if m.is_file() && m.len() < 1_000_000 => {}
        _ => return vec![],
    }
    let Ok(text) = fs::read_to_string(path) else { return vec![] };
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with('#') && has_token(l, needle))
        .take(max)
        .map(|(i, l)| (i + 1, short(l.trim(), 110)))
        .collect()
}

pub fn short(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { format!("{}…", s.chars().take(n).collect::<String>()) }
}

/// Runs a command and returns its output if it succeeded (None if it is missing or fails).
pub fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let o = Command::new(cmd).args(args).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

pub fn user_name(uid: u32) -> String {
    fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|t| t.lines().find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() > 2 && f[2].parse() == Ok(uid)).then(|| f[0].to_string())
        }))
        .unwrap_or_else(|| uid.to_string())
}

pub fn home() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_whole_word() {
        assert!(has_token("port: 8080", "8080"));
        assert!(has_token("listen 0.0.0.0:8080;", "8080"));
        assert!(!has_token("port: 80801", "8080"));
        assert!(!has_token("ver 1.8080", "8080"));
        assert!(!has_token("http_port", "80"));
        assert!(has_token("gameserver -port7777 -id3", "7777"));
        assert!(!has_token("x7777", "7777"));
    }
}
