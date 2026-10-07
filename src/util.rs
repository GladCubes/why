use std::fs;
use std::path::Path;
use std::process::Command;

pub fn has_token(line: &str, needle: &str) -> bool {
    let b = line.as_bytes();
    let low = line.to_ascii_lowercase();
    line.match_indices(needle).any(|(i, _)| {
        let edge = |c: u8| c.is_ascii_alphanumeric() || c == b'.' || c == b'_';
        (i == 0 || !edge(b[i - 1]) || low[..i].ends_with("port")) && (i + needle.len() >= b.len() || !edge(b[i + needle.len()]))
    })
}

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

pub fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let o = Command::new(cmd).args(args).env("LC_ALL", "C").env("LANGUAGE", "C").output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

pub fn on_path(bin: &str) -> bool {
    let exts: &[&str] = if cfg!(windows) { &["", ".exe", ".cmd", ".bat", ".com"] } else { &[""] };
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| exts.iter().any(|e| d.join(format!("{bin}{e}")).is_file())))
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

pub fn group_name(gid: u32) -> String {
    fs::read_to_string("/etc/group")
        .ok()
        .and_then(|t| t.lines().find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() > 2 && f[2].parse() == Ok(gid)).then(|| f[0].to_string())
        }))
        .unwrap_or_else(|| gid.to_string())
}

pub fn ago(secs: u64) -> String {
    match secs {
        0..=89 => format!("{secs} s"),
        90..=5399 => format!("{} min", secs / 60),
        5400..=172_799 => format!("{} h {} min", secs / 3600, secs % 3600 / 60),
        _ => format!("{} days {} h", secs / 86400, secs % 86400 / 3600),
    }
}

pub fn date(epoch: u64) -> String {
    let (days, rem) = (epoch / 86400, epoch % 86400);
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", rem / 3600, rem % 3600 / 60)
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn home() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_time() {
        assert_eq!(date(0), "1970-01-01 00:00 UTC");
        assert_eq!(date(1_791_372_845), "2026-10-07 11:34 UTC");
        assert_eq!(ago(45), "45 s");
        assert_eq!(ago(7200), "2 h 0 min");
        assert_eq!(ago(3 * 86400 + 4 * 3600), "3 days 4 h");
    }

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
