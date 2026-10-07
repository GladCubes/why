use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() { out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char) } else { out.push('=') }
        }
    }
    out
}

pub fn ps(script: &str) -> Option<String> {
    let full = format!("$ErrorActionPreference='SilentlyContinue';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.Encoding]::UTF8;{script}");
    let utf16: Vec<u8> = full.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut c = Command::new("powershell.exe");
    c.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &b64(&utf16)]);
    #[cfg(windows)]
    c.creation_flags(0x0800_0000);
    let o = c.output().ok()?;
    Some(String::from_utf8_lossy(&o.stdout).into_owned())
}

pub fn q(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

pub fn rows(out: &str) -> Vec<Vec<String>> {
    out.lines().map(|l| l.trim_end_matches('\r')).filter(|l| !l.trim().is_empty()).map(|l| l.split('\t').map(|c| c.trim().to_string()).collect()).collect()
}

pub fn split_cmd(cmd: &str) -> Vec<String> {
    let (mut out, mut cur, mut quoted) = (vec![], String::new(), false);
    for ch in cmd.chars() {
        match ch {
            '"' => quoted = !quoted,
            ' ' if !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(ch),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_values() {
        assert_eq!(b64(b"Man"), "TWFu");
        assert_eq!(b64(b"Ma"), "TWE=");
        assert_eq!(b64(b"M"), "TQ==");
        assert_eq!(b64(b""), "");
    }

    #[test]
    fn quotes_and_splits() {
        assert_eq!(q("it's"), "'it''s'");
        assert_eq!(split_cmd(r#""C:\Program Files\a b.exe" -x --port=80 "c d""#), vec![r"C:\Program Files\a b.exe", "-x", "--port=80", "c d"]);
        assert_eq!(rows("a\tb\r\n\n c \t d\n"), vec![vec!["a", "b"], vec!["c", "d"]]);
    }
}
