//! Unit file di systemd: dove sta, cosa lancia e quali drop-in lo modificano.
use crate::util::home;
use std::fs;
use std::path::PathBuf;

fn dirs(user: bool) -> Vec<PathBuf> {
    if user {
        let mut d: Vec<PathBuf> = home().map(|h| h.join(".config/systemd/user")).into_iter().collect();
        d.extend(["/etc/systemd/user", "/usr/lib/systemd/user"].map(PathBuf::from));
        d
    } else {
        ["/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"].map(PathBuf::from).to_vec()
    }
}

/// Il file della unit e i suoi drop-in (in ordine di lettura).
pub fn files(name: &str, user: bool) -> Vec<PathBuf> {
    let template = name.find('@').map(|i| format!("{}@.service", &name[..i]));
    let mut out = vec![];
    for d in dirs(user) {
        for n in std::iter::once(name).chain(template.as_deref()) {
            let f = d.join(n);
            if f.is_file() && out.is_empty() {
                out.push(f);
            }
            if let Ok(rd) = fs::read_dir(d.join(format!("{n}.d"))) {
                let mut conf: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "conf")).collect();
                conf.sort();
                out.extend(conf);
            }
        }
    }
    out
}

/// Le righe che dicono cosa parte e con che ambiente.
pub fn key_lines(path: &PathBuf) -> Vec<String> {
    let Ok(text) = fs::read_to_string(path) else { return vec![] };
    const KEYS: [&str; 5] = ["ExecStart=", "WorkingDirectory=", "EnvironmentFile=", "Environment=", "User="];
    text.lines().map(str::trim).filter(|l| KEYS.iter().any(|k| l.starts_with(k))).map(String::from).collect()
}
