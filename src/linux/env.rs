//! `why env NOME`: dove e' definita una variabile (file di shell, sistema, .env, compose) e quale valore vale ora.
use crate::graph::Node;
use crate::util::{home, short};
use std::fs;
use std::path::{Path, PathBuf};

/// Se la riga definisce NOME, il valore che gli da'.
pub fn defines(line: &str, name: &str) -> Option<String> {
    let mut l = line.trim();
    if l.starts_with('#') {
        return None;
    }
    for p in ["export ", "declare -x ", "set -gx ", "set -Ux ", "set -x ", "set -g ", "set -U ", "- ", "Environment=", "SETUVAR "] {
        if let Some(r) = l.strip_prefix(p) {
            l = r.trim_start();
            break;
        }
    }
    let l = l.trim_matches('"');
    let rest = l.strip_prefix(name)?;
    // NOME=valore (shell, .env, systemd), NOME: valore (yaml, fish_variables), NOME valore (fish)
    let v = rest.strip_prefix('=').or_else(|| rest.strip_prefix(':')).or_else(|| rest.strip_prefix(' '))?;
    Some(v.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
}

fn secret(name: &str) -> bool {
    let n = name.to_uppercase();
    ["KEY", "TOKEN", "SECRET", "PASS", "PWD", "AUTH"].iter().any(|k| n.contains(k))
}

/// I valori sensibili non finiscono a schermo: due caratteri e la lunghezza; nelle URL si nasconde solo la password.
fn show(name: &str, v: &str) -> String {
    if secret(name) && !v.is_empty() {
        return format!("{}… ({} caratteri, nascosto)", v.chars().take(2).collect::<String>(), v.chars().count());
    }
    if let (Some(s), Some(at)) = (v.find("://"), v.rfind('@')) {
        if let Some(c) = v[s + 3..at].find(':') {
            return short(&format!("{}***{}", &v[..s + 3 + c + 1], &v[at..]), 100);
        }
    }
    short(v, 100)
}

fn shell_files() -> Vec<PathBuf> {
    let mut f: Vec<PathBuf> = ["/etc/environment", "/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshenv", "/etc/zsh/zprofile", "/etc/zsh/zshrc", "/etc/fish/config.fish"].map(PathBuf::from).to_vec();
    f.extend(list("/etc/profile.d", |n| n.ends_with(".sh")));
    if let Some(h) = home() {
        for n in [".profile", ".bash_profile", ".bashrc", ".zshenv", ".zprofile", ".zshrc", ".pam_environment", ".config/fish/config.fish", ".config/fish/fish_variables"] {
            f.push(h.join(n));
        }
        f.extend(list(&h.join(".config/fish/conf.d").to_string_lossy(), |n| n.ends_with(".fish")));
        f.extend(list(&h.join(".config/environment.d").to_string_lossy(), |n| n.ends_with(".conf")));
    }
    f
}

fn list(dir: &str, keep: impl Fn(&str) -> bool) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.file_name().is_some_and(|n| keep(&n.to_string_lossy()))).collect();
    v.sort();
    v
}

/// .env e compose nella cartella corrente e nelle cartelle sopra, fino alla home.
fn project_files() -> Vec<PathBuf> {
    let mut out = vec![];
    let Ok(mut dir) = std::env::current_dir() else { return out };
    let stop = home();
    loop {
        for e in fs::read_dir(&dir).into_iter().flatten().flatten().take(500) {
            let n = e.file_name().to_string_lossy().into_owned();
            let compose = (n.starts_with("docker-compose") || n.starts_with("compose.")) && (n.ends_with(".yml") || n.ends_with(".yaml"));
            if (n.starts_with(".env") || compose) && e.path().is_file() {
                out.push(e.path());
            }
        }
        if Some(&dir) == stop.as_ref() || !dir.pop() || dir == Path::new("/") {
            break;
        }
    }
    out
}

pub fn explain(name: &str) -> Node {
    let current = std::env::var(name).ok();
    let mut root = match &current {
        Some(v) => Node::new(format!("VARIABILE {name} = {}", show(name, v))).proof("ambiente del processo `why`, cioe' quello della tua shell"),
        None => Node::new(format!("VARIABILE {name}: non impostata nell'ambiente attuale")).proof("ambiente del processo `why`"),
    };
    let mut found = 0;
    for (group, files, loaded) in [
        ("file della shell e del sistema", shell_files(), "viene letto all'avvio della shell o del login"),
        ("file di progetto", project_files(), "NON lo legge la shell: vale solo per i programmi che lo caricano (dotenv, docker compose, ...)"),
    ] {
        let mut g = Node::new(group.to_string());
        for f in files {
            let Ok(text) = fs::read_to_string(&f) else { continue };
            for (i, l) in text.lines().enumerate() {
                let Some(v) = defines(l, name) else { continue };
                found += 1;
                let same = current.as_deref() == Some(v.as_str());
                let label = format!("{}:{}  =  {}{}", f.display(), i + 1, show(name, &v), if same { "   ← stesso valore dell'ambiente attuale" } else { "" });
                let n = g.add(Node::new(label).probable().proof(loaded));
                if !same && current.is_some() {
                    n.add(Node::new("valore diverso da quello attuale: scavalcato, non caricato o ridefinito piu' avanti").probable());
                }
            }
        }
        if !g.children.is_empty() {
            root.add(g);
        }
    }
    if found == 0 {
        root.add(Node::new("nessuna definizione trovata nei file controllati").unknown().proof("shell, /etc, ~/.config/fish, .env e compose da qui fino alla home"));
        if current.is_some() {
            root.add(Node::new("eppure la variabile esiste: arriva da un programma che ha avviato la shell (terminale, sessione grafica, systemd --user) o da `export` fatto a mano").probable());
        }
    }
    root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_definitions() {
        assert_eq!(defines("export FOO=bar", "FOO").as_deref(), Some("bar"));
        assert_eq!(defines("FOO=\"a b\"", "FOO").as_deref(), Some("a b"));
        assert_eq!(defines("set -gx FOO bar", "FOO").as_deref(), Some("bar"));
        assert_eq!(defines("    - FOO=bar", "FOO").as_deref(), Some("bar"));
        assert_eq!(defines("  FOO: bar", "FOO").as_deref(), Some("bar"));
        assert_eq!(defines("# export FOO=bar", "FOO"), None);
        assert_eq!(defines("export FOOBAR=1", "FOO"), None);
    }

    #[test]
    fn hides_secrets() {
        assert!(show("API_TOKEN", "abcdef").contains("nascosto"));
        assert_eq!(show("PORT", "3000"), "3000");
        assert_eq!(show("DATABASE_URL", "postgres://u:pw@localhost/db"), "postgres://u:***@localhost/db");
    }
}
