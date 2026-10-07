//! A package as a dependency of the project in the current directory (npm, cargo, pip, dotnet): shared by every platform.
use crate::graph::Node;
use crate::util::{on_path, run, short};
use std::fs;
use std::path::Path;

fn field(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| l.strip_prefix(key)?.trim_start().strip_prefix(':').map(|v| v.trim().to_string()))
}

/// The package as a dependency of the project in the current directory (npm, cargo, pip, dotnet).
pub fn project(root: &mut Node, name: &str) -> bool {
    let mut found = false;
    let mut add = |tool: &str, out: Option<String>, proof: &str| {
        if let Some(o) = out.filter(|o| !o.trim().is_empty()) {
            let mut n = Node::new(format!("dependency in this project ({tool})")).proof(proof.to_string());
            for l in o.lines().take(14) {
                n.add(Node::new(short(l.trim_end(), 130)));
            }
            root.add(n);
            found = true;
        }
    };
    if Path::new("package-lock.json").exists() && on_path("npm") {
        add("npm", run("npm", &["explain", name]), "npm explain");
    }
    if Path::new("Cargo.lock").exists() && on_path("cargo") {
        add("cargo", run("cargo", &["tree", "--offline", "-i", name]), "cargo tree -i");
    }
    if (Path::new("requirements.txt").exists() || Path::new("pyproject.toml").exists()) && on_path("pip") {
        add("pip", run("pip", &["show", name]).map(|s| format!("{}\n{}", field(&s, "Version").map(|v| format!("version {v}")).unwrap_or_default(), field(&s, "Required-by").map(|r| format!("required by: {r}")).unwrap_or_default())), "pip show");
    }
    if on_path("dotnet") {
        if let Some(proj) = fs::read_dir(".").ok().and_then(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).find(|n| n.ends_with(".csproj") || n.ends_with(".sln"))) {
            add("dotnet", run("dotnet", &["nuget", "why", &proj, name]), "dotnet nuget why (needs the .NET 10 SDK)");
        }
    }
    found
}

