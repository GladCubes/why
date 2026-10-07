//! The chain of explanations: every node says what it is, how I know (proof) and how sure I am.
use std::io::IsTerminal;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Certainty {
    /// read directly from the system
    Certain,
    /// derived from a text match: probable, not proven
    Probable,
    /// I could not verify it
    Unknown,
}

pub struct Node {
    pub label: String,
    pub proof: Option<String>,
    pub certainty: Certainty,
    pub children: Vec<Node>,
}

impl Node {
    pub fn new(label: impl Into<String>) -> Self {
        Node { label: label.into(), proof: None, certainty: Certainty::Certain, children: vec![] }
    }
    pub fn proof(mut self, p: impl Into<String>) -> Self {
        self.proof = Some(p.into());
        self
    }
    pub fn probable(mut self) -> Self {
        self.certainty = Certainty::Probable;
        self
    }
    pub fn unknown(mut self) -> Self {
        self.certainty = Certainty::Unknown;
        self
    }
    pub fn add(&mut self, child: Node) -> &mut Node {
        self.children.push(child);
        self.children.last_mut().unwrap()
    }
}

/// Prints the tree. It writes through one buffer so a closed pipe (`why ... | head`) does not panic.
pub fn print(root: &Node) {
    use std::io::Write;
    let color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let mut out = format!("{}\n", line(root, color));
    render(root, "", color, &mut out);
    let _ = std::io::stdout().write_all(out.as_bytes());
}

fn render(n: &Node, prefix: &str, color: bool, out: &mut String) {
    for (i, c) in n.children.iter().enumerate() {
        let last = i + 1 == n.children.len();
        out.push_str(&format!("{prefix}{}{}\n", if last { "└── " } else { "├── " }, line(c, color)));
        render(c, &format!("{prefix}{}", if last { "    " } else { "│   " }), color, out);
    }
}

fn line(n: &Node, color: bool) -> String {
    let (mark, tint) = match n.certainty {
        Certainty::Certain => ("", "\x1b[1m"),
        Certainty::Probable => ("≈ ", "\x1b[33m"),
        Certainty::Unknown => ("? ", "\x1b[31m"),
    };
    let proof = n.proof.as_ref().map(|p| format!("  ← {p}")).unwrap_or_default();
    if color {
        format!("{tint}{mark}{}\x1b[0m\x1b[2m{proof}\x1b[0m", n.label)
    } else {
        format!("{mark}{}{proof}", n.label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_uncertain_nodes() {
        let n = Node::new("a").probable();
        assert_eq!(line(&n, false), "≈ a");
        assert_eq!(line(&Node::new("b").unknown().proof("x"), false), "? b  ← x");
    }
}
