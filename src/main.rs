//! why: perche' questa porta, questa variabile, questa cosa e' cosi'? Ogni passaggio ha la sua prova.
mod graph;
#[cfg(target_os = "linux")]
mod linux;
mod util;

const HELP: &str = "why: ricostruisce da dove arriva una cosa, con la prova di ogni passaggio

USO
  why port <N>      chi ascolta su una porta, come e' stato avviato, quale configurazione la nomina
  why env <NOME>    dove e' definita una variabile e quale valore vale ora

LEGENDA
  riga normale    letto direttamente dal sistema
  ≈ riga          corrispondenza di testo: probabile, non dimostrato
  ? riga          non sono riuscito a verificarlo

Per vedere i processi di altri utenti e le regole del firewall serve sudo.";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let tree = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["port", n] => match n.parse::<u16>() {
            Ok(p) => explain_port(p),
            Err(_) => return fail(&format!("`{n}` non e' una porta valida (1-65535)")),
        },
        ["env", name] => explain_env(name),
        [] | ["-h"] | ["--help"] | ["help"] => return println!("{HELP}"),
        _ => return fail("comando non riconosciuto, prova `why --help`"),
    };
    graph::print(&tree);
}

fn fail(msg: &str) {
    eprintln!("why: {msg}");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn explain_port(p: u16) -> graph::Node {
    linux::port::explain(p)
}
#[cfg(target_os = "linux")]
fn explain_env(n: &str) -> graph::Node {
    linux::env::explain(n)
}

#[cfg(not(target_os = "linux"))]
fn explain_port(_: u16) -> graph::Node {
    graph::Node::new("questa piattaforma non e' ancora supportata").unknown()
}
#[cfg(not(target_os = "linux"))]
fn explain_env(_: &str) -> graph::Node {
    graph::Node::new("questa piattaforma non e' ancora supportata").unknown()
}
