use crate::graph::Node;
use crate::util::{has_token, run};

pub fn services(port: u16) -> Vec<Node> {
    let Some(out) = run("kubectl", &["get", "svc", "-A", "--no-headers", "-o", "custom-columns=NS:.metadata.namespace,NAME:.metadata.name,TYPE:.spec.type,PORT:.spec.ports[*].port,NODEPORT:.spec.ports[*].nodePort,TARGET:.spec.ports[*].targetPort"]) else { return vec![] };
    parse(&out, &port.to_string())
}

fn parse(out: &str, port: &str) -> Vec<Node> {
    out.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let [ns, name, kind, svc, node, target] = f[..] else { return None };
            let hit = [("service port", svc), ("node port", node), ("target port", target)].into_iter().find(|(_, v)| v.split(',').any(|x| has_token(x, port)))?;
            Some(Node::new(format!("Kubernetes Service {ns}/{name} ({kind}): {} {port}  [ports {svc} → target {target}, nodePort {node}]", hit.0)).proof("kubectl get svc -A"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_services_by_any_port() {
        let out = "default web NodePort 80 30080 8080\nkube-system dns ClusterIP 53,53 <none> 53\n";
        assert_eq!(parse(out, "30080").len(), 1);
        assert_eq!(parse(out, "8080").len(), 1);
        assert_eq!(parse(out, "53").len(), 1);
        assert!(parse(out, "9999").is_empty());
    }
}
