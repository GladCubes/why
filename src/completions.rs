//! Shell completion scripts. They call back `why __complete <kind>` to get the live names.

pub fn script(shell: &str) -> Option<&'static str> {
    Some(match shell {
        "fish" => FISH,
        "bash" => BASH,
        "zsh" => ZSH,
        _ => return None,
    })
}

const FISH: &str = r#"complete -c why -f
complete -c why -n '__fish_use_subcommand' -a port -d 'Who listens on a port, and why'
complete -c why -n '__fish_use_subcommand' -a process -d 'Why a process exists'
complete -c why -n '__fish_use_subcommand' -a file -d 'Where a file comes from and what uses it'
complete -c why -n '__fish_use_subcommand' -a service -d 'Why a service is running'
complete -c why -n '__fish_use_subcommand' -a package -d 'Why a package is installed'
complete -c why -n '__fish_use_subcommand' -a env -d 'Where an environment variable comes from'
complete -c why -n '__fish_use_subcommand' -a snapshot -d 'A picture of this machine'
complete -c why -n '__fish_use_subcommand' -a compare -d 'What differs between two machines'
complete -c why -n '__fish_use_subcommand' -a completions -d 'Print a shell completion script'
complete -c why -n '__fish_seen_subcommand_from port' -a 'list tcp udp' -d 'List ports / protocol'
complete -c why -n '__fish_seen_subcommand_from port' -a '(why __complete port)'
complete -c why -n '__fish_seen_subcommand_from env' -a 'list' -d 'List every variable'
complete -c why -n '__fish_seen_subcommand_from env' -a '(why __complete env)'
complete -c why -n '__fish_seen_subcommand_from process service package' -a 'list' -d 'List them all'
complete -c why -n '__fish_seen_subcommand_from process' -a '(why __complete process)'
complete -c why -n '__fish_seen_subcommand_from service' -a '(why __complete service)'
complete -c why -n '__fish_seen_subcommand_from package' -a '(why __complete package)'
complete -c why -n '__fish_seen_subcommand_from file' -F
complete -c why -n '__fish_seen_subcommand_from compare' -a 'local' -F
complete -c why -n '__fish_seen_subcommand_from completions' -a 'fish bash zsh'
"#;

const BASH: &str = r#"_why() {
  local cur=${COMP_WORDS[COMP_CWORD]}
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=($(compgen -W "port process file service package env snapshot compare completions" -- "$cur"))
  else
    case ${COMP_WORDS[1]} in
      port) COMPREPLY=($(compgen -W "list tcp udp $(why __complete port | cut -f1)" -- "$cur")) ;;
      env) COMPREPLY=($(compgen -W "list $(why __complete env | cut -f1)" -- "$cur")) ;;
      process|service|package) COMPREPLY=($(compgen -W "list $(why __complete "${COMP_WORDS[1]}" | cut -f1)" -- "$cur")) ;;
      file|compare) COMPREPLY=($(compgen -f -- "$cur")) ;;
      completions) COMPREPLY=($(compgen -W "fish bash zsh" -- "$cur")) ;;
    esac
  fi
}
complete -F _why why
"#;

const ZSH: &str = r#"#compdef why
_why() {
  if (( CURRENT == 2 )); then
    compadd port process file service package env snapshot compare completions
  else
    case $words[2] in
      port) compadd list tcp udp ${(f)"$(why __complete port | cut -f1)"} ;;
      env) compadd list ${(f)"$(why __complete env | cut -f1)"} ;;
      process|service|package) compadd list ${(f)"$(why __complete $words[2] | cut -f1)"} ;;
      file|compare) _files ;;
      completions) compadd fish bash zsh ;;
    esac
  fi
}
_why "$@"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    /// The files shipped in packages (`completions/`) must match what `why completions` prints.
    #[test]
    fn packaged_files_match() {
        // compared without carriage returns: a Windows checkout may convert line endings
        let same = |shell: &str, file: &str| script(shell).map(|s| s.replace('\r', "")) == Some(file.replace('\r', ""));
        assert!(same("bash", include_str!("../completions/why.bash")));
        assert!(same("fish", include_str!("../completions/why.fish")));
        assert!(same("zsh", include_str!("../completions/_why")));
    }
}
