//! Shell completion scripts. They call back `why __complete port|env` to get the live names.

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
complete -c why -n '__fish_use_subcommand' -a env -d 'Where an environment variable comes from'
complete -c why -n '__fish_use_subcommand' -a completions -d 'Print a shell completion script'
complete -c why -n '__fish_seen_subcommand_from port' -a 'list' -d 'List every listening port'
complete -c why -n '__fish_seen_subcommand_from port' -a '(why __complete port)'
complete -c why -n '__fish_seen_subcommand_from env' -a 'list' -d 'List every variable'
complete -c why -n '__fish_seen_subcommand_from env' -a '(why __complete env)'
complete -c why -n '__fish_seen_subcommand_from completions' -a 'fish bash zsh'
"#;

const BASH: &str = r#"_why() {
  local cur=${COMP_WORDS[COMP_CWORD]}
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=($(compgen -W "port env completions" -- "$cur"))
  else
    case ${COMP_WORDS[1]} in
      port|env) COMPREPLY=($(compgen -W "list $(why __complete "${COMP_WORDS[1]}" | cut -f1)" -- "$cur")) ;;
      completions) COMPREPLY=($(compgen -W "fish bash zsh" -- "$cur")) ;;
    esac
  fi
}
complete -F _why why
"#;

const ZSH: &str = r#"#compdef why
_why() {
  if (( CURRENT == 2 )); then
    compadd port env completions
  else
    case $words[2] in
      port|env) compadd list ${(f)"$(why __complete $words[2] | cut -f1)"} ;;
      completions) compadd fish bash zsh ;;
    esac
  fi
}
_why "$@"
"#;
