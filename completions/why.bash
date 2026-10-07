_why() {
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
