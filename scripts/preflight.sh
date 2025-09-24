#!/usr/bin/env bash
# Sentinela-DNS — preflight.sh
# Suporta Debian 12 (bookworm) e Debian 13 (trixie).

set -o nounset
set -o pipefail

GREEN="\033[1;32m"; RED="\033[1;31m"; YELLOW="\033[1;33m"; CYAN="\033[1;36m"; BOLD="\033[1m"; RESET="\033[0m"
ok()   { echo -e "✔ ${GREEN}$*${RESET}"; }
warn() { echo -e "⚠ ${YELLOW}$*${RESET}"; }
err()  { echo -e "✖ ${RED}$*${RESET}"; }

PEND=0
add_pend(){ PEND=$((PEND+1)); err "$@"; }

echo -e ">> ${BOLD}Pré-check...${RESET}"

# Detecta SO
OS_NAME="Desconhecido"; DEBIAN_VERSION=""; DEBIAN_CODENAME=""
ARCH="$(uname -m)"
[[ -r /etc/os-release ]] && . /etc/os-release && {
  OS_NAME="${PRETTY_NAME:-$NAME}"
  DEBIAN_VERSION="${VERSION_ID:-}"
  DEBIAN_CODENAME="${VERSION_CODENAME:-}"
}

echo -e "  Arquitetura: ${BOLD}${ARCH}${RESET}"
case "${DEBIAN_VERSION%%.*}" in
  12|13) ok "SO OK: Debian ${DEBIAN_VERSION} (${DEBIAN_CODENAME}) detectado." ;;
  *)     warn "SO não testado oficialmente: ${OS_NAME} (${DEBIAN_VERSION:-?})";;
esac

# Acesso externo (não trava)
check_url(){ curl -fsS --max-time 5 -o /dev/null "$1" && ok "Acesso OK: $1" || warn "Acesso FALHOU: $1"; }
check_url "https://github.com/"
check_url "https://api.github.com/"
check_url "https://packages.grafana.com/"
check_url "https://deb.debian.org/"

# Binários
need_bins=(curl wget jq tar awk grep sed systemctl)
opt_bins=(dig host ss nc)
for b in "${need_bins[@]}"; do
  command -v "$b" >/dev/null 2>&1 && ok "Binário presente: $b" \
    || add_pend "Binário ausente: $b (apt-get update && apt-get install -y $b)"
done
for b in "${opt_bins[@]}"; do
  command -v "$b" >/dev/null 2>&1 && ok "Opcional presente: $b" \
    || warn "Opcional ausente: $b (recomendado instalar)"
done

# systemd / journal
systemctl --version >/dev/null 2>&1 && ok "systemd OK" || add_pend "systemd indisponível"
[[ -d /var/log/journal ]] && ok "journal persistente presente (/var/log/journal)" \
  || warn "journal persistente ausente (recomendado: mkdir -p /var/log/journal)"

# Pacotes Debian necessários (inclui libssl3 e unbound-anchor)
need_pkgs=(libssl3 unbound-anchor)
for p in "${need_pkgs[@]}"; do
  dpkg -s "$p" >/dev/null 2>&1 && ok "Pacote presente: $p" \
    || warn "Pacote ausente: $p (instalar: apt-get install -y $p)"
done

echo
echo "================ RESUMO ================"
if [[ $PEND -gt 0 ]]; then
  add_pend "Foram encontradas ${PEND} pendência(s)."
  echo -e "${YELLOW}Sugestão:${RESET} apt-get update && apt-get install -y ${need_bins[*]}"
  exit 1
else
  ok "Nenhuma pendência crítica encontrada."
  echo -e "SO detectado: '${OS_NAME}' (debian_version: ${DEBIAN_VERSION:-?}, codename: ${DEBIAN_CODENAME:-?})"
  echo -e "Pronto para prosseguir com ${BOLD}make install${RESET}."
  exit 0
fi
