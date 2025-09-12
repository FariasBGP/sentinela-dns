#!/usr/bin/env bash
set -euo pipefail

# ==========================
# CONFIG PADRÃO
# ==========================
REQUIRED_OS="Debian 12"
ARCH_REQUIRED="x86_64"     # amd64
GRAFANA_APT_FILE="/etc/apt/sources.list.d/grafana.list"
PROM_TARGET_HOST="${PROM_TARGET_HOST:-localhost}"
PROM_TARGET_PORT="${PROM_TARGET_PORT:-9090}"

CHECK_PORTS_UDP=(53)                  # Unbound
CHECK_PORTS_TCP=(53 9100 9167 3000)   # Unbound, node_exporter, unbound_exporter, Grafana

REQUIRED_CMDS=(curl wget jq tar awk grep sed systemctl)
OPTIONAL_CMDS=(dig host ss)
PKGS_UTILS=(curl wget jq tar ca-certificates gnupg lsb-release apt-transport-https netcat-openbsd iproute2)
PKG_NODE_EXPORTER="prometheus-node-exporter"
PKG_UNBOUND="unbound"

DO_FIX=0
[[ "${1:-}" == "--fix" ]] && DO_FIX=1

CLR_RESET="\033[0m"; CLR_OK="\033[32m"; CLR_WARN="\033[33m"; CLR_ERR="\033[31m"; CLR_INFO="\033[36m"
ok(){   echo -e "${CLR_OK}✔$CLR_RESET $*"; }
warn(){ echo -e "${CLR_WARN}▲$CLR_RESET $*"; }
err(){  echo -e "${CLR_ERR}✖$CLR_RESET $*"; }
inf(){  echo -e "${CLR_INFO}ℹ$CLR_RESET $*"; }

FAILS=()
add_fail(){ FAILS+=("$*"); err "$*"; }

# ==========================
# ROOT
# ==========================
if [[ $EUID -ne 0 ]]; then
  add_fail "Execute como root. Ex.: su - ; ./preflight.sh"
  echo; echo "Resumo: ${#FAILS[@]} pendência(s)."; exit 1
fi

# ==========================
# OS / ARCH
# ==========================
OS_NAME="$(lsb_release -sd 2>/dev/null || true)"
DEBIAN_VER="$(cat /etc/debian_version 2>/dev/null || true)"
ARCH="$(uname -m)"

if [[ "$OS_NAME" =~ Debian\ GNU/Linux\ 12.* ]] || [[ "$DEBIAN_VER" =~ ^12 ]]; then
  ok "SO: $OS_NAME (debian_version: $DEBIAN_VER)"
else
  add_fail "SO não é Debian 12. Detectado: '$OS_NAME' (debian_version: $DEBIAN_VER)"
fi

if [[ "$ARCH" == "$ARCH_REQUIRED" ]]; then
  ok "Arquitetura: $ARCH"
else
  add_fail "Arquitetura esperada '$ARCH_REQUIRED', detectado '$ARCH'"
fi

# ==========================
# Conectividade externa
# ==========================
check_http(){ local url="$1"
  if curl -fsSL --max-time 8 "$url" >/dev/null; then ok "Acesso OK: $url"; else add_fail "Sem acesso: $url"; fi
}
inf "Checando acesso externo…"
check_http "https://github.com/"
check_http "https://api.github.com/"
check_http "https://packages.grafana.com/"
check_http "https://deb.debian.org/"

# ==========================
# Binários necessários
# ==========================
MISSING_CMDS=()
for c in "${REQUIRED_CMDS[@]}"; do
  if command -v "$c" >/dev/null 2>&1; then ok "Binário presente: $c"; else MISSING_CMDS+=("$c"); add_fail "Falta binário: $c"; fi
done
for c in "${OPTIONAL_CMDS[@]}"; do
  if command -v "$c" >/dev/null 2>&1; then ok "Opcional presente: $c"; else warn "Opcional ausente: $c"; fi
done

if (( DO_FIX )) && ((${#MISSING_CMDS[@]} > 0)); then
  inf "Instalando utilitários básicos… (${PKGS_UTILS[*]})"
  apt-get update -y && apt-get install -y "${PKGS_UTILS[@]}" || add_fail "Falha ao instalar utilitários básicos."
fi

# ==========================
# RESUMO FINAL
# ==========================
echo
echo "================== RESUMO =================="
if ((${#FAILS[@]}==0)); then
  ok "Pré-check finalizado: ambiente OK para instalar."
  exit 0
else
  err "Foram encontradas ${#FAILS[@]} pendência(s):"
  for f in "${FAILS[@]}"; do echo " - $f"; done
  exit 1
fi
