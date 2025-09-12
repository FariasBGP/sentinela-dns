#!/usr/bin/env bash
set -euo pipefail

CLR_RESET="\033[0m"; CLR_OK="\033[32m"; CLR_WARN="\033[33m"; CLR_ERR="\033[31m"; CLR_INFO="\033[36m"
ok(){   echo -e "${CLR_OK}✔$CLR_RESET $*"; }
warn(){ echo -e "${CLR_WARN}▲$CLR_RESET $*"; }
err(){  echo -e "${CLR_ERR}✖$CLR_RESET $*"; }
inf(){  echo -e "${CLR_INFO}ℹ$CLR_RESET $*"; }

fail=0; add_fail(){ err "$*"; fail=$((fail+1)); }

svc_check(){ local s="$1"
  if systemctl is-active --quiet "$s"; then ok "Serviço ativo: $s"; else add_fail "Serviço INATIVO: $s"; fi
}

probe_http(){ local url="$1" name="$2"
  if curl -fsS --max-time 5 "$url" >/dev/null; then ok "Endpoint OK: $name ($url)"
  else add_fail "Falha endpoint: $name ($url)"; fi
}

# --- Serviços
inf "Checando serviços…"
svc_check unbound
svc_check unbound_exporter
svc_check grafana-server
svc_check prometheus
svc_check prometheus-node-exporter || svc_check node-exporter || true

# --- Portas (se 'ss' existir)
if command -v ss >/dev/null 2>&1; then
  inf "Checando portas (LISTEN)…"
  for p in 53 9100 9167 9090 3000; do
    if ss -tuln | grep -q ":$p\b"; then ok "Porta $p ouvindo"; else add_fail "Porta $p não está ouvindo"; fi
  done
fi

# --- Endpoints HTTP
inf "Checando endpoints HTTP…"
probe_http "http://127.0.0.1:9100/metrics" "node_exporter"
probe_http "http://127.0.0.1:9167/metrics" "unbound_exporter"
probe_http "http://127.0.0.1:9090/-/ready"  "Prometheus ready"
probe_http "http://127.0.0.1:3000/api/health" "Grafana health"

# --- Unbound-control (opcional)
if command -v unbound-control >/dev/null 2>&1; then
  if unbound-control status >/dev/null 2>&1; then
    ok "unbound-control responde (status OK)"
  else
    warn "unbound-control não respondeu (certs/remote-control?)."
  fi
fi

# --- Prometheus targets (opcional)
if curl -fsS --max-time 5 "http://127.0.0.1:9090/api/v1/targets" >/tmp/targets.json 2>/dev/null; then
  up_unbound=$(jq -r '.data.activeTargets[]?|select(.labels.job=="unbound")|.health' /tmp/targets.json | grep -c "up" || true)
  up_node=$(jq -r '.data.activeTargets[]?|select(.labels.job=="node")|.health' /tmp/targets.json | grep -c "up" || true)
  [[ "$up_unbound" -ge 1 ]] && ok "Prometheus vê unbound_exporter (targets up: $up_unbound)" || add_fail "Prometheus NÃO vê unbound_exporter"
  [[ "$up_node"    -ge 1 ]] && ok "Prometheus vê node_exporter (targets up: $up_node)"       || add_fail "Prometheus NÃO vê node_exporter"
else
  warn "Não consegui consultar /api/v1/targets do Prometheus."
fi

echo
echo "================== RESUMO =================="
if (( fail == 0 )); then
  ok "Tudo saudável 🚀"
  exit 0
else
  err "$fail verificação(ões) falhou/falharam."
  exit 1
fi
