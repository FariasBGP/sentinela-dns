#!/usr/bin/env bash
# Sentinela-DNS — health.sh
set -euo pipefail

GREEN="\033[1;32m"; YELLOW="\033[1;33m"; RED="\033[1;31m"; RESET="\033[0m"
ok(){ echo -e "✔ ${GREEN}$*${RESET}"; }
warn(){ echo -e "▲ ${YELLOW}$*${RESET}"; }
err(){ echo -e "✖ ${RED}$*${RESET}"; }

echo ">> Checando serviços..."
for s in unbound unbound_exporter prometheus grafana-server prometheus-node-exporter; do
  if systemctl is-active --quiet "$s"; then ok "service: $s -> active"; else warn "service: $s -> inactive"; fi
done

echo ">> Checando portas..."
ss -tuln | grep -E ':(53|8953|9090|9100|9167|3000)\b' || warn "nenhuma das portas alvo apareceu"

echo ">> Endpoints:"
for u in \
  http://127.0.0.1:9100/metrics \
  http://127.0.0.1:9167/metrics \
  http://127.0.0.1:9090/-/ready \
  http://127.0.0.1:3000/api/health
do
  printf "%s -> " "$u"
  curl -fsS --max-time 5 "$u" >/dev/null && echo OK || echo FAIL
done

echo ">> unbound-control status:"
unbound-control -c /etc/unbound/unbound.conf status || warn "unbound-control falhou (verifique remote-control/certs)"

echo ">> DNS (teste simples):"
if command -v dig >/dev/null 2>&1; then
  dig @127.0.0.1 cloudflare.com A +dnssec +nocmd +noall +answer || warn "dig falhou"
else
  warn "dig não instalado"
fi
