#!/bin/bash
# Sentinela-DNS — health.sh
# Checa saúde dos serviços e Unbound, com resumo.

set -uo pipefail  # Removido -e para evitar exits em erros não críticos

GREEN="\033[1;32m"; RED="\033[1;31m"; YELLOW="\033[1;33m"; RESET="\033[0m"
ok()   { echo -e "✔ ${GREEN}$*${RESET}"; }
warn() { echo -e "⚠ ${YELLOW}$*${RESET}"; }
err()  { echo -e "✖ ${RED}$*${RESET}"; }

echo ">> Checando saúde dos serviços (resumido)..."

# Serviços principais
for s in unbound unbound_exporter prometheus grafana-server prometheus-node-exporter; do
  if systemctl is-active --quiet $s; then
    ok "$s: ATIVO"
  else
    warn "$s: INATIVO (verifique se instalado)"
  fi
done

# Portas essenciais (resumo)
echo ">> Portas essenciais:"
PORTS_OK=1
if ! ss -tuln | grep -q ':53 '; then PORTS_OK=0; warn "Porta 53 (DNS) ausente"; fi
if ! ss -tuln | grep -q ':8953 '; then PORTS_OK=0; warn "Porta 8953 (control) ausente"; fi
if ! ss -tuln | grep -q ':9090 '; then PORTS_OK=0; warn "Porta 9090 (Prometheus) ausente"; fi
if ! ss -tuln | grep -q ':9167 '; then PORTS_OK=0; warn "Porta 9167 (unbound_exporter) ausente"; fi
if ! ss -tuln | grep -q ':3000 '; then PORTS_OK=0; warn "Porta 3000 (Grafana) ausente"; fi
[ $PORTS_OK -eq 1 ] && ok "Todas portas OK" || err "Algumas portas ausentes"

# Endpoints de saúde
echo ">> Endpoints de saúde:"
for u in \
  http://127.0.0.1:9167/metrics \
  http://127.0.0.1:9090/-/ready \
  http://127.0.0.1:3000/api/health; do
  if curl -fsS --max-time 5 $u >/dev/null 2>&1; then
    ok "$u: OK"
  else
    warn "$u: FAIL (pode ser esperado se não instalado)"
  fi
done

# Verificações específicas do Unbound
echo ">> Resumo Unbound:"
STATUS_SUMMARY=$(systemctl status unbound --no-pager -l | grep -E 'Active|Main PID|CPU|Memory' | sed 's/^/  /' || echo "  Status indisponível")
echo "$STATUS_SUMMARY"

echo ">> Logs recentes (erros/warnings):"
LOGS_ERRORS=$(journalctl -u unbound -n 20 --no-pager | grep -iE 'error|warning|fatal' | sed 's/^/  /' || echo "  Nenhum erro recente")
echo "$LOGS_ERRORS"

echo ">> Teste de resolução DNS:"
if dig @127.0.0.1 google.com +short +time=1 | grep -qE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
  ok "Resolução OK (rápida)"
else
  err "Resolução falhou"
fi

echo ">> Resumo Estatísticas Unbound:"
STATS=$(unbound-control stats_noreset 2>/dev/null)
if [ -n "$STATS" ]; then
  TOTAL_QUERIES=$(echo "$STATS" | grep total.num.queries= | cut -d= -f2)
  CACHE_HITS=$(echo "$STATS" | grep total.num.cachehits= | cut -d= -f2)
  CACHE_MISS=$(echo "$STATS" | grep total.num.cachemiss= | cut -d= -f2)
  BOGUS=$(echo "$STATS" | grep num.answer.bogus= | cut -d= -f2 || echo 0)
  HIT_RATIO=$(awk "BEGIN {print int(($CACHE_HITS / ($CACHE_HITS + $CACHE_MISS)) * 100)}")
  ok "Queries Total: $TOTAL_QUERIES | Cache Hit Ratio: ${HIT_RATIO}% | Bogus: $BOGUS"
else
  warn "unbound-control falhou (verifique remote-control no conf)"
fi

echo ">> Resumo Métricas exporter:"
if systemctl is-active --quiet unbound_exporter; then
  METRICS=$(curl -s http://127.0.0.1:9167/metrics 2>/dev/null)
  if [ -n "$METRICS" ]; then
    HITS=$(echo "$METRICS" | grep unbound_cache_hits | awk '{sum+=$2} END {print int(sum)}')
    QUERIES=$(echo "$METRICS" | grep unbound_queries | awk '{sum+=$2} END {print int(sum)}')
    HIT_RATIO=$(awk "BEGIN {print int(($HITS / $QUERIES) * 100)}")
    ok "Queries: $QUERIES | Hits: $HITS | Ratio: ${HIT_RATIO}%"
  else
    warn "Métricas indisponíveis (curl falhou)"
  fi
else
  warn "Exporter inativo; skip métricas"
fi
