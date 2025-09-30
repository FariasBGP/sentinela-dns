#!/usr/bin/env bash
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C

# Uso: top-nxdomain.sh [janela] [topN]
# Ex.: top-nxdomain.sh 12h 20   -> últimas 12h, top 20
WINDOW="${1:-12h}"
TOPN="${2:-20}"

OUTDIR="/var/lib/node_exporter/textfile_collector"
OUTTMP="${OUTDIR}/sentinela_nxdomain.prom.$$"
OUT="${OUTDIR}/sentinela_nxdomain.prom"

# Arquivo opcional com IPs para excluir (um por linha)
EXCLUDE_FILE="/etc/sentinela/nxdomain.exclude"
EXCLUDE_REGEX=""
if [[ -f "$EXCLUDE_FILE" ]]; then
  EXCLUDE_REGEX="$(grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$EXCLUDE_FILE" | paste -sd'|' - || true)"
fi

# Busca logs do Unbound e filtra NXDOMAIN
LOGS="$(journalctl -u unbound -S -"${WINDOW}" --no-pager | grep ' NXDOMAIN ' || true)"

# Contagem total
TOTAL="$(printf '%s\n' "$LOGS" | wc -l | tr -d ' ')"
TS="$(date +%s)"

# Top IPs
IPS="$(printf '%s\n' "$LOGS" \
  | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
  | { if [[ -n "$EXCLUDE_REGEX" ]]; then grep -Ev "^(${EXCLUDE_REGEX})$"; else cat; fi; } \
  | sort | uniq -c | sort -nr | head -"$TOPN")"

# Top domínios (A/AAAA/PTR/HTTPS IN NXDOMAIN)
DOMS="$(printf '%s\n' "$LOGS" \
  | grep -oP '(?<=\s)[A-Za-z0-9._-]+\.(arpa|[a-z]{2,})(?=\.\s+(A|AAAA|PTR|HTTPS)\s+IN\s+NXDOMAIN)' \
  | sort | uniq -c | sort -nr | head -"$TOPN")"

# Escreve métricas em formato Prometheus
{
  echo "# HELP sentinela_nxdomain_total Total de NXDOMAIN no intervalo"
  echo "# TYPE sentinela_nxdomain_total gauge"
  echo "sentinela_nxdomain_total{window=\"${WINDOW}\"} ${TOTAL} ${TS}"

  echo
  echo "# HELP sentinela_nxdomain_ip_count NXDOMAIN por IP de origem no intervalo"
  echo "# TYPE sentinela_nxdomain_ip_count gauge"
  if [[ -n "${IPS}" ]]; then
    while read -r c ip; do
      [[ -z "$ip" ]] && continue
      echo "sentinela_nxdomain_ip_count{ip=\"${ip}\",window=\"${WINDOW}\"} ${c} ${TS}"
    done <<< "$IPS"
  fi

  echo
  echo "# HELP sentinela_nxdomain_domain_count NXDOMAIN por domínio no intervalo"
  echo "# TYPE sentinela_nxdomain_domain_count gauge"
  if [[ -n "${DOMS}" ]]; then
    while read -r c dom; do
      [[ -z "$dom" ]] && continue
      dom_esc="${dom//\"/\\\"}"
      echo "sentinela_nxdomain_domain_count{domain=\"${dom_esc}\",window=\"${WINDOW}\"} ${c} ${TS}"
    done <<< "$DOMS"
  fi
} > "$OUTTMP"

# Grava de forma atômica
install -m 0644 "$OUTTMP" "$OUT"
rm -f "$OUTTMP"