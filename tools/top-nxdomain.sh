#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C LANG=C
umask 022

WINDOW="${1:-12h}"
TOPN="${2:-20}"

OUTDIR="/var/lib/node_exporter/textfile_collector"
OUT="${OUTDIR}/sentinela_nxdomain.prom"
TMP="${OUT}.tmp.$$"

mkdir -p "$OUTDIR"
chown prometheus:prometheus "$OUTDIR" || true
chmod 755 "$OUTDIR" || true

# Função pra coletar total NXDOMAIN via pipeline
total_nxdomain() {
  journalctl -u unbound -S -"${WINDOW}" --no-pager 2>/dev/null | grep -F ' NXDOMAIN ' | wc -l | tr -d ' ' || echo 0
}

# Função pra top IPs via pipeline
top_ips() {
  journalctl -u unbound -S -"${WINDOW}" --no-pager 2>/dev/null | grep -F ' NXDOMAIN ' \
    | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
    | sort | uniq -c | sort -nr | head -"$TOPN" || true
}

# Função pra top domínios via pipeline (melhorei o sed pra robustez)
top_domains() {
  journalctl -u unbound -S -"${WINDOW}" --no-pager 2>/dev/null | sed -nE 's/.*[[:space:]]([A-Za-z0-9._-]+\.(arpa|[a-z]{2,}))\.?[[:space:]]+(A|AAAA|PTR|HTTPS)[[:space:]]+IN[[:space:]]+NXDOMAIN.*/\1/p' \
    | sort | uniq -c | sort -nr | head -"$TOPN" || true
}

# Coleta dados
TOTAL="$(total_nxdomain)"
IPS="$(top_ips)"
DOMS="$(top_domains)"

# Emite métricas
{
  echo "# HELP sentinela_nxdomain_total Total NXDOMAIN in window"
  echo "# TYPE sentinela_nxdomain_total gauge"
  echo "sentinela_nxdomain_total{window=\"${WINDOW}\"} ${TOTAL}"

  echo
  echo "# HELP sentinela_nxdomain_ip_count NXDOMAIN by source IP in window"
  echo "# TYPE sentinela_nxdomain_ip_count gauge"
  if [ -n "${IPS}" ]; then
    while read -r c ip; do
      [ -z "${ip}" ] && continue
      echo "sentinela_nxdomain_ip_count{ip=\"${ip}\",window=\"${WINDOW}\"} ${c}"
    done <<< "$IPS"
  fi

  echo
  echo "# HELP sentinela_nxdomain_domain_count NXDOMAIN by domain in window"
  echo "# TYPE sentinela_nxdomain_domain_count gauge"
  if [ -n "${DOMS}" ]; then
    while read -r c dom; do
      [ -z "${dom}" ] && continue
      dom_esc="${dom//\\/\\\\}"
      dom_esc="${dom_esc//\"/\\\"}"
      echo "sentinela_nxdomain_domain_count{domain=\"${dom_esc}\",window=\"${WINDOW}\"} ${c}"
    done <<< "$DOMS"
  fi
} > "$TMP"

# Normaliza e instala
sed -i 's/\r$//' "$TMP" || true
install -m 0644 "$TMP" "$OUT"
chown prometheus:prometheus "$OUT" || true
rm -f "$TMP"
