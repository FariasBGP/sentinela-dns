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

# Limita linhas pra 100.000 para maior cobertura em tráfego alto (ajuste se necessário)
total_nxdomain() {
  journalctl -u unbound -S -"${WINDOW}" --lines=100000 --no-pager 2>/dev/null | grep ' IN NXDOMAIN ' | wc -l | tr -d ' ' || echo 0
}

# Função otimizada para top IPs: extrai apenas o campo do IP após "info: "
top_ips() {
  journalctl -u unbound -S -"${WINDOW}" --lines=100000 --no-pager 2>/dev/null | grep ' IN NXDOMAIN ' \
    | awk '/info:/ {print $8}' \
    | sort | uniq -c | sort -nr | head -"$TOPN" || true
}

# Função corrigida para top domínios: extrai o domínio após o IP, removendo o ponto final
top_domains() {
  journalctl -u unbound -S -"${WINDOW}" --lines=100000 --no-pager 2>/dev/null | grep ' IN NXDOMAIN ' \
    | awk '/info:/ {sub(/\.$/,"",$9); print $9}' \
    | sort | uniq -c | sort -nr | head -"$TOPN" || true
}

# Executa em paralelo
top_ips > "${TMP}.ips" &
top_domains > "${TMP}.doms" &
TOTAL="$(total_nxdomain)"
wait

IPS="$(cat "${TMP}.ips")"
DOMS="$(cat "${TMP}.doms")"
rm -f "${TMP}.ips" "${TMP}.doms"

# Debug: Imprime no terminal pra teste
echo "DEBUG: Total NXDOMAIN: ${TOTAL}"
echo "DEBUG: Top IPs:"
echo "${IPS}"
echo "DEBUG: Top Domains:"
echo "${DOMS}"

# Emite métricas com melhorias: adiciona timestamp se necessário, escapa corretamente
{
  echo "# HELP sentinela_nxdomain_total Total de respostas NXDOMAIN na janela de tempo"
  echo "# TYPE sentinela_nxdomain_total gauge"
  echo "sentinela_nxdomain_total{window=\"${WINDOW}\"} ${TOTAL}"
  echo
  echo "# HELP sentinela_nxdomain_ip_count Contagem de NXDOMAIN por IP de origem na janela de tempo"
  echo "# TYPE sentinela_nxdomain_ip_count gauge"
  if [ -n "${IPS}" ]; then
    while read -r c ip; do
      [ -z "${ip}" ] && continue
      echo "sentinela_nxdomain_ip_count{ip=\"${ip}\",window=\"${WINDOW}\"} ${c}"
    done <<< "$IPS"
  fi
  echo
  echo "# HELP sentinela_nxdomain_domain_count Contagem de NXDOMAIN por domínio na janela de tempo"
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

sed -i 's/\r$//' "$TMP" || true
install -m 0644 "$TMP" "$OUT"
chown prometheus:prometheus "$OUT" || true
rm -f "$TMP"
