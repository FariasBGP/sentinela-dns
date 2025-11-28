#!/usr/bin/env bash
set -uo pipefail
export LC_ALL=C LANG=C

# Configurações
DURATION="30"
TOPN="20"
OUTDIR="/var/lib/node_exporter/textfile_collector"
OUT="${OUTDIR}/sentinela_nxdomain.prom"
TMP_PCAP="/tmp/nxdomain_capture.pcap"
TMP_TXT="/tmp/nxdomain_parsed.txt"
TMP_PROM="${OUT}.tmp.$$"

mkdir -p "$OUTDIR"

# 1. CAPTURA
# Captura pacotes UDP na porta 53
timeout "$DURATION" tcpdump -tnn -vv -i any -s 0 -w "$TMP_PCAP" udp src port 53 2>/dev/null || true

# 2. ANÁLISE
# Converte para texto
tcpdump -nn -vv -r "$TMP_PCAP" 2>/dev/null > "$TMP_TXT"

# Filtra apenas linhas com NXDomain
grep "NXDomain" "$TMP_TXT" > "${TMP_TXT}.clean"

# Calcula Total
TOTAL=$(wc -l < "${TMP_TXT}.clean")

# --- EXTRAÇÃO DE IPs (Mantida) ---
# Pega o IP de destino (o cliente)
IPS=$(cat "${TMP_TXT}.clean" \
  | sed -n 's/.* > \([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)\.[0-9]*:.*/\1/p' \
  | sort | uniq -c | sort -nr | head -n "$TOPN")

# --- EXTRAÇÃO DE DOMÍNIOS (CORRIGIDA) ---
# Procura por " q: " seguido de qualquer coisa até um espaço e "?" (ex: A?), e pega o que vem a seguir
DOMS=$(cat "${TMP_TXT}.clean" \
  | sed -nE 's/.* q: [A-Za-z]+\? ([a-zA-Z0-9._-]+).*/\1/p' \
  | sed 's/\.$//' \
  | sort | uniq -c | sort -nr | head -n "$TOPN")

# 3. GERA MÉTRICAS
{
  echo "# HELP sentinela_nxdomain_total Total NXDOMAIN na amostra"
  echo "# TYPE sentinela_nxdomain_total gauge"
  echo "sentinela_nxdomain_total{window=\"12h\"} ${TOTAL}"

  echo "# HELP sentinela_nxdomain_ip_count Top IPs recebendo NXDOMAIN"
  echo "# TYPE sentinela_nxdomain_ip_count gauge"
  if [ -n "${IPS}" ]; then
    echo "${IPS}" | while read -r count ip; do
      [ -z "${ip}" ] && continue
      echo "sentinela_nxdomain_ip_count{ip=\"${ip}\",window=\"12h\"} ${count}"
    done
  fi

  echo "# HELP sentinela_nxdomain_domain_count Top Domínios gerando NXDOMAIN"
  echo "# TYPE sentinela_nxdomain_domain_count gauge"
  if [ -n "${DOMS}" ]; then
    echo "${DOMS}" | while read -r count dom; do
      [ -z "${dom}" ] && continue
      # Escapa aspas para o formato Prometheus
      dom_esc="${dom//\"/\\\"}"
      echo "sentinela_nxdomain_domain_count{domain=\"${dom_esc}\",window=\"12h\"} ${count}"
    done
  fi
} > "$TMP_PROM"

# 4. FINALIZAÇÃO
mv "$TMP_PROM" "$OUT"
chown prometheus:prometheus "$OUT" || true
chmod 644 "$OUT"
rm -f "$TMP_PCAP" "$TMP_TXT" "${TMP_TXT}.clean" "$TMP_PROM"
