#!/usr/bin/env bash
set -uo pipefail
export LC_ALL=C LANG=C

# Configurações
DURATION="20"       # Tempo de captura
TOPN="20"           # Top N IPs
OUTDIR="/var/lib/node_exporter/textfile_collector"
OUT="${OUTDIR}/sentinela_queries.prom"
TMP_PCAP="/tmp/queries_capture.pcap"
TMP_TXT="/tmp/queries_parsed.txt"
TMP_IPS="/tmp/queries_ips.txt"
TMP_IGNORE="/tmp/ignore_ips.txt"
TMP_PROM="${OUT}.tmp.$$"

mkdir -p "$OUTDIR"

# 0. IDENTIFICAR IPs LOCAIS (Para ignorar)
# Cria uma lista com todos os IPs do servidor (v4 e v6) para um arquivo temporário
# Adiciona também localhost e ::1 explicitamente
{
  ip -o addr show | awk '{print $4}' | cut -d/ -f1
  echo "127.0.0.1"
  echo "::1"
} | sort | uniq > "$TMP_IGNORE"

# 1. CAPTURA (Sniffer de Entrada)
# Captura pacotes UDP destinados à porta 53
timeout "$DURATION" tcpdump -tnn -i any -s 0 -w "$TMP_PCAP" udp dst port 53 2>/dev/null || true

# 2. ANÁLISE
# Converte pcap para texto
tcpdump -tnn -r "$TMP_PCAP" 2>/dev/null > "$TMP_TXT"

# Calcula Total (Bruto)
TOTAL=$(wc -l < "$TMP_TXT")

# Extrai IPs de Origem
cat "$TMP_TXT" \
  | awk -F ' > ' '{print $1}' \
  | awk '{print $NF}' \
  | sed 's/\.[0-9]*$//' \
  > "$TMP_IPS"

# Filtra removendo os IPs do próprio servidor (usando grep -v -F -f)
# -F: String fixa (não regex)
# -f: Lê padrões do arquivo (nossa lista de IPs locais)
# -v: Inverte (mostra o que NÃO está na lista)
# -x: Match exato da linha
IPS=$(grep -v -F -x -f "$TMP_IGNORE" "$TMP_IPS" \
  | sort | uniq -c | sort -nr | head -n "$TOPN")

# 3. GERA MÉTRICAS (Prometheus)
{
  echo "# HELP sentinela_queries_total Total de consultas na amostra"
  echo "# TYPE sentinela_queries_total gauge"
  echo "sentinela_queries_total{window=\"${DURATION}s\"} ${TOTAL}"

  echo "# HELP sentinela_query_ip_count Top IPs enviando consultas (Excluindo o próprio servidor)"
  echo "# TYPE sentinela_query_ip_count gauge"
  if [ -n "${IPS}" ]; then
    echo "${IPS}" | while read -r count ip; do
      [ -z "${ip}" ] && continue
      echo "sentinela_query_ip_count{ip=\"${ip}\",window=\"${DURATION}s\"} ${count}"
    done
  fi
} > "$TMP_PROM"

# 4. FINALIZAÇÃO
mv "$TMP_PROM" "$OUT"
chown prometheus:prometheus "$OUT" || true
chmod 644 "$OUT"
rm -f "$TMP_PCAP" "$TMP_TXT" "$TMP_IPS" "$TMP_IGNORE" "$TMP_PROM"
