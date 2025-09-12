#!/usr/bin/env bash
set -euo pipefail

# ==========================
# Sentinela-DNS - instalador full auto (Debian 12 / amd64)
# ==========================

UNBOUND_EXPORTER_VERSION="${UNBOUND_EXPORTER_VERSION:-0.4.5}"
PROM_URL_DEFAULT="http://localhost:9090"

# ---- helpers de log
CLR_RESET="\033[0m"; CLR_OK="\033[32m"; CLR_WARN="\033[33m"; CLR_ERR="\033[31m"; CLR_INFO="\033[36m"
ok(){   echo -e "${CLR_OK}✔$CLR_RESET $*"; }
warn(){ echo -e "${CLR_WARN}▲$CLR_RESET $*"; }
err(){  echo -e "${CLR_ERR}✖$CLR_RESET $*"; }
inf(){  echo -e "${CLR_INFO}ℹ$CLR_RESET $*"; }

fail_count=0
add_fail(){ err "$*"; fail_count=$((fail_count+1)); }

require_root(){
  if [[ $EUID -ne 0 ]]; then
    err "Execute como root (su -)."; exit 1
  fi
}

# ==========================
# Checagens iniciais
# ==========================
require_root
ARCH="$(uname -m)"
if [[ "$ARCH" != "x86_64" ]]; then
  warn "Arquitetura '$ARCH' — script foi feito para amd64/x86_64. Continuando mesmo assim."
fi

# ==========================
# Atualização & pacotes base
# ==========================
inf "Atualizando sistema e instalando utilitários…"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get dist-upgrade -y || true
apt-get install -y \
  curl wget jq tar ca-certificates gnupg lsb-release apt-transport-https \
  dnsutils iproute2 netcat-openbsd \
  unbound prometheus-node-exporter || add_fail "Falha ao instalar pacotes base."

# ==========================
# Unbound - métricas & hardening
# ==========================
inf "Configurando Unbound (métricas e hardening)…"
mkdir -p /etc/unbound/unbound.conf.d
METRICS_CONF="/etc/unbound/unbound.conf.d/metrics.conf"
cat > "$METRICS_CONF" <<'EOF'
server:
  extended-statistics: yes
  statistics-interval: 0
  statistics-cumulative: yes
  prefetch: yes
  prefetch-key: yes
  qname-minimisation: yes
  harden-dnssec-stripped: yes
  do-ip4: yes
  do-ip6: no
  do-udp: yes
  do-tcp: yes
  serve-expired: yes
  serve-expired-ttl: 86400
  cache-min-ttl: 60
  cache-max-ttl: 86400

remote-control:
  control-enable: yes
  control-interface: 127.0.0.1
EOF

# Gera chaves do unbound-control se necessário
if command -v unbound-control >/dev/null 2>&1; then
  unbound-control-setup >/dev/null 2>&1 || true
fi
systemctl enable unbound >/dev/null 2>&1 || true
systemctl restart unbound || add_fail "Unbound não iniciou corretamente."

# ==========================
# Unbound Exporter (release)
# ==========================
inf "Instalando unbound_exporter v${UNBOUND_EXPORTER_VERSION}…"
tmpdir="$(mktemp -d)"; cd "$tmpdir"
URL="https://github.com/kumina/unbound_exporter/releases/download/v${UNBOUND_EXPORTER_VERSION}/unbound_exporter-${UNBOUND_EXPORTER_VERSION}.linux-amd64.tar.gz"
wget -q "$URL"
tar xzf "unbound_exporter-${UNBOUND_EXPORTER_VERSION}.linux-amd64.tar.gz"
install -m 0755 "unbound_exporter-${UNBOUND_EXPORTER_VERSION}.linux-amd64/unbound_exporter" /usr/local/bin/unbound_exporter

cat > /etc/systemd/system/unbound_exporter.service <<'EOF'
[Unit]
Description=Prometheus Unbound Exporter
After=network-online.target unbound.service
Requires=unbound.service

[Service]
User=nobody
Group=nogroup
ExecStart=/usr/local/bin/unbound_exporter --unbound.host=127.0.0.1:8953 --web.listen-address=:9167
Restart=on-failure
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable unbound_exporter >/dev/null 2>&1 || true
systemctl restart unbound_exporter || add_fail "unbound_exporter não iniciou."

# ==========================
# Prometheus (APT) + scrape jobs
# ==========================
inf "Instalando e configurando Prometheus…"
apt-get install -y prometheus || add_fail "Falha ao instalar Prometheus."
PROM_FILE="/etc/prometheus/prometheus.yml"

# Adiciona jobs se não existirem
if ! grep -q "job_name: 'unbound'" "$PROM_FILE"; then
  cat >> "$PROM_FILE" <<'EOF'

  - job_name: 'unbound'
    static_configs:
      - targets: ['localhost:9167']

  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']
EOF
fi

systemctl enable prometheus >/dev/null 2>&1 || true
systemctl restart prometheus || add_fail "Prometheus não iniciou."

# ==========================
# Grafana (repo oficial) + datasource
# ==========================
inf "Instalando Grafana e provisionando datasource…"
if [[ ! -f /etc/apt/sources.list.d/grafana.list ]]; then
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://packages.grafana.com/gpg.key | gpg --dearmor -o /etc/apt/keyrings/grafana.gpg
  echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://packages.grafana.com/oss/deb stable main" > /etc/apt/sources.list.d/grafana.list
  apt-get update -y
fi
apt-get install -y grafana || add_fail "Falha ao instalar Grafana."

mkdir -p /etc/grafana/provisioning/datasources
cat > /etc/grafana/provisioning/datasources/prometheus.yaml <<EOF
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: ${PROM_URL_DEFAULT}
    isDefault: true
EOF

mkdir -p /var/lib/grafana/dashboards/unbound /etc/grafana/provisioning/dashboards
cat > /etc/grafana/provisioning/dashboards/dashboards.yaml <<'EOF'
apiVersion: 1
providers:
  - name: 'Sentinela-DNS'
    folder: 'DNS/Unbound'
    type: file
    disableDeletion: false
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards/unbound
EOF

# placeholder de dashboard (você pode trocar depois)
cat > /var/lib/grafana/dashboards/unbound/unbound_overview.json <<'EOF'
{
  "title": "Unbound Overview (Sentinela-DNS)",
  "timezone": "browser",
  "schemaVersion": 36,
  "version": 1,
  "panels": []
}
EOF

systemctl enable grafana-server >/dev/null 2>&1 || true
systemctl restart grafana-server || add_fail "Grafana não iniciou."

# ==========================
# Snippets de scrape para uso externo (extra)
# ==========================
cat > /root/SCRAPE_SNIPPETS.yml <<'EOF'
- job_name: 'unbound'
  static_configs:
    - targets: ['SEU_HOST:9167']

- job_name: 'node'
  static_configs:
    - targets: ['SEU_HOST:9100']
EOF

# ==========================
# Health-checks finais
# ==========================
inf "Rodando checagens finais…"

svc_check(){
  local s="$1"
  if systemctl is-active --quiet "$s"; then ok "Serviço ativo: $s"; else add_fail "Serviço INATIVO: $s"; fi
}

svc_check unbound
svc_check prometheus
svc_check grafana-server
svc_check prometheus-node-exporter || svc_check node-exporter || true
svc_check unbound_exporter

probe_http(){
  local url="$1" name="$2"
  if curl -fsS --max-time 5 "$url" >/dev/null; then ok "Endpoint OK: $name ($url)"; else add_fail "Falha endpoint: $name ($url)"; fi
}
probe_http "http://localhost:9100/metrics" "node_exporter"
probe_http "http://localhost:9167/metrics" "unbound_exporter"
probe_http "http://localhost:9090/-/ready"  "Prometheus"
probe_http "http://localhost:3000/api/health" "Grafana"

# ==========================
# Resumo & saídas úteis
# ==========================
echo
echo "================== RESUMO =================="
if (( fail_count == 0 )); then
  ok "Instalação concluída com sucesso."
else
  err "Instalação concluída com ${fail_count} alerta(s)/falha(s). Revise as mensagens acima."
fi

echo
echo "Acessos locais:"
echo "  Prometheus:  http://SEU_IP:9090"
echo "  Grafana:     http://SEU_IP:3000   (usuário padrão: admin / senha inicial: admin)"
echo "Exporters:"
echo "  node_exporter:     http://SEU_IP:9100/metrics"
echo "  unbound_exporter:  http://SEU_IP:9167/metrics"
echo
echo "Snippets Prometheus externo: /root/SCRAPE_SNIPPETS.yml"
