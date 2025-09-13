#!/usr/bin/env bash
set -euo pipefail

# ==========================
# Sentinela-DNS - instalador full auto (Debian 12 / amd64)
# ==========================
# Personalizáveis via env:
UNBOUND_EXPORTER_VERSION="${UNBOUND_EXPORTER_VERSION:-0.4.5}"
PROM_URL="${PROM_URL:-http://localhost:9090}"         # datasource do Grafana
GRAFANA_INSTALL="${GRAFANA_INSTALL:-yes}"             # yes|no
PROM_INSTALL="${PROM_INSTALL:-yes}"                   # yes|no
NODE_EXPORTER_INSTALL="${NODE_EXPORTER_INSTALL:-yes}" # yes|no

DEBIAN_FRONTEND=noninteractive
export DEBIAN_FRONTEND

# ---- helpers
CLR_OK="\033[32m"; CLR_WARN="\033[33m"; CLR_ERR="\033[31m"; CLR_INFO="\033[36m"; CLR_RESET="\033[0m"
ok(){   echo -e "${CLR_OK}✔${CLR_RESET} $*"; }
warn(){ echo -e "${CLR_WARN}▲${CLR_RESET} $*"; }
err(){  echo -e "${CLR_ERR}✖${CLR_RESET} $*"; }
inf(){  echo -e "${CLR_INFO}ℹ${CLR_RESET} $*"; }

require_root(){ [[ $EUID -eq 0 ]] || { err "Execute como root (su -)."; exit 1; }; }
backup_file(){ local f="$1"; [[ -f "$f" ]] && cp -a "$f" "${f}.bak.$(date +%F-%H%M%S)" || true; }

require_root

# Descobre diretório do script e raiz do repositório
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ==========================
# Atualização & pacotes base
# ==========================
inf "Atualizando sistema e instalando utilitários…"
apt-get update -y
apt-get dist-upgrade -y || true
apt-get install -y curl wget jq tar ca-certificates gnupg lsb-release apt-transport-https dnsutils iproute2 netcat-openbsd

# ==========================
# Unbound + métricas/hardening
# ==========================
inf "Instalando/ativando Unbound…"
apt-get install -y unbound
mkdir -p /etc/unbound/unbound.conf.d
METRICS_CONF="/etc/unbound/unbound.conf.d/metrics.conf"

if [[ ! -f "$METRICS_CONF" ]]; then
  inf "Criando $METRICS_CONF (métricas + hardening)…"
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
else
  ok "Mantendo $METRICS_CONF existente."
fi

# chaves do unbound-control (idempotente)
if command -v unbound-control >/dev/null 2>&1; then
  unbound-control-setup >/dev/null 2>&1 || true
fi
systemctl enable unbound >/dev/null 2>&1 || true
systemctl restart unbound
ok "Unbound ativo."

# ==========================
# unbound_exporter (release)
# ==========================
inf "Instalando unbound_exporter v${UNBOUND_EXPORTER_VERSION}…"
tmpdir="$(mktemp -d)"; pushd "$tmpdir" >/dev/null
URL="https://github.com/kumina/unbound_exporter/releases/download/v${UNBOUND_EXPORTER_VERSION}/unbound_exporter-${UNBOUND_EXPORTER_VERSION}.linux-amd64.tar.gz"
wget -q "$URL"
tar xzf "unbound_exporter-${UNBOUND_EXPORTER_VERSION}.linux-amd64.tar.gz"
install -m 0755 "unbound_exporter-${UNBOUND_EXPORTER_VERSION}.linux-amd64/unbound_exporter" /usr/local/bin/unbound_exporter
popd >/dev/null

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
systemctl restart unbound_exporter
ok "unbound_exporter ativo em :9167."

# ==========================
# node_exporter (via pacote)
# ==========================
if [[ "$NODE_EXPORTER_INSTALL" == "yes" ]]; then
  inf "Instalando node_exporter (prometheus-node-exporter)…"
  apt-get install -y prometheus-node-exporter
  systemctl enable prometheus-node-exporter >/dev/null 2>&1 || true
  systemctl restart prometheus-node-exporter
  ok "node_exporter ativo em :9100."
fi

# ==========================
# Prometheus (APT) + scrape jobs
# ==========================
if [[ "$PROM_INSTALL" == "yes" ]]; then
  inf "Instalando/ajustando Prometheus…"
  apt-get install -y prometheus
  PROM_FILE="/etc/prometheus/prometheus.yml"
  backup_file "$PROM_FILE"

  # Garante estrutura mínima
  if ! grep -q "^scrape_configs:" "$PROM_FILE"; then
    cat > "$PROM_FILE" <<'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
EOF
  fi

  # adiciona jobs unbound & node se faltarem
  grep -q "job_name: 'unbound'" "$PROM_FILE" || cat >> "$PROM_FILE" <<'EOF'

  - job_name: 'unbound'
    static_configs:
      - targets: ['localhost:9167']
EOF

  grep -q "job_name: 'node'" "$PROM_FILE" || cat >> "$PROM_FILE" <<'EOF'

  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']
EOF

  # valida e sobe
  if command -v promtool >/dev/null 2>&1; then
    promtool check config "$PROM_FILE" || { err "prometheus.yml inválido"; exit 1; }
  fi
  systemctl enable prometheus >/dev/null 2>&1 || true
  systemctl restart prometheus
  ok "Prometheus ativo em :9090."
fi

# ==========================
# Grafana (repo oficial) + datasource + dashboard do repositório
# ==========================
if [[ "$GRAFANA_INSTALL" == "yes" ]]; then
  inf "Instalando Grafana + datasource Prometheus (${PROM_URL})…"
  if [[ ! -f /etc/apt/sources.list.d/grafana.list ]]; then
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://packages.grafana.com/gpg.key | gpg --dearmor -o /etc/apt/keyrings/grafana.gpg
    echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://packages.grafana.com/oss/deb stable main" > /etc/apt/sources.list.d/grafana.list
    apt-get update -y
  fi
  apt-get install -y grafana

  # Datasource
  mkdir -p /etc/grafana/provisioning/datasources
  cat > /etc/grafana/provisioning/datasources/prometheus.yaml <<EOF
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: ${PROM_URL}
    isDefault: true
EOF

  # Provisionamento de dashboards
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

  # Copia o dashboard do repositório, se existir
  SRC_DASH="${REPO_ROOT}/grafana/provisioning/dashboards/unbound_overview.json"
  DST_DASH="/var/lib/grafana/dashboards/unbound/unbound_overview.json"
  if [[ -f "$SRC_DASH" ]]; then
    cp -f "$SRC_DASH" "$DST_DASH"
    ok "Dashboard copiado do repositório: $SRC_DASH -> $DST_DASH"
  else
    # Fallback: cria placeholder se ainda não existir
    if [[ ! -f "$DST_DASH" ]]; then
      cat > "$DST_DASH" <<'EOF'
{
  "title": "Unbound Overview (Sentinela-DNS)",
  "timezone": "browser",
  "schemaVersion": 36,
  "version": 1,
  "panels": []
}
EOF
      warn "Dashboard do repo não encontrado; placeholder criado em $DST_DASH"
    fi
  fi

  systemctl enable grafana-server >/dev/null 2>&1 || true
  systemctl restart grafana-server
  ok "Grafana ativo em :3000."
fi

# ==========================
# Snippets Prometheus externo (extra)
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
# Health-check final
# ==========================
echo
inf "Executando checagens finais…"
if [[ -x "${SCRIPT_DIR}/health.sh" ]]; then
  "${SCRIPT_DIR}/health.sh" || true
else
  for s in unbound unbound_exporter prometheus grafana-server prometheus-node-exporter; do
    systemctl is-active --quiet "$s" && ok "Serviço ativo: $s" || warn "Serviço INATIVO (ok se não instalado): $s"
  done
fi

echo
ok "Instalação/atualização concluída."
echo "Prometheus:  ${PROM_URL}"
echo "Grafana:     http://SEU_IP:3000  (admin/admin → altere a senha)"
echo "Exporters:   node_exporter :9100 | unbound_exporter :9167"
