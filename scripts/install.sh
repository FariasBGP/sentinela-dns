#!/usr/bin/env bash
set -euo pipefail

WITH_GRAFANA="${WITH_GRAFANA:-no}"          # yes|no
WITH_PROM_LOCAL="${WITH_PROM_LOCAL:-no}"    # yes|no
PROM_URL="${PROM_URL:-http://localhost:9090}"
UNBOUND_EXPORTER_VERSION="${UNBOUND_EXPORTER_VERSION:-0.4.5}"

if [[ $EUID -ne 0 ]]; then
  echo "Execute como root."; exit 1
fi

# Dependências principais
apt-get update -y
apt-get install -y unbound prometheus-node-exporter curl wget jq tar ca-certificates gnupg lsb-release

# Config básica do Unbound
mkdir -p /etc/unbound/unbound.conf.d
cat > /etc/unbound/unbound.conf.d/metrics.conf <<'EOF'
server:
  extended-statistics: yes
  prefetch: yes
  qname-minimisation: yes
  harden-dnssec-stripped: yes
  serve-expired: yes

remote-control:
  control-enable: yes
  control-interface: 127.0.0.1
EOF

systemctl enable unbound
systemctl restart unbound

# Instalar unbound_exporter
cd /tmp
wget -q https://github.com/kumina/unbound_exporter/releases/download/v${UNBOUND_EXPORTER_VERSION}/unbound_exporter-${UNBOUND_EXPORTER_VERSION}.linux-amd64.tar.gz
tar xzf unbound_exporter-${UNBOUND_EXPORTER_VERSION}.linux-amd64.tar.gz
install -m 0755 unbound_exporter-${UNBOUND_EXPORTER_VERSION}.linux-amd64/unbound_exporter /usr/local/bin/unbound_exporter

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

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable unbound_exporter
systemctl restart unbound_exporter

# Instalar Grafana opcional
if [[ "$WITH_GRAFANA" == "yes" ]]; then
  if [[ ! -f /etc/apt/sources.list.d/grafana.list ]]; then
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://packages.grafana.com/gpg.key | gpg --dearmor -o /etc/apt/keyrings/grafana.gpg
    echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://packages.grafana.com/oss/deb stable main" > /etc/apt/sources.list.d/grafana.list
    apt-get update -y
  fi
  apt-get install -y grafana

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

  systemctl enable grafana-server
  systemctl restart grafana-server
fi

echo "Instalação concluída. 🎉"
