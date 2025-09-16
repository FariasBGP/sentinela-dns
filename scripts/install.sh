#!/usr/bin/env bash
set -euo pipefail

# ==========================
# Sentinela-DNS - instalador full auto (Debian 12 / amd64)
# ==========================
UNBOUND_EXPORTER_VERSION="${UNBOUND_EXPORTER_VERSION:-0.4.6}"
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
# Unbound - configuração MODULAR (unbound.conf.d)
# ==========================
inf "Instalando/ativando Unbound…"
apt-get install -y unbound
install -d -m 0755 /etc/unbound/unbound.conf.d

# garante include no unbound.conf principal
if ! grep -q 'include: "/etc/unbound/unbound.conf.d/\*.conf"' /etc/unbound/unbound.conf 2>/dev/null; then
  echo 'include: "/etc/unbound/unbound.conf.d/*.conf"' >> /etc/unbound/unbound.conf
fi

# limpa resquícios do modo antigo (se existirem)
rm -f /etc/unbound/unbound.conf.d/metrics.conf || true

# ---- Fragments (idempotentes)
cat >/etc/unbound/unbound.conf.d/21-root-auto-trust-anchor-file.conf <<'EOF'
server:
  auto-trust-anchor-file: "/var/lib/unbound/root.key"
EOF

cat >/etc/unbound/unbound.conf.d/31-statisticas.conf <<'EOF'
server:
  statistics-interval: 0
  extended-statistics: yes
  statistics-cumulative: yes
EOF

cat >/etc/unbound/unbound.conf.d/41-protocols.conf <<'EOF'
server:
  do-ip4: yes
  do-ip6: yes
  do-udp: yes
  do-tcp: yes
EOF

cat >/etc/unbound/unbound.conf.d/51-acls-locals.conf <<'EOF'
server:
  access-control: 127.0.0.1/32 allow
  access-control: ::1/128    allow
  access-control: 10.0.0.0/8      allow
  access-control: 100.64.0.0/10   allow
  access-control: 172.16.0.0/12   allow
EOF

cat >/etc/unbound/unbound.conf.d/52-acls-trusteds.conf <<'EOF'
server:
  # Coloque aqui faixas adicionais de clientes confiáveis
  # access-control: 192.168.0.0/22 allow
  # access-control: 2001:db8::/32   allow
EOF

cat >/etc/unbound/unbound.conf.d/59-acls-default-policy.conf <<'EOF'
server:
  access-control: 0.0.0.0/0 deny
  access-control: ::/0      deny
EOF

THREADS="$(nproc)"
cat >/etc/unbound/unbound.conf.d/61-configs.conf <<EOF
server:
  outgoing-range: 8192
  outgoing-port-avoid: 0-1024
  outgoing-port-permit: 1025-65535

  num-threads: ${THREADS}
  num-queries-per-thread: 2048

  msg-cache-size: 64m
  msg-cache-slabs: ${THREADS}
  rrset-cache-size: 128m
  rrset-cache-slabs: ${THREADS}

  infra-host-ttl: 60
  infra-lame-ttl: 120
  infra-cache-numhosts: 10000
  infra-cache-lame-size: 10k
  infra-cache-slabs: ${THREADS}
  key-cache-slabs: ${THREADS}
  rrset-roundrobin: yes

  hide-identity: yes
  hide-version: yes
  harden-glue: yes
  harden-algo-downgrade: yes
  harden-below-nxdomain: yes
  harden-dnssec-stripped: yes
  harden-large-queries: yes
  harden-referral-path: no
  harden-short-bufsize: yes

  do-not-query-address: 127.0.0.1/8
  do-not-query-localhost: yes
  edns-buffer-size: 1472
  aggressive-nsec: yes
  delay-close: 10000
  neg-cache-size: 8M
  qname-minimisation: yes
  deny-any: yes
  ratelimit: 2000
  unwanted-reply-threshold: 10000
  use-caps-for-id: yes
  val-clean-additional: yes
  minimal-responses: yes
  prefetch: yes
  prefetch-key: yes
  serve-expired: yes
  so-reuseport: yes
EOF

cat >/etc/unbound/unbound.conf.d/62-listen-loopback.conf <<'EOF'
server:
  interface: 127.0.0.1
  interface: ::1
EOF

cat >/etc/unbound/unbound.conf.d/63-listen-interfaces.conf <<'EOF'
server:
  interface: 0.0.0.0
  interface: ::
  port: 53
  do-udp: yes
  do-tcp: yes
EOF

cat >/etc/unbound/unbound.conf.d/89-hyperlocal-cache.conf <<'EOF'
server:
  auth-zone:
    name: "."
    master: 198.41.0.4
    master: 2001:503:ba3e::2:30
    master: 192.33.4.12
    master: 2001:500:2::c
    master: 199.7.91.13
    master: 2001:500:2d::d
    master: 192.203.230.10
    master: 2001:500:a8::e
    master: 192.5.5.241
    master: 2001:500:2f::f
    master: 192.112.36.4
    master: 2001:500:12::d0d
    master: 192.36.148.17
    master: 2001:7fe::53
    master: 192.58.128.30
    master: 2001:503:c27::2:30
    master: 193.0.14.129
    master: 2001:7fd::1
    master: 199.7.83.42
    master: 2001:500:9f::42
    master: 202.12.27.33
    master: 2001:dc3::35
    fallback-enabled: yes
    for-downstream: no
    for-upstream: yes
    zonefile: ""
EOF

# Remote-control COM TLS (necessário p/ exporter com cert/key)
cat >/etc/unbound/unbound.conf.d/99-remote-control.conf <<'EOF'
remote-control:
  control-enable: yes
  control-interface: 127.0.0.1
  control-port: 8953
  control-use-cert: yes
EOF

# root.key (DNSSEC trust anchor)
if [[ ! -f /var/lib/unbound/root.key ]]; then
  unbound-anchor -a /var/lib/unbound/root.key || true
fi

unbound-checkconf
systemctl enable unbound >/dev/null 2>&1 || true
systemctl restart unbound
ok "Unbound ativo (configuração modular)."

# ==========================
# unbound_exporter (download se existir; fallback: compilar do source)
# ==========================
inf "Instalando/ajustando unbound_exporter…"
VER="${UNBOUND_EXPORTER_VERSION:-0.4.6}"
tmpdir="$(mktemp -d)"; pushd "$tmpdir" >/dev/null
ok_dl=0
for URL in \
  "https://github.com/letsencrypt/unbound_exporter/releases/download/v${VER}/unbound_exporter-${VER}.linux-amd64.tar.gz" \
  "https://github.com/kumina/unbound_exporter/releases/download/v${VER}/unbound_exporter-${VER}.linux-amd64.tar.gz"
do
  if curl -fsSL --connect-timeout 10 -o ue.tar.gz "$URL" && tar -tzf ue.tar.gz >/dev/null 2>&1; then
    tar -xzf ue.tar.gz
    BIN="$(find . -type f -name unbound_exporter -perm -u+x | head -n1 || true)"
    if [[ -n "$BIN" ]]; then install -m0755 "$BIN" /usr/local/bin/unbound_exporter; ok_dl=1; break; fi
  fi
done
if [[ "$ok_dl" -ne 1 ]]; then
  inf "Tarball indisponível; compilando do source (Go)…"
  apt-get install -y golang
  GO111MODULE=on GOBIN=/usr/local/bin go install "github.com/letsencrypt/unbound_exporter@v${VER}"
fi
popd >/dev/null

# Certs do unbound-control (idempotente) + permissões
unbound-control-setup >/dev/null 2>&1 || true
chown unbound:unbound /etc/unbound/unbound_*pem /etc/unbound/unbound_*key 2>/dev/null || true
chmod 640 /etc/unbound/unbound_*pem /etc/unbound/unbound_*key 2>/dev/null || true
systemctl restart unbound

# Service systemd (usa tcp:// e cert/key) — roda como usuário 'unbound'
cat > /etc/systemd/system/unbound_exporter.service <<'EOF'
[Unit]
Description=Prometheus Unbound Exporter
After=network-online.target unbound.service
Requires=unbound.service

[Service]
User=unbound
Group=unbound
ExecStart=/usr/local/bin/unbound_exporter \
  --unbound.host=tcp://127.0.0.1:8953 \
  --unbound.cert=/etc/unbound/unbound_control.pem \
  --unbound.key=/etc/unbound/unbound_control.key \
  --web.listen-address=:9167 \
  --web.telemetry-path=/metrics
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now unbound_exporter >/dev/null 2>&1 || true
systemctl restart unbound_exporter
ok "unbound_exporter ativo em :9167."

# ==========================
# node_exporter
# ==========================
if [[ "$NODE_EXPORTER_INSTALL" == "yes" ]]; then
  apt-get install -y prometheus-node-exporter
  systemctl enable prometheus-node-exporter >/dev/null 2>&1 || true
  systemctl restart prometheus-node-exporter
  ok "node_exporter ativo em :9100."
fi

# ==========================
# Prometheus
# ==========================
if [[ "$PROM_INSTALL" == "yes" ]]; then
  apt-get install -y prometheus
  PROM_FILE="/etc/prometheus/prometheus.yml"
  backup_file "$PROM_FILE"

  if ! grep -q "^scrape_configs:" "$PROM_FILE" 2>/dev/null; then
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

  systemctl enable prometheus >/dev/null 2>&1 || true
  systemctl restart prometheus
  ok "Prometheus ativo em :9090."
fi

# ==========================
# Grafana
# ==========================
if [[ "$GRAFANA_INSTALL" == "yes" ]]; then
  if [[ ! -f /etc/apt/sources.list.d/grafana.list ]]; then
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://packages.grafana.com/gpg.key | gpg --dearmor -o /etc/apt/keyrings/grafana.gpg
    echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://packages.grafana.com/oss/deb stable main" > /etc/apt/sources.list.d/grafana.list
    apt-get update -y
  fi
  apt-get install -y grafana

  install -d /etc/grafana/provisioning/datasources
  if [[ -f "${REPO_ROOT}/grafana/provisioning/datasources/prometheus.yaml" ]]; then
    cp -f "${REPO_ROOT}/grafana/provisioning/datasources/prometheus.yaml" /etc/grafana/provisioning/datasources/prometheus.yaml
    sed -i "s#^\\s*url:.*#    url: ${PROM_URL}#g" /etc/grafana/provisioning/datasources/prometheus.yaml || true
  else
    cat > /etc/grafana/provisioning/datasources/prometheus.yaml <<EOF
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    uid: prometheus
    access: proxy
    url: ${PROM_URL}
    isDefault: true
EOF
  fi

  # garante UID fixo
  if ! grep -q '^\s*uid:\s*prometheus' /etc/grafana/provisioning/datasources/prometheus.yaml; then
    awk '
      {print}
      $0 ~ /type:[[:space:]]*prometheus/ && !i {print "    uid: prometheus"; i=1}
    ' /etc/grafana/provisioning/datasources/prometheus.yaml > /tmp/prom.yaml && mv /tmp/prom.yaml /etc/grafana/provisioning/datasources/prometheus.yaml
  fi

  install -d /etc/grafana/provisioning/dashboards /var/lib/grafana/dashboards/unbound
  cat > /etc/grafana/provisioning/dashboards/sentinela-unbound.yaml <<'EOF'
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

  if [[ -f "${REPO_ROOT}/grafana/provisioning/dashboards/sentinela-unbound-main.json" ]]; then
    cp -f "${REPO_ROOT}/grafana/provisioning/dashboards/sentinela-unbound-main.json" \
          /var/lib/grafana/dashboards/unbound/sentinela-unbound-main.json
  else
    cat > /var/lib/grafana/dashboards/unbound/sentinela-unbound-main.json <<'EOF'
{ "title": "Sentinela-DNS · Unbound (Main)", "schemaVersion": 36, "version": 1, "panels": [] }
EOF
  fi

  systemctl enable grafana-server >/dev/null 2>&1 || true
  systemctl restart grafana-server
  ok "Grafana ativo em :3000."
fi

# ==========================
# Snippets Prometheus externo
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
for s in unbound unbound_exporter prometheus grafana-server prometheus-node-exporter; do
  systemctl is-active --quiet "$s" && ok "Serviço ativo: $s" || warn "Serviço INATIVO (ok se não instalado): $s"
done

ok "Instalação/atualização concluída."
echo "Prometheus:  ${PROM_URL}"
echo "Grafana:     http://SEU_IP:3000 (admin/admin → altere a senha)"
echo "Exporters:   node_exporter :9100 | unbound_exporter :9167"
