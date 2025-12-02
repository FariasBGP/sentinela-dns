#!/usr/bin/env bash
# Sentinela-DNS — install.sh
# Instala/atualiza Unbound + Exporters + Prometheus + Grafana + Agente (Debian 12/13).
# Nível de Segurança: Hardened (Systemd Sandbox + Auto-patch)

set -euo pipefail

# ===== UI =====
CLR_OK="\033[32m"; CLR_WARN="\033[33m"; CLR_ERR="\033[31m"; CLR_INFO="\033[36m"; CLR_RESET="\033[0m"
ok(){   echo -e "${CLR_OK}✔${CLR_RESET} $*"; }
warn(){ echo -e "${CLR_WARN}▲${CLR_RESET} $*"; }
err(){  echo -e "${CLR_ERR}✖${CLR_RESET} $*"; }
inf(){  echo -e "${CLR_INFO}ℹ${CLR_RESET} $*"; }
require_root(){ [[ $EUID -eq 0 ]] || { err "Execute como root (su -)."; exit 1; }; }

require_root
DEBIAN_FRONTEND=noninteractive; export DEBIAN_FRONTEND

UNBOUND_EXPORTER_VERSION="${UNBOUND_EXPORTER_VERSION:-0.4.6}"
PROM_URL="${PROM_URL:-http://localhost:9090}"
GRAFANA_INSTALL="${GRAFANA_INSTALL:-yes}"        # yes|no
PROM_INSTALL="${PROM_INSTALL:-yes}"              # yes|no
NODE_EXPORTER_INSTALL="${NODE_EXPORTER_INSTALL:-yes}" # yes|no

# URL DA SUA API (Ajuste aqui se mudar de domínio no futuro)
API_URL_DEFAULT="https://api-sentinela.bgpconsultoria.com.br/api/v1/config"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ===== SO =====
. /etc/os-release || true
case "${VERSION_ID%%.*}" in
  12|13) ok "Debian ${VERSION_ID} detectado."; ;;
  *)     warn "SO não testado oficialmente (${PRETTY_NAME:-?}). Prosseguindo…";;
esac

# Define pacote libssl
LIBSSL_PKG="libssl3"
if [[ "${VERSION_ID%%.*}" == "13" ]]; then
  LIBSSL_PKG="libssl3t64"
fi

# ===== Pacotes base =====
inf "Atualizando sistema e instalando utilitários…"
apt-get update -y
apt-get dist-upgrade -y || true
apt-get install -y curl wget jq tar ca-certificates gnupg lsb-release apt-transport-https \
                   dnsutils iproute2 netcat-openbsd apparmor-utils "${LIBSSL_PKG}" unbound unbound-anchor \
                   python3-requests psmisc

# Desabilita AppArmor
inf "Desabilitando AppArmor para unbound..."
aa-disable /etc/apparmor.d/usr.sbin.unbound || true

# ===== Unbound (config modular) =====
inf "Configurando Unbound (modular)…"
install -d -m 0755 /etc/unbound/unbound.conf.d
rm -f /etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf

cat >/etc/unbound/unbound.conf <<'EOF'
server:
  verbosity: 1
include: "/etc/unbound/unbound.conf.d/*.conf"
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
  access-control: ::1/128 allow
  access-control: 10.0.0.0/8 allow
  access-control: 100.64.0.0/10 allow
  access-control: 172.16.0.0/12 allow
EOF

cat >/etc/unbound/unbound.conf.d/52-acls-trusteds.conf <<'EOF'
server:
  # Coloque aqui faixas adicionais de clientes confiáveis
  # access-control: 192.168.0.0/22 allow
EOF

cat >/etc/unbound/unbound.conf.d/59-acls-default-policy.conf <<'EOF'
server:
  access-control: 0.0.0.0/0 deny
  access-control: ::/0 deny
EOF

cat >/etc/unbound/unbound.conf.d/61-configs.conf <<'EOF'
server:
  outgoing-range: 8192
  outgoing-port-avoid: 0-1024
  outgoing-port-permit: 1025-65535
  num-threads: 32
  num-queries-per-thread: 2048
  msg-cache-size: 64m
  msg-cache-slabs: 32
  rrset-cache-size: 128m
  rrset-cache-slabs: 32
  infra-host-ttl: 60
  infra-lame-ttl: 120
  infra-cache-numhosts: 10000
  infra-cache-lame-size: 10k
  infra-cache-slabs: 32
  key-cache-slabs: 32
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

cat >/etc/unbound/unbound.conf.d/63-listen-interfaces.conf <<'EOF'
server:
  interface: 0.0.0.0
  interface: ::0
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

cat >/etc/unbound/unbound.conf.d/99-remote-control.conf <<'EOF'
server:
  chroot: ""
  directory: "/etc/unbound"
  pidfile: "/var/run/unbound.pid"
  username: "unbound"

remote-control:
  control-enable: yes
  control-interface: 127.0.0.1
  control-port: 8953
  control-use-cert: yes
  server-key-file: "/etc/unbound/unbound_server.key"
  server-cert-file: "/etc/unbound/unbound_server.pem"
  control-key-file: "/etc/unbound/unbound_control.key"
  control-cert-file: "/etc/unbound/unbound_control.pem"
EOF

# Corrige permissões
chown -R unbound:unbound /etc/unbound /var/lib/unbound
chmod -R 755 /etc/unbound
chmod 644 /var/lib/unbound/root.key 2>/dev/null || true

# ===== CHAVES SSL (Antes da validação) =====
if [[ ! -f /etc/unbound/unbound_server.key || ! -f /etc/unbound/unbound_control.key ]]; then
  inf "Gerando certificados para unbound-control..."
  unbound-control-setup -d /etc/unbound/ || {
    err "Falha no unbound-control-setup. Verifique logs."
    exit 1
  }
  chown unbound:unbound /etc/unbound/unbound_{server,control}.{key,pem}
  chmod 600 /etc/unbound/unbound_{server,control}.key
  chmod 644 /etc/unbound/unbound_{server,control}.pem
fi

# Valida config
if ! unbound-checkconf >/dev/null 2>&1; then
  err "Configuração do Unbound inválida!"
  unbound-checkconf
  exit 1
fi
ok "Configuração do Unbound validada."

# Override systemd
install -d -m 0755 /etc/systemd/system/unbound.service.d
cat >/etc/systemd/system/unbound.service.d/override.conf <<'EOF'
[Service]
ExecStartPre=
Environment="DAEMON_OPTS="
ExecStart=
ExecStart=/usr/sbin/unbound -d $DAEMON_OPTS
EOF

systemctl daemon-reload
systemctl enable unbound
systemctl restart unbound
ok "Unbound ativo."

# ===== unbound_exporter =====
inf "Instalando unbound_exporter..."
tmpdir="$(mktemp -d)"; pushd "$tmpdir" >/dev/null
ok_dl=0
for URL in \
  "https://github.com/letsencrypt/unbound_exporter/releases/download/v${UNBOUND_EXPORTER_VERSION}/unbound_exporter-${UNBOUND_EXPORTER_VERSION}.linux-amd64.tar.gz" \
  "https://github.com/kumina/unbound_exporter/releases/download/v${UNBOUND_EXPORTER_VERSION}/unbound_exporter-${UNBOUND_EXPORTER_VERSION}.linux-amd64.tar.gz"
do
  if curl -fsSL --connect-timeout 10 -o ue.tar.gz "$URL" && tar -tzf ue.tar.gz >/dev/null 2>&1; then
    tar -xzf ue.tar.gz
    BIN="$(find . -type f -name unbound_exporter -perm -u+x | head -n1 || true)"
    if [[ -n "$BIN" ]]; then install -m0755 "$BIN" /usr/local/bin/unbound_exporter; ok_dl=1; break; fi
  fi
done
if [[ "$ok_dl" -ne 1 ]]; then
  inf "Compilando do source (Go)..."
  apt-get install -y golang
  GO111MODULE=on GOBIN=/usr/local/bin go install "github.com/letsencrypt/unbound_exporter@v${UNBOUND_EXPORTER_VERSION}"
fi
popd >/dev/null

cat > /etc/systemd/system/unbound_exporter.service <<'EOF'
[Unit]
Description=Prometheus Unbound Exporter
After=network-online.target unbound.service
Requires=unbound.service
[Service]
User=unbound
Group=unbound
ExecStart=/usr/local/bin/unbound_exporter --unbound.host=tcp://127.0.0.1:8953 --unbound.cert=/etc/unbound/unbound_control.pem --unbound.key=/etc/unbound/unbound_control.key --web.listen-address=:9167 --web.telemetry-path=/metrics
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now unbound_exporter
ok "unbound_exporter ativo."

# ===== node_exporter =====
if [[ "$NODE_EXPORTER_INSTALL" == "yes" ]]; then
  inf "Instalando prometheus-node-exporter..."
  apt-get install -y prometheus-node-exporter
  install -d -m 0755 /etc/systemd/system/prometheus-node-exporter.service.d
  cat > /etc/systemd/system/prometheus-node-exporter.service.d/override.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/prometheus-node-exporter --collector.textfile.directory=/var/lib/node_exporter/textfile_collector
EOF
  systemctl daemon-reload
  systemctl enable --now prometheus-node-exporter
  ok "node_exporter ativo."
fi

# ===== Prometheus =====
if [[ "$PROM_INSTALL" == "yes" ]]; then
  apt-get install -y prometheus
  install -d -m 0755 "/etc/prometheus"
  cat > "/etc/prometheus/prometheus.yml" <<'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s
scrape_configs:
  - job_name: 'prometheus'
    static_configs: [{targets: ['localhost:9090']}]
  - job_name: 'unbound'
    static_configs: [{targets: ['localhost:9167']}]
  - job_name: 'node'
    static_configs: [{targets: ['localhost:9100']}]
EOF
  systemctl enable --now prometheus
  ok "Prometheus ativo."
fi

# ===== Grafana =====
if [[ "$GRAFANA_INSTALL" == "yes" ]]; then
  if [[ ! -f /etc/apt/sources.list.d/grafana.list ]]; then
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://packages.grafana.com/gpg.key | gpg --dearmor -o /etc/apt/keyrings/grafana.gpg
    echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://packages.grafana.com/oss/deb stable main" > /etc/apt/sources.list.d/grafana.list
    apt-get update -y
  fi
  apt-get install -y grafana
  if ss -tuln | grep -q ':3000 '; then fuser -k 3000/tcp || true; fi

  install -d /etc/grafana/provisioning/datasources
  cat > /etc/grafana/provisioning/datasources/prometheus.yaml <<EOF
apiVersion: 1
datasources:
- name: Prometheus
  type: prometheus
  url: ${PROM_URL}
  access: proxy
  isDefault: true
EOF

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

  cp -f "${REPO_ROOT}/grafana/provisioning/dashboards/"*.json /var/lib/grafana/dashboards/unbound/ 2>/dev/null || true
  
  BRANDING_DIR="${REPO_ROOT}/branding"
  GRAFANA_IMG_DIR="/usr/share/grafana/public/img"
  if [[ -f "${BRANDING_DIR}/logo.jpg" ]]; then
    cp "${BRANDING_DIR}/logo.jpg" "${GRAFANA_IMG_DIR}/grafana_logo.svg"
    cp "${BRANDING_DIR}/logo.jpg" "${GRAFANA_IMG_DIR}/grafana_icon.svg"
  fi

  chown -R grafana:grafana /etc/grafana /var/lib/grafana /var/log/grafana
  chmod -R 755 /etc/grafana /var/lib/grafana /var/log/grafana
  systemctl enable --now grafana-server
  ok "Grafana ativo."
fi

# ===== Agente Sentinela (INTERATIVO) =====
inf "Instalando componentes do Sentinela..."

# 1. Script NXDOMAIN (Mantém lógica original)
if [[ -f "${REPO_ROOT}/scripts/top-nxdomain-optimized.sh" ]]; then
  install -m 0755 "${REPO_ROOT}/scripts/top-nxdomain-optimized.sh" /usr/local/bin/top-nxdomain.sh
fi

# 2. Script Agente (Modified with Patch)
if [[ -f "${REPO_ROOT}/scripts/sentinela-agent.py" ]]; then
    target_bin="/usr/local/bin/sentinela-agent.py"
    install -m 0700 "${REPO_ROOT}/scripts/sentinela-agent.py" "$target_bin"
    
    # AUTO-CORREÇÃO: Remove o import alucinado pela IA (deque)
    sed -i '/from collections import deque/d' "$target_bin"
    ok "Script sentinela-agent.py instalado e saneado em $target_bin"
else
    warn "Script sentinela-agent.py não encontrado."
fi

# 3. Configuração do Agente (Modified with Patch)
install -d -m 0700 /etc/sentinela
install -d -m 0700 /var/lib/sentinela # Garante diretório de estado para o Sandbox

if [[ ! -f "/etc/sentinela/agent.conf" ]]; then
    echo ""
    echo "=================================================================="
    echo "  CONFIGURAÇÃO INICIAL DO AGENTE SENTINELA"
    echo "=================================================================="
    echo "  Cole a API KEY gerada no Painel Admin para este servidor."
    echo "  (Se você está apenas atualizando, pode cancelar com Ctrl+C)"
    echo "=================================================================="
    read -p "API Key: " USER_API_KEY
    echo ""

    if [[ -n "$USER_API_KEY" ]]; then
        cat > /etc/sentinela/agent.conf <<EOF
[api]
url = ${API_URL_DEFAULT}
key = ${USER_API_KEY}

[settings]
bind_ip = 0.0.0.0
redirect_ip_v4 = 127.0.0.1
redirect_ip_v6 = ::1
EOF
        chmod 600 /etc/sentinela/agent.conf
        ok "Arquivo de configuração agent.conf criado."
    else
        warn "Nenhuma chave inserida. O agente não irá conectar até que configure /etc/sentinela/agent.conf."
    fi
else
    inf "Arquivo agent.conf já existe. Mantendo configuração atual."
fi

# 4. Serviços Systemd (Hardened Generation)
inf "Aplicando Systemd Hardening..."

# Timer NXDOMAIN
if [[ -f "${REPO_ROOT}/systemd/top-nxdomain.service" ]]; then
    install -m 0644 "${REPO_ROOT}/systemd/top-nxdomain.service" /etc/systemd/system/
    install -m 0644 "${REPO_ROOT}/systemd/top-nxdomain.timer" /etc/systemd/system/
    systemctl enable --now top-nxdomain.timer
fi

# Service Agent BLINDADO
cat > /etc/systemd/system/sentinela-agent.service <<EOF
[Unit]
Description=Sentinela-DNS Agent (Hardened)
After=network-online.target unbound.service nsd.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sentinela-agent.py
Restart=on-failure
RestartSec=10s

# --- SECURITY SANDBOX ---
ProtectSystem=strict
ReadWritePaths=/etc/unbound/unbound.conf.d /etc/nsd /var/lib/sentinela /run/sentinela /etc/sentinela
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now sentinela-agent.service
ok "Agente Sentinela instalado, blindado e ativo."

ok "Instalação concluída."
echo "Grafana: http://SEU_IP:3000"