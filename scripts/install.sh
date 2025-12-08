#!/usr/bin/env bash
# Sentinela-DNS — install.sh (v4.1 Modular & Fixes)
# Instala seletivamente: DNS, Flow e Monitoramento.

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

# Versões
UNBOUND_EXPORTER_VERSION="${UNBOUND_EXPORTER_VERSION:-0.4.6}"
GOFLOW2_VERSION="${GOFLOW2_VERSION:-2.2.3}" # Atualizado para versão existente
PROM_URL="${PROM_URL:-http://localhost:9090}"
API_URL_DEFAULT="https://api-sentinela.bgpconsultoria.com.br/api/v1/config"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ===== WIZARD DE SELEÇÃO =====
echo ""
echo "=================================================================="
echo "  INSTALADOR SENTINELA-DNS v4.1 (Modular + Fixes)"
echo "=================================================================="
echo "Selecione os componentes para instalar neste servidor."
echo ""

# 1. Módulo DNS
read -p ">> Instalar Módulo DNS (Unbound + NSD + Agente)? [S/n]: " OPT_DNS
OPT_DNS=${OPT_DNS:-S}

# 2. Módulo Flow
read -p ">> Instalar Módulo Flow (Coletor NetFlow)? [s/N]: " OPT_FLOW
OPT_FLOW=${OPT_FLOW:-N}

# 3. Monitoramento
read -p ">> Instalar Stack Monitoramento (Prometheus + Grafana)? [S/n]: " OPT_MON
OPT_MON=${OPT_MON:-S}

echo ""
inf "Iniciando instalação..."
echo "   - DNS: $OPT_DNS"
echo "   - Flow: $OPT_FLOW"
echo "   - Mon: $OPT_MON"
sleep 2

# ===== SO Check & Base =====
. /etc/os-release || true
LIBSSL_PKG="libssl3"
if [[ "${VERSION_ID%%.*}" == "13" ]]; then LIBSSL_PKG="libssl3t64"; fi

inf "Atualizando sistema e pacotes base..."
apt-get update -y
apt-get dist-upgrade -y || true

# Pacotes Comuns a todos
apt-get install -y curl wget jq tar ca-certificates gnupg lsb-release apt-transport-https \
                   dnsutils iproute2 netcat-openbsd apparmor-utils psmisc prometheus-node-exporter

# Configura Node Exporter (Sempre presente para saúde do servidor)
install -d -m 0755 /etc/systemd/system/prometheus-node-exporter.service.d
cat > /etc/systemd/system/prometheus-node-exporter.service.d/override.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/prometheus-node-exporter --collector.textfile.directory=/var/lib/node_exporter/textfile_collector
EOF
systemctl daemon-reload
systemctl enable --now prometheus-node-exporter
ok "Base do sistema pronta."


# ==============================================================================
# MÓDULO DNS (Unbound, NSD, Agente, Exporter)
# ==============================================================================
if [[ "$OPT_DNS" =~ ^[Ss] ]]; then
    inf "Instalando Módulo DNS..."

    # Instala pacotes específicos DNS
    apt-get install -y "${LIBSSL_PKG}" unbound unbound-anchor nsd python3-requests

    # Desabilita AppArmor
    aa-disable /etc/apparmor.d/usr.sbin.unbound 2>/dev/null || true

    # Previne conflito porta 53 durante install
    if systemctl is-active --quiet nsd; then systemctl stop nsd; fi

    # --- Configuração Unbound ---
    install -d -m 0755 /etc/unbound/unbound.conf.d
    rm -f /etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf

    cat >/etc/unbound/unbound.conf <<'EOF'
server:
  verbosity: 1
include: "/etc/unbound/unbound.conf.d/*.conf"
EOF

    # (Configs padrão omitidas para brevidade - mantendo as essenciais)
    cat >/etc/unbound/unbound.conf.d/31-statisticas.conf <<'EOF'
server:
  statistics-interval: 0
  extended-statistics: yes
  statistics-cumulative: yes
EOF
    cat >/etc/unbound/unbound.conf.d/41-protocols.conf <<'EOF'
server:
  do-ip4: yes; do-ip6: yes; do-udp: yes; do-tcp: yes
EOF
    cat >/etc/unbound/unbound.conf.d/51-acls-locals.conf <<'EOF'
server:
  access-control: 127.0.0.1/32 allow; access-control: ::1/128 allow
  access-control: 10.0.0.0/8 allow; access-control: 100.64.0.0/10 allow; access-control: 172.16.0.0/12 allow
EOF
    cat >/etc/unbound/unbound.conf.d/59-acls-default-policy.conf <<'EOF'
server:
  access-control: 0.0.0.0/0 deny; access-control: ::/0 deny
EOF
    cat >/etc/unbound/unbound.conf.d/61-configs.conf <<'EOF'
server:
  outgoing-range: 8192; outgoing-port-avoid: 0-1024; outgoing-port-permit: 1025-65535
  num-threads: 4; msg-cache-size: 128m; rrset-cache-size: 256m; so-reuseport: yes
  harden-glue: yes; harden-dnssec-stripped: yes; use-caps-for-id: no
  edns-buffer-size: 1232; prefetch: yes; serve-expired: yes
EOF
    cat >/etc/unbound/unbound.conf.d/63-listen-interfaces.conf <<'EOF'
server:
  interface: 0.0.0.0; interface: ::0; port: 53; do-udp: yes; do-tcp: yes
EOF
    cat >/etc/unbound/unbound.conf.d/20-dnssec.conf <<'EOF'
server:
  auto-trust-anchor-file: "/var/lib/unbound/root.key"
EOF
    cat >/etc/unbound/unbound.conf.d/99-remote-control.conf <<'EOF'
server:
  chroot: ""; username: "unbound"
remote-control:
  control-enable: yes; control-interface: 127.0.0.1; control-port: 8953; control-use-cert: yes
  server-key-file: "/etc/unbound/unbound_server.key"; server-cert-file: "/etc/unbound/unbound_server.pem"
  control-key-file: "/etc/unbound/unbound_control.key"; control-cert-file: "/etc/unbound/unbound_control.pem"
EOF

    chown -R unbound:unbound /etc/unbound /var/lib/unbound
    chmod -R 755 /etc/unbound
    chmod 644 /var/lib/unbound/root.key 2>/dev/null || true

    if [[ ! -f /etc/unbound/unbound_server.key ]]; then
      inf "Gerando certificados Unbound..."
      unbound-control-setup -d /etc/unbound/ >/dev/null 2>&1 || true
      chown unbound:unbound /etc/unbound/unbound_{server,control}.{key,pem}
    fi

    # Systemd Override Unbound
    install -d -m 0755 /etc/systemd/system/unbound.service.d
    cat >/etc/systemd/system/unbound.service.d/override.conf <<'EOF'
[Service]
ExecStartPre=
Environment="DAEMON_OPTS="
ExecStart=
ExecStart=/usr/sbin/unbound -d $DAEMON_OPTS
EOF
    systemctl daemon-reload
    systemctl enable unbound; systemctl restart unbound
    ok "Unbound configurado."

    # --- Unbound Exporter ---
    if ! command -v unbound_exporter >/dev/null 2>&1; then
      inf "Compilando unbound_exporter..."
      apt-get install -y golang
      GO111MODULE=on GOBIN=/usr/local/bin go install "github.com/letsencrypt/unbound_exporter@v${UNBOUND_EXPORTER_VERSION}"
    fi
    cat > /etc/systemd/system/unbound_exporter.service <<'EOF'
[Unit]
Description=Prometheus Unbound Exporter
After=network-online.target unbound.service
[Service]
User=unbound
Group=unbound
ExecStart=/usr/local/bin/unbound_exporter --unbound.host=tcp://127.0.0.1:8953 --unbound.cert=/etc/unbound/unbound_control.pem --unbound.key=/etc/unbound/unbound_control.key --web.listen-address=:9167 --web.telemetry-path=/metrics
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
    systemctl enable --now unbound_exporter

    # --- Scripts Auxiliares DNS ---
    if [[ -f "${REPO_ROOT}/tools/top-nxdomain.sh" ]]; then
      install -m 0755 "${REPO_ROOT}/tools/top-nxdomain.sh" /usr/local/bin/top-nxdomain.sh
    fi
    if [[ -f "${REPO_ROOT}/tools/top-talkers.sh" ]]; then
      install -m 0755 "${REPO_ROOT}/tools/top-talkers.sh" /usr/local/bin/top-talkers.sh
    fi
    
    # Timers Systemd
    for S in top-nxdomain top-talkers; do
        if [[ -f "${REPO_ROOT}/systemd/${S}.service" ]]; then
            install -m 0644 "${REPO_ROOT}/systemd/${S}.service" /etc/systemd/system/
            install -m 0644 "${REPO_ROOT}/systemd/${S}.timer" /etc/systemd/system/
            systemctl enable --now ${S}.timer
        fi
    done

    # --- Agente Sentinela (Recursivo/Auth) ---
    inf "Configurando Agente..."
    if [[ -f "${REPO_ROOT}/scripts/sentinela-agent.py" ]]; then
        install -m 0700 "${REPO_ROOT}/scripts/sentinela-agent.py" /usr/local/bin/sentinela-agent.py
        sed -i '/from collections import deque/d' /usr/local/bin/sentinela-agent.py
    fi

    # Pastas e Config
    install -d -m 0700 /etc/sentinela /var/lib/sentinela
    install -d -m 0755 /etc/nsd
    install -d -m 0775 /etc/nsd/zones
    chown nsd:nsd /etc/nsd/zones 2>/dev/null || true

    # Wizard Agente
    if [[ ! -f "/etc/sentinela/agent.conf" ]]; then
        echo ">>> CONFIGURAÇÃO RECURSIVA <<<"
        read -p "API Key (Recursivo) [Enter para pular]: " USER_API_KEY
        if [[ -n "$USER_API_KEY" ]]; then
            cat > /etc/sentinela/agent.conf <<EOF
[api]
url = ${API_URL_DEFAULT}
key = ${USER_API_KEY}
EOF
            chmod 600 /etc/sentinela/agent.conf
        fi
    fi

    if [[ ! -f "/etc/sentinela/agent-auth.conf" ]]; then
        read -p "Configurar Autoritativo (NSD)? [y/N]: " CONFIRM_AUTH
        if [[ "$CONFIRM_AUTH" =~ ^[Yy]$ ]]; then
            read -p "API Key (Autoritativo): " AUTH_API_KEY
            if [[ -n "$AUTH_API_KEY" ]]; then
                cat > /etc/sentinela/agent-auth.conf <<EOF
[api]
url = ${API_URL_DEFAULT}
key = ${AUTH_API_KEY}
EOF
                chmod 600 /etc/sentinela/agent-auth.conf
            fi
        fi
    fi

    # Services Agente
    cat > /etc/systemd/system/sentinela-agent.service <<EOF
[Unit]
Description=Sentinela-DNS Agent (Recursivo)
After=network-online.target unbound.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sentinela-agent.py
Restart=on-failure
RestartSec=10s
RuntimeDirectory=sentinela
ProtectSystem=strict
ReadWritePaths=/etc/unbound/unbound.conf.d /etc/nsd /var/lib/sentinela /run/sentinela /etc/sentinela
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/sentinela-agent-auth.service <<EOF
[Unit]
Description=Sentinela-DNS Agent (Autoritativo)
After=network-online.target nsd.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sentinela-agent.py /etc/sentinela/agent-auth.conf
Restart=on-failure
RestartSec=10s
RuntimeDirectory=sentinela
ProtectSystem=strict
ReadWritePaths=/etc/unbound/unbound.conf.d /etc/nsd /var/lib/sentinela /run/sentinela /etc/sentinela
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    if [[ -f "/etc/sentinela/agent.conf" ]]; then systemctl enable --now sentinela-agent.service; fi
    if [[ -f "/etc/sentinela/agent-auth.conf" ]]; then systemctl enable --now sentinela-agent-auth.service; fi

    ok "Módulo DNS instalado com sucesso."
else
    inf "Módulo DNS ignorado."
fi


# ==============================================================================
# MÓDULO FLOW (NetFlow)
# ==============================================================================
if [[ "$OPT_FLOW" =~ ^[Ss] ]]; then
    inf "Instalando Módulo Sentinela-Flow..."

    # URL CORRIGIDA PARA O BINÁRIO
    GOFLOW_URL="https://github.com/netsampler/goflow2/releases/download/v${GOFLOW2_VERSION}/goflow2-${GOFLOW2_VERSION}-linux-x86_64"
    
    # Download direto do binário
    if curl -fsSL --connect-timeout 15 -o /usr/local/bin/goflow2 "$GOFLOW_URL"; then
        chmod +x /usr/local/bin/goflow2
        ok "Binário GoFlow2 (v${GOFLOW2_VERSION}) instalado em /usr/local/bin/goflow2."

        cat > /etc/systemd/system/sentinela-flow.service <<EOF
[Unit]
Description=Sentinela-Flow (NetFlow Collector)
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/goflow2 -listen "netflow://:2055" -metrics.addr ":9191" -loglevel "error"
Nice=19
CPUSchedulingPolicy=idle
Restart=on-failure
RestartSec=10s
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now sentinela-flow.service
        ok "Módulo Flow ativo na porta 2055."
    else
        err "Falha ao baixar GoFlow2. URL: $GOFLOW_URL"
        warn "O módulo de Flow não será iniciado."
    fi
else
    inf "Módulo Flow ignorado."
fi


# ==============================================================================
# MONITORAMENTO (Prometheus & Grafana)
# ==============================================================================
if [[ "$OPT_MON" =~ ^[Ss] ]]; then
    inf "Instalando Stack de Monitoramento..."
    apt-get install -y prometheus

    # Configura Prometheus Targets dinamicamente
    TARGETS="['localhost:9090']"
    if [[ "$OPT_DNS" =~ ^[Ss] ]]; then
        TARGETS="$TARGETS, {targets: ['localhost:9167'], labels: {job: 'unbound'}}" # Unbound Exp
    fi
    # Node Exporter sempre presente
    TARGETS="$TARGETS, {targets: ['localhost:9100'], labels: {job: 'node'}}" 
    if [[ "$OPT_FLOW" =~ ^[Ss] ]]; then
        TARGETS="$TARGETS, {targets: ['localhost:9191'], labels: {job: 'netflow'}}"
    fi

    cat > "/etc/prometheus/prometheus.yml" <<EOF
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: 'sentinela'
    static_configs:
      - targets: $TARGETS
EOF
    systemctl enable --now prometheus
    systemctl restart prometheus

    # Grafana
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
    ok "Monitoramento ativo."
else
    inf "Monitoramento local ignorado."
fi

ok "Instalação Finalizada com Sucesso!"
