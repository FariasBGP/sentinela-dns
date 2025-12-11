#!/usr/bin/env bash
# Sentinela-DNS — install.sh (v4.5 Stable & Fixes)
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
GOFLOW2_VERSION="${GOFLOW2_VERSION:-2.2.3}" 
PROM_URL="${PROM_URL:-http://localhost:9090}"
API_URL_DEFAULT="https://api-sentinela.bgpconsultoria.com.br/api/v1/config"

# Variáveis de Controle (Padrão) - Evita erro 'unbound variable'
GRAFANA_INSTALL="yes"
PROM_INSTALL="yes"
NODE_EXPORTER_INSTALL="yes"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ===== WIZARD DE SELEÇÃO =====
echo ""
echo "=================================================================="
echo "  INSTALADOR SENTINELA-DNS v4.5 (Stable Fixes)"
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

# Atualiza variáveis baseado na escolha do usuário
if [[ ! "$OPT_MON" =~ ^[Ss] ]]; then
    GRAFANA_INSTALL="no"
    PROM_INSTALL="no"
    # Node Exporter mantemos pois é útil para debug geral
fi

echo ""
inf "Iniciando instalação..."

# ===== SO Check & Base =====
. /etc/os-release || true
LIBSSL_PKG="libssl3"
if [[ "${VERSION_ID%%.*}" == "13" ]]; then LIBSSL_PKG="libssl3t64"; fi

inf "Atualizando sistema e pacotes base..."
apt-get update -y
apt-get dist-upgrade -y || true

# Pacotes Comuns
apt-get install -y curl wget jq tar ca-certificates gnupg lsb-release apt-transport-https \
                   dnsutils iproute2 netcat-openbsd apparmor-utils psmisc prometheus-node-exporter

# Configura Node Exporter
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

    apt-get install -y "${LIBSSL_PKG}" unbound unbound-anchor nsd python3-requests

    # Desabilita AppArmor
    aa-disable /etc/apparmor.d/usr.sbin.unbound 2>/dev/null || true

    if systemctl is-active --quiet nsd; then systemctl stop nsd; fi

    # --- Configuração Unbound ---
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
    cat >/etc/unbound/unbound.conf.d/59-acls-default-policy.conf <<'EOF'
server:
  access-control: 0.0.0.0/0 deny
  access-control: ::/0 deny
EOF
    # CORREÇÃO DE SINTAXE: Cada diretiva em uma linha separada
    cat >/etc/unbound/unbound.conf.d/61-configs.conf <<'EOF'
server:
  outgoing-range: 8192
  outgoing-port-avoid: 0-1024
  outgoing-port-permit: 1025-65535
  num-threads: 4
  msg-cache-size: 128m
  rrset-cache-size: 256m
  so-reuseport: yes
  harden-glue: yes
  harden-dnssec-stripped: yes
  use-caps-for-id: no
  edns-buffer-size: 1232
  prefetch: yes
  serve-expired: yes
EOF
    cat >/etc/unbound/unbound.conf.d/63-listen-interfaces.conf <<'EOF'
server:
  interface: 0.0.0.0
  interface: ::0
  port: 53
  do-udp: yes
  do-tcp: yes
EOF
    cat >/etc/unbound/unbound.conf.d/20-dnssec.conf <<'EOF'
server:
  auto-trust-anchor-file: "/var/lib/unbound/root.key"
EOF
    cat >/etc/unbound/unbound.conf.d/99-remote-control.conf <<'EOF'
server:
  chroot: ""
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

    # --- Scripts Auxiliares DNS (CORRIGIDO) ---
    if [[ -f "${REPO_ROOT}/scripts/top-nxdomain-optimized.sh" ]]; then
      install -m 0755 "${REPO_ROOT}/scripts/top-nxdomain-optimized.sh" /usr/local/bin/top-nxdomain-optimized.sh
      ok "Script top-nxdomain-optimized.sh instalado."
    elif [[ -f "${REPO_ROOT}/tools/top-nxdomain.sh" ]]; then
      # Fallback
      install -m 0755 "${REPO_ROOT}/tools/top-nxdomain.sh" /usr/local/bin/top-nxdomain.sh
      warn "Usando versão legada do top-nxdomain.sh"
    fi
    
    if [[ -f "${REPO_ROOT}/tools/top-talkers.sh" ]]; then
      install -m 0755 "${REPO_ROOT}/tools/top-talkers.sh" /usr/local/bin/top-talkers.sh
    fi
    
    # Timers Systemd (Ajuste para chamar o script correto)
    if [[ -f "${REPO_ROOT}/systemd/top-nxdomain.service" ]]; then
        install -m 0644 "${REPO_ROOT}/systemd/top-nxdomain.service" /etc/systemd/system/
        install -m 0644 "${REPO_ROOT}/systemd/top-nxdomain.timer" /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable --now top-nxdomain.timer
    fi

    # --- Agente Sentinela (Recursivo/Auth) ---
    inf "Configurando Agente..."
    if [[ -f "${REPO_ROOT}/scripts/sentinela-agent.py" ]]; then
        install -m 0700 "${REPO_ROOT}/scripts/sentinela-agent.py" /usr/local/bin/sentinela-agent.py
        sed -i '/from collections import deque/d' /usr/local/bin/sentinela-agent.py
    fi

    install -d -m 0700 /etc/sentinela /var/lib/sentinela
    install -d -m 0755 /etc/nsd
    install -d -m 0775 /etc/nsd/zones
    chown nsd:nsd /etc/nsd/zones 2>/dev/null || true

    if [[ ! -f "/etc/sentinela/agent.conf" ]]; then
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

    GOFLOW_URL="https://github.com/netsampler/goflow2/releases/download/v${GOFLOW2_VERSION}/goflow2-${GOFLOW2_VERSION}-linux-x86_64"
    
    # FIX: Para serviço antes de baixar para evitar 'Text file busy'
    if systemctl is-active --quiet sentinela-flow; then
        inf "Parando serviço sentinela-flow para atualização..."
        systemctl stop sentinela-flow
    fi

    if curl -fsSL --connect-timeout 15 -o /usr/local/bin/goflow2 "$GOFLOW_URL"; then
        chmod +x /usr/local/bin/goflow2
        ok "Binário GoFlow2 (v${GOFLOW2_VERSION}) instalado."

        cat > /etc/systemd/system/sentinela-flow.service <<EOF
[Unit]
Description=Sentinela-Flow (NetFlow Collector)
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/goflow2 -listen "netflow://:2055" -addr ":9191" -transport "file" -transport.file "/var/log/goflow.log"
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
        
        # Script Analisador
        if [[ -f "${REPO_ROOT}/tools/flow-analyzer.sh" ]]; then
            install -m 0755 "${REPO_ROOT}/tools/flow-analyzer.sh" /usr/local/bin/flow-analyzer.sh
        elif [[ -f "/usr/local/bin/flow-analyzer.sh" ]]; then
             ok "Analisador já presente."
        else
             cat > /usr/local/bin/flow-analyzer.sh <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
LOG_FILE="/var/log/goflow.log"
OUT_FILE="/var/lib/node_exporter/textfile_collector/sentinela_flow_threats.prom"
TMP_FILE="${OUT_FILE}.tmp.$$"
PORTS_FILTER="23|22|8291|3389|445|21" 
if [ ! -f "$LOG_FILE" ]; then exit 0; fi
DATA=$(tail -n 10000 "$LOG_FILE" | grep -E "\"dst_port\":($PORTS_FILTER)," | jq -r '"\(.src_addr) \(.dst_port)"' | sort | uniq -c | sort -nr | head -n 20)
{
  echo "# HELP sentinela_flow_threat_count Top IPs atacando portas críticas"
  echo "# TYPE sentinela_flow_threat_count gauge"
  if [ -n "$DATA" ]; then
    while read -r count ip port; do
      echo "sentinela_flow_threat_count{ip=\"$ip\",port=\"$port\"} $count"
    done <<< "$DATA"
  fi
} > "$TMP_FILE"
mv "$TMP_FILE" "$OUT_FILE"
chown prometheus:prometheus "$OUT_FILE" 2>/dev/null || true
chmod 644 "$OUT_FILE"
if [ -f "$LOG_FILE" ] && [ $(stat -c%s "$LOG_FILE") -ge 104857600 ]; then truncate -s 0 "$LOG_FILE"; fi
EOF
             chmod +x /usr/local/bin/flow-analyzer.sh
             ok "Analisador criado (fallback)."
        fi

        cat > /etc/systemd/system/sentinela-threats.service <<EOF
[Unit]
Description=Sentinela Threats Analyzer
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/flow-analyzer.sh
EOF
        cat > /etc/systemd/system/sentinela-threats.timer <<EOF
[Unit]
Description=Roda analisador de ameaças a cada 2 min
[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
Unit=sentinela-threats.service
[Install]
WantedBy=timers.target
EOF
        systemctl daemon-reload
        systemctl enable --now sentinela-threats.timer
        ok "Analisador de Ameaças agendado."
    else
        err "Falha ao baixar GoFlow2."
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

    # CORREÇÃO: Criação do prometheus.yml com sintaxe válida e modular
    cat > "/etc/prometheus/prometheus.yml" <<EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s
scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']
EOF

    # Adiciona jobs condicionais
    if [[ "$OPT_DNS" =~ ^[Ss] ]]; then
        cat >> "/etc/prometheus/prometheus.yml" <<EOF
  - job_name: 'unbound'
    static_configs:
      - targets: ['localhost:9167']
EOF
    fi

    if [[ "$OPT_FLOW" =~ ^[Ss] ]]; then
        cat >> "/etc/prometheus/prometheus.yml" <<EOF
  - job_name: 'netflow'
    static_configs:
      - targets: ['localhost:9191']
EOF
    fi

    systemctl enable --now prometheus
    systemctl restart prometheus

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
else
    inf "Monitoramento local ignorado."
fi

ok "Instalação Finalizada com Sucesso!"
