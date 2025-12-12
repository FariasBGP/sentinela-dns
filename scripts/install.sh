#!/usr/bin/env bash
# Sentinela-DNS — install.sh (v4.8 Standalone Ultimate)
# Instala seletivamente: DNS, Flow e Monitoramento.
# GERA TODOS OS ARQUIVOS (INCLUINDO AGENTE PYTHON) LOCALMENTE.

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

# Variáveis de Controle
GRAFANA_INSTALL="yes"
PROM_INSTALL="yes"
NODE_EXPORTER_INSTALL="yes"

# ===== WIZARD DE SELEÇÃO =====
echo ""
echo "=================================================================="
echo "  INSTALADOR SENTINELA-DNS v4.8 (Standalone Ultimate)"
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

if [[ ! "$OPT_MON" =~ ^[Ss] ]]; then
    GRAFANA_INSTALL="no"
    PROM_INSTALL="no"
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
    
    # --- LOGGING (CRÍTICO) ---
    cat >/etc/unbound/unbound.conf.d/90-logging.conf <<'EOF'
server:
  log-queries: yes
  log-replies: yes
  use-syslog: yes
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
    ok "Unbound configurado (com logs ativos)."

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

    # --- Coletor NXDOMAIN (Criação INLINE) ---
    inf "Criando script de métricas NXDOMAIN..."
    cat > /usr/local/bin/top-nxdomain-optimized.sh <<'EOF'
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

total_nxdomain() {
  journalctl -u unbound -S -"${WINDOW}" --lines=100000 --no-pager 2>/dev/null | grep ' IN NXDOMAIN ' | wc -l | tr -d ' ' || echo 0
}

top_ips() {
  journalctl -u unbound -S -"${WINDOW}" --lines=100000 --no-pager 2>/dev/null | grep ' IN NXDOMAIN ' \
    | awk '/info:/ {print $8}' \
    | sort | uniq -c | sort -nr | head -"$TOPN" || true
}

top_domains() {
  journalctl -u unbound -S -"${WINDOW}" --lines=100000 --no-pager 2>/dev/null | grep ' IN NXDOMAIN ' \
    | awk '/info:/ {sub(/\.$/,"",$9); print $9}' \
    | sort | uniq -c | sort -nr | head -"$TOPN" || true
}

top_ips > "${TMP}.ips" &
top_domains > "${TMP}.doms" &
TOTAL="$(total_nxdomain)"
wait

IPS="$(cat "${TMP}.ips")"
DOMS="$(cat "${TMP}.doms")"
rm -f "${TMP}.ips" "${TMP}.doms"

{
  echo "# HELP sentinela_nxdomain_total Total de respostas NXDOMAIN"
  echo "# TYPE sentinela_nxdomain_total gauge"
  echo "sentinela_nxdomain_total{window=\"${WINDOW}\"} ${TOTAL}"
  echo
  echo "# HELP sentinela_nxdomain_ip_count Top IPs NXDOMAIN"
  echo "# TYPE sentinela_nxdomain_ip_count gauge"
  if [ -n "${IPS}" ]; then
    while read -r c ip; do
      [ -z "${ip}" ] && continue
      echo "sentinela_nxdomain_ip_count{ip=\"${ip}\",window=\"${WINDOW}\"} ${c}"
    done <<< "$IPS"
  fi
  echo
  echo "# HELP sentinela_nxdomain_domain_count Top Domínios NXDOMAIN"
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

install -m 0644 "$TMP" "$OUT"
chown prometheus:prometheus "$OUT" || true
rm -f "$TMP"
EOF
    chmod +x /usr/local/bin/top-nxdomain-optimized.sh
    ok "Script NXDOMAIN criado."

    cat > /etc/systemd/system/top-nxdomain.service <<'EOF'
[Unit]
Description=Gera métricas NXDOMAIN (textfile collector)
Wants=network-online.target
After=network-online.target unbound.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/top-nxdomain-optimized.sh 12h 20
EOF
    cat > /etc/systemd/system/top-nxdomain.timer <<'EOF'
[Unit]
Description=Executa o coletor de métricas NXDOMAIN a cada 10 minutos
[Timer]
OnBootSec=1min
OnUnitActiveSec=10min
Unit=top-nxdomain.service
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now top-nxdomain.timer
    ok "Coletor NXDOMAIN agendado."

    # --- Agente Sentinela (INLINE - SEM GIT) ---
    inf "Instalando Agente Sentinela..."
    
    install -d -m 0700 /etc/sentinela /var/lib/sentinela
    install -d -m 0755 /etc/nsd
    install -d -m 0775 /etc/nsd/zones
    chown nsd:nsd /etc/nsd/zones 2>/dev/null || true

    # Criação do Script Python (Inline)
    cat > /usr/local/bin/sentinela-agent.py <<'END_PYTHON'
#!/usr/bin/env python3
import requests
import json
import os
import sys
import subprocess
import time
import configparser
from contextlib import contextmanager

if len(sys.argv) > 1:
    CONFIG_FILE = sys.argv[1]
    STATE_FILE = f"/var/lib/sentinela/state_{os.path.basename(CONFIG_FILE)}.json"
else:
    CONFIG_FILE = "/etc/sentinela/agent.conf"
    STATE_FILE = "/var/lib/sentinela/last_state.json"

POLL_INTERVAL = 60
UNBOUND_BLOCK_FILE = "/etc/unbound/unbound.conf.d/92-sentinela-blocklist.conf"
UNBOUND_IFACE_FILE = "/etc/unbound/unbound.conf.d/63-listen-interfaces.conf"
UNBOUND_ACL_LOCALS = "/etc/unbound/unbound.conf.d/51-acls-locals.conf"
UNBOUND_ACL_TRUSTEDS = "/etc/unbound/unbound.conf.d/52-acls-trusteds.conf"
NSD_CONF_DIR = "/etc/nsd"
NSD_ZONES_DIR = "/etc/nsd/zones"
NSD_MAIN_CONF = "/etc/nsd/nsd.conf"

@contextmanager
def Mbox(msg):
    print("=" * (len(msg) + 4))
    print(f"[ {msg} ]")
    print("=" * (len(msg) + 4))
    yield
    print("-" * (len(msg) + 4))

def read_config():
    try:
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)
        return config['api']['url'], config['api']['key']
    except Exception as e:
        print(f"ERRO: Configuração inválida ({CONFIG_FILE}): {e}")
        return None, None

def fetch_remote_config(url, api_key):
    try:
        headers = {'Authorization': f'Bearer {api_key}'}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"ERRO: Falha na API: {e}")
        return None

def fetch_external_blocklist(url_list):
    if not url_list: return set()
    MAX_LINES = 500000 
    total_lines = 0
    final_set = set()
    for url in url_list:
        try:
            print(f"  A baixar lista externa: {url}")
            with requests.get(url, stream=True, timeout=15) as r:
                r.raise_for_status()
                for line in r.iter_lines():
                    if total_lines >= MAX_LINES: break
                    if line:
                        decoded = line.decode('utf-8', errors='ignore').strip()
                        if decoded: final_set.add(decoded); total_lines += 1
        except Exception as e: print(f"  AVISO: Erro na lista {url}: {e}")
    return final_set

def apply_recursive(config):
    print(">>> Modo: RECURSIVO (Unbound)")
    bind_ips = config['settings'].get('bind_ip', '0.0.0.0').split()
    try:
        with open(UNBOUND_IFACE_FILE, 'w') as f:
            f.write("server:\n")
            for ip in bind_ips: f.write(f"  interface: {ip}\n")
            f.write("  port: 53\n  do-udp: yes\n  do-tcp: yes\n")
    except Exception as e: print(f"Erro interfaces: {e}")

    acls = config.get('acls', {})
    try:
        with open(UNBOUND_ACL_LOCALS, 'w') as f:
            f.write("server:\n  access-control: 127.0.0.1/32 allow\n  access-control: ::1/128 allow\n")
            for cidr in acls.get('locals', []):
                if cidr.strip(): f.write(f"  access-control: {cidr.strip()} allow\n")
    except Exception as e: print(f"Erro ACL Locals: {e}")

    try:
        with open(UNBOUND_ACL_TRUSTEDS, 'w') as f:
            f.write("server:\n")
            for cidr in acls.get('trusteds', []):
                if cidr.strip(): f.write(f"  access-control: {cidr.strip()} allow\n")
    except Exception as e: print(f"Erro ACL Trusteds: {e}")

    priv_list = set(config.get('blocklist_private', []))
    ext_urls = config.get('blocklist_external_urls', [])
    ext_list = set()
    if ext_urls:
        cached = get_current_state().get('cached_ext_list', []) if get_current_state() else []
        res = fetch_external_blocklist(ext_urls)
        ext_list = res if res is not None else set(cached)
        if res is not None: config['cached_ext_list'] = list(ext_list)

    final_list = list(priv_list | ext_list)
    rv4 = config['settings'].get('redirect_ip_v4', '127.0.0.1')
    rv6 = config['settings'].get('redirect_ip_v6', '::1')

    try:
        with open(UNBOUND_BLOCK_FILE, 'w') as f:
            f.write("# SENTINELA-DNS BLOCKLIST\nserver:\n")
            for d in sorted(final_list):
                d = d.strip().replace("http://", "").replace("https://", "").split("/")[0]
                if d:
                    f.write(f"  local-zone: \"{d}\" redirect\n")
                    f.write(f"  local-data: \"{d} A {rv4}\"\n")
                    f.write(f"  local-data: \"{d} AAAA {rv6}\"\n")
    except Exception as e: print(f"Erro blocklist: {e}")

    if subprocess.run(['unbound-checkconf'], capture_output=True, timeout=30).returncode == 0:
        subprocess.run(['systemctl', 'restart', 'unbound'], timeout=30)
        print("Unbound recarregado.")
    else: print("ERRO CRÍTICO: Configuração inválida.")

def apply_authoritative(config):
    print(">>> Modo: AUTORITATIVO (NSD)")
    os.makedirs(NSD_ZONES_DIR, exist_ok=True)
    bind_ips = config['settings'].get('bind_ip', '0.0.0.0').split()
    zonas = config.get('zonas', [])
    try:
        with open(NSD_MAIN_CONF, 'w') as f:
            f.write("server:\n")
            for ip in bind_ips: f.write(f"  ip-address: {ip}\n")
            f.write("  port: 53\n  username: nsd\n  zonesdir: \"/etc/nsd/zones\"\n\n")
            f.write("remote-control:\n  control-enable: yes\n  control-interface: 127.0.0.1\n\n")
            for z in zonas:
                safe = z['nome'].strip('.').replace('/', '_') + ".zone"
                f.write(f"zone:\n  name: \"{z['nome']}\"\n  zonefile: \"{safe}\"\n")
    except Exception as e: print(f"Erro nsd.conf: {e}")

    for z in zonas:
        safe = z['nome'].strip('.').replace('/', '_') + ".zone"
        zfile = os.path.join(NSD_ZONES_DIR, safe)
        try:
            with open(zfile, 'w') as f:
                f.write(f"$ORIGIN {z['nome']}.\n$TTL {z['ttl']}\n")
                f.write(f"@ IN SOA ns1.{z['nome']}. {z['email'].replace('@', '.')} (\n")
                f.write(f" {z['serial']} 3600 1800 604800 86400 )\n")
                f.write(f"  IN NS ns1.{z['nome']}.\n  IN NS ns2.{z['nome']}.\n\n")
                for reg in z['registros']:
                    h = reg['host']; v = reg['valor']
                    if h == '@': h = ''
                    if reg['tipo'] in ['CNAME', 'NS', 'PTR'] and not v.endswith('.'): v += '.'
                    f.write(f"{h}\tIN\t{reg['tipo']}\t{v}\n")
        except Exception as e: print(f"Erro zona {z['nome']}: {e}")

    subprocess.run(['systemctl', 'enable', 'nsd'], capture_output=True)
    subprocess.run(['systemctl', 'restart', 'nsd'], capture_output=True)
    print("NSD recarregado.")

def get_current_state():
    try:
        with open(STATE_FILE, 'r') as f: return json.load(f)
    except: return None

def write_new_state(state_data):
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, 'w') as f: json.dump(state_data, f)
    except Exception as e: print(f"Erro estado: {e}")

def main_loop():
    with Mbox(f"Sentinela-Agente Iniciado"): pass
    fail_count = 0
    while True:
        try:
            api_url, api_key = read_config()
            if not api_url: 
                time.sleep(POLL_INTERVAL); continue
            
            print("Verificando API...")
            remote = fetch_remote_config(api_url, api_key)
            if remote:
                fail_count = 0
                current = get_current_state()
                r_clean = remote.copy(); c_clean = current.copy() if current else {}
                if 'cached_ext_list' in r_clean: del r_clean['cached_ext_list']
                if 'cached_ext_list' in c_clean: del c_clean['cached_ext_list']

                if c_clean == r_clean: print("Sem alterações.")
                else:
                    mode = remote.get('mode')
                    if mode == 'recursive':
                        subprocess.run(['systemctl', 'start', 'unbound'], capture_output=True)
                        apply_recursive(remote)
                    elif mode == 'authoritative':
                        apply_authoritative(remote)
                    write_new_state(remote)
            else:
                fail_count += 1
                print(f"Falha na API. Tentativa {fail_count}...")
        except KeyboardInterrupt: sys.exit(0)
        except Exception as e: print(f"Erro crítico: {e}"); time.sleep(60)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    try: main_loop()
    except KeyboardInterrupt: sys.exit(0)
END_PYTHON
    chmod +x /usr/local/bin/sentinela-agent.py
    ok "Agente instalado (Versão Inline)."

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
             ok "Analisador criado."

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

        # Se houver dashboards, poderia baixar aqui, mas sem git vamos pular essa cópia de arquivos complexos
        # ou embuti-los se fossem críticos. O essencial (DataSource) está configurado.
        
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
