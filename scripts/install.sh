#!/usr/bin/env bash
# Sentinela-DNS — install.sh
# Instala/atualiza Unbound + Exporters + Prometheus + Grafana (Debian 12/13).

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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ===== SO =====
. /etc/os-release || true
case "${VERSION_ID%%.*}" in
  12|13) ok "Debian ${VERSION_ID} detectado."; ;;
  *)     warn "SO não testado oficialmente (${PRETTY_NAME:-?}). Prosseguindo…";;
esac

# Define pacote libssl baseado na versão do Debian
LIBSSL_PKG="libssl3"
if [[ "${VERSION_ID%%.*}" == "13" ]]; then
  LIBSSL_PKG="libssl3t64"
fi

# ===== Pacotes base =====
inf "Atualizando sistema e instalando utilitários…"
apt-get update -y
apt-get dist-upgrade -y || true
apt-get install -y curl wget jq tar ca-certificates gnupg lsb-release apt-transport-https \
                   dnsutils iproute2 netcat-openbsd apparmor-utils "${LIBSSL_PKG}" unbound unbound-anchor

# Desabilita AppArmor para unbound (evita problemas de permissão em certs)
inf "Desabilitando AppArmor para unbound..."
aa-disable /etc/apparmor.d/usr.sbin.unbound || true

# ===== Unbound (config modular) =====
inf "Configurando Unbound (modular)…"
install -d -m 0755 /etc/unbound/unbound.conf.d

# unbound.conf — mantém apenas 1 include, removendo configs padrão que possam duplicar
rm -f /etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf  # Remove se existir do pacote
cat >/etc/unbound/unbound.conf <<'EOF'
server:
  verbosity: 1

include: "/etc/unbound/unbound.conf.d/*.conf"
EOF

# Fragments (idempotentes) - Removido 21-root-auto-trust-anchor-file.conf para evitar duplicata com auth-zone

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
  # access-control: 2001:db8::/32 allow
EOF

cat >/etc/unbound/unbound.conf.d/59-acls-default-policy.conf <<'EOF'
server:
  access-control: 0.0.0.0/0 deny
  access-control: ::/0 deny
EOF

# Ajustes de desempenho (alinhados e potências de 2)
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

# Interfaces
cat >/etc/unbound/unbound.conf.d/63-listen-interfaces.conf <<'EOF'
server:
  interface: 0.0.0.0
  interface: ::0
  port: 53
  do-udp: yes
  do-tcp: yes
EOF

# Hyperlocal root cache (opcional) - Isso substitui o auto-trust-anchor
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

# Remote-control (sem chroot para evitar conflitos)
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

# Corrige permissões no diretório unbound
chown -R unbound:unbound /etc/unbound /var/lib/unbound
chmod -R 755 /etc/unbound
chmod 600 /etc/unbound/unbound_{server,control}.key 2>/dev/null || true
chmod 644 /etc/unbound/unbound_{server,control}.pem 2>/dev/null || true
chmod 644 /var/lib/unbound/root.key 2>/dev/null || true

# Valida config antes de prosseguir
if ! unbound-checkconf >/dev/null 2>&1; then
  err "Configuração do Unbound inválida! Verifique /etc/unbound/unbound.conf e fragments."
  unbound-checkconf
  exit 1
fi
ok "Configuração do Unbound validada."

# Gera certificados do unbound-control (idempotente, após config)
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

# Override systemd para remover chroot e definir ExecStart
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
sleep 2  # Aguarda estabilizar
systemctl restart unbound
sleep 2
if ! systemctl is-active --quiet unbound; then
  err "Falha ao iniciar Unbound após config. Verifique: systemctl status unbound"
  exit 1
fi
ok "Unbound ativo em :53."

# ===== unbound_exporter =====
inf "Instalando unbound_exporter (v${UNBOUND_EXPORTER_VERSION})…"
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
  inf "Tarball indisponível; compilando do source (Go)…"
  apt-get install -y golang
  GO111MODULE=on GOBIN=/usr/local/bin go install "github.com/letsencrypt/unbound_exporter@v${UNBOUND_EXPORTER_VERSION}"
fi
popd >/dev/null

# Service systemd do exporter
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
systemctl enable --now unbound_exporter
systemctl restart unbound_exporter
sleep 2
if ! systemctl is-active --quiet unbound_exporter; then
  err "Falha ao iniciar unbound_exporter. Verifique: journalctl -u unbound_exporter"
  exit 1
fi
ok "unbound_exporter ativo em :9167."

# ===== node_exporter =====
if [[ "$NODE_EXPORTER_INSTALL" == "yes" ]]; then
  inf "Instalando e configurando prometheus-node-exporter..."
  apt-get install -y prometheus-node-exporter

  # Garante que o exporter leia nosso diretório de métricas customizadas
  install -d -m 0755 /etc/systemd/system/prometheus-node-exporter.service.d
  cat > /etc/systemd/system/prometheus-node-exporter.service.d/override.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/prometheus-node-exporter --collector.textfile.directory=/var/lib/node_exporter/textfile_collector
EOF

  systemctl daemon-reload
  systemctl enable prometheus-node-exporter
  systemctl restart prometheus-node-exporter
  sleep 2
  if ! systemctl is-active --quiet prometheus-node-exporter; then
    err "Falha ao iniciar prometheus-node-exporter. Verifique: journalctl -u prometheus-node-exporter"
    exit 1
  fi
  ok "prometheus-node-exporter ativo em :9100 (com textfile collector)."
fi

# ===== Prometheus (idempotente) =====
if [[ "$PROM_INSTALL" == "yes" ]]; then
  apt-get install -y prometheus

  PROM_FILE="/etc/prometheus/prometheus.yml"
  PROM_DIR="/etc/prometheus"
  install -d -m 0755 "$PROM_DIR"

  # Backup se existir
  if [[ -f "$PROM_FILE" ]]; then
    cp -a "$PROM_FILE" "${PROM_FILE}.bak.$(date +%F-%H%M%S)"
  fi

  # Escreve template LIMPO
  cat > "$PROM_FILE" <<'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'unbound'
    static_configs:
      - targets: ['localhost:9167']

  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']
EOF

  # Validação
  if command -v promtool >/dev/null 2>&1; then
    promtool check config "$PROM_FILE" || echo "WARN: promtool apontou problemas em $PROM_FILE"
  fi

  systemctl enable --now prometheus
  systemctl restart prometheus
  ok "Prometheus ativo em :9090."
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

  # Verifica se porta 3000 está livre; mata se ocupada
  if ss -tuln | grep -q ':3000 '; then
    inf "Porta 3000 ocupada; matando processo..."
    fuser -k 3000/tcp || true
  fi

  install -d /etc/grafana/provisioning/datasources
  rm -f /etc/grafana/provisioning/datasources/sample.yaml
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

  if [[ -f "${REPO_ROOT}/grafana/provisioning/dashboards/sentinela-unbound-main.json" ]]; then
    cp -f "${REPO_ROOT}/grafana/provisioning/dashboards/sentinela-unbound-main.json" \
      /var/lib/grafana/dashboards/unbound/sentinela-unbound-main.json
  else
    cat > /var/lib/grafana/dashboards/unbound/sentinela-unbound-main.json <<'EOF'
{ "title": "Sentinela-DNS · Unbound (Main)", "schemaVersion": 36, "version": 1, "panels": [] }
EOF
  fi

  # Corrige permissões para Grafana
  chown -R grafana:grafana /etc/grafana /var/lib/grafana /var/log/grafana
  chmod -R 755 /etc/grafana /var/lib/grafana /var/log/grafana

  systemctl daemon-reload
  systemctl enable --now grafana-server
  systemctl restart grafana-server || {
    err "Falha ao iniciar Grafana. Verifique logs com journalctl -u grafana-server"
    exit 1
  }
  sleep 5
  if ! systemctl is-active --quiet grafana-server; then
    err "Grafana não subiu. Verifique systemctl status grafana-server"
    exit 1
  fi
  ok "Grafana ativo em :3000."
fi

# ===== Coletor Customizado NXDOMAIN =====
inf "Instalando e agendando o coletor de métricas NXDOMAIN..."

# Copia o script otimizado para o diretório de binários
if [[ -f "${REPO_ROOT}/scripts/top-nxdomain-optimized.sh" ]]; then
  install -m 0755 "${REPO_ROOT}/scripts/top-nxdomain-optimized.sh" /usr/local/bin/
  ok "Script top-nxdomain-optimized.sh instalado."
else
  warn "Script top-nxdomain-optimized.sh não encontrado no repositório."
fi

# Copia e ativa as unidades do systemd (service e timer)
if [[ -d "${REPO_ROOT}/systemd" ]]; then
  # Copia os arquivos de serviço e timer
  install -m 0644 "${REPO_ROOT}/systemd/top-nxdomain.service" /etc/systemd/system/
  install -m 0644 "${REPO_ROOT}/systemd/top-nxdomain.timer" /etc/systemd/system/

  # Recarrega o systemd, habilita e inicia o timer
  systemctl daemon-reload
  systemctl enable --now top-nxdomain.timer
  ok "Coletor NXDOMAIN agendado para rodar a cada 10 minutos."
else
  warn "Diretório 'systemd' não encontrado. Pulei a instalação do coletor NXDOMAIN."
fi

# ===== Health-check final =====
for s in unbound unbound_exporter prometheus grafana-server prometheus-node-exporter; do
  systemctl is-active --quiet "$s" && ok "Serviço ativo: $s" || warn "Serviço INATIVO (ok se não instalado): $s"
done

ok "Instalação/atualização concluída."
echo "Prometheus: ${PROM_URL}"
echo "Grafana: http://SEU_IP:3000 (admin/admin → altere a senha)"
echo "Exporters: node_exporter :9100 | unbound_exporter :9167"
