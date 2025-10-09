#!/bin/bash
# Sentinela-DNS — optimize.sh
# Otimiza Unbound baseado em hardware (CPU, mem, disco) para max cache.

set -euo pipefail

CONF_FILE="/etc/unbound/unbound.conf.d/61-configs.conf"
SYSCTL_FILE="/etc/sysctl.d/99-sentinela.conf"
BACKUP_CONF="${CONF_FILE}.bak.$(date +%F-%H%M%S)"

# Função para próxima potência de 2
next_power_of_2() {
  local n=$1
  local p=1
  while [ $p -lt $n ]; do
    p=$((p * 2))
  done
  echo $p
}

# Coleta hardware
CPU_CORES=$(nproc --all)
MEM_TOTAL_MB=$(free -m | grep Mem | awk '{print $2}')
DISK_AVAIL_GB=$(df -BG /var/lib/unbound | tail -1 | awk '{print $4}' | sed 's/G//')

echo ">> Hardware detectado:"
echo "  CPU Cores: $CPU_CORES"
echo "  Memória Total: ${MEM_TOTAL_MB}MB"
echo "  Disco Disponível em /var/lib/unbound: ${DISK_AVAIL_GB}GB"

# Calcula valores otimizados (conservadores, potências de 2)
THREADS=$((CPU_CORES > 32 ? 32 : CPU_CORES))  # Max 32 threads
SLABS=$(next_power_of_2 $((THREADS * 2)))  # Próxima potência de 2 >= 2x threads
QUERIES_PER_THREAD=4096  # Fixo alto
MSG_CACHE_MB=$((MEM_TOTAL_MB / 10))  # ~10% mem
RRSET_CACHE_MB=$((MEM_TOTAL_MB / 5))  # 2x msg, ~20% mem
NEG_CACHE_MB=$((MEM_TOTAL_MB / 20))  # Pequeno
RATELIMIT=$((THREADS * 1000))  # 1k por thread

# Ajustes se mem baixa
if [ $MEM_TOTAL_MB -lt 2048 ]; then
  MSG_CACHE_MB=128
  RRSET_CACHE_MB=256
  NEG_CACHE_MB=4
  SLABS=8
fi

# Verifica disco (avisa se baixo)
if [ $DISK_AVAIL_GB -lt 10 ]; then
  echo "AVISO: Disco baixo (${DISK_AVAIL_GB}GB) – libere espaço para logs/zonefiles."
fi

# Backup conf original
cp -a "$CONF_FILE" "$BACKUP_CONF" 2>/dev/null || true
echo ">> Backup do conf em $BACKUP_CONF."

# Atualiza conf Unbound
cat > $CONF_FILE <<EOF
server:
  outgoing-range: 8192
  outgoing-port-avoid: 0-1024
  outgoing-port-permit: 1025-65535

  num-threads: $THREADS
  num-queries-per-thread: $QUERIES_PER_THREAD

  msg-cache-size: ${MSG_CACHE_MB}m
  msg-cache-slabs: $SLABS
  rrset-cache-size: ${RRSET_CACHE_MB}m
  rrset-cache-slabs: $SLABS

  infra-host-ttl: 60
  infra-lame-ttl: 120
  infra-cache-numhosts: 10000
  infra-cache-lame-size: 10k
  infra-cache-slabs: $SLABS
  key-cache-slabs: $SLABS
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
  neg-cache-size: ${NEG_CACHE_MB}M
  qname-minimisation: yes
  deny-any: yes
  ratelimit: $RATELIMIT
  unwanted-reply-threshold: 10000
  use-caps-for-id: yes
  val-clean-additional: yes
  minimal-responses: yes
  prefetch: yes
  prefetch-key: yes
  serve-expired: yes
  so-reuseport: yes
EOF

echo ">> Unbound conf otimizado em $CONF_FILE."

# Valida conf antes de prosseguir
if ! unbound-checkconf >/dev/null 2>&1; then
  echo "ERRO: Configuração inválida! Restaurando backup..."
  cp -a "$BACKUP_CONF" "$CONF_FILE"
  unbound-checkconf
  exit 1
fi
echo ">> Configuração validada."

# Ajustes kernel persistentes
cat > $SYSCTL_FILE <<EOF
vm.overcommit_memory=1
vm.overcommit_ratio=80
fs.file-max=2097152
net.core.somaxconn=8192
net.ipv4.tcp_max_syn_backlog=8192
net.core.netdev_max_backlog=8192
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=30
EOF

sysctl --load=$SYSCTL_FILE
echo ">> Kernel otimizado via sysctl em $SYSCTL_FILE."

# Restart e valida
systemctl restart unbound
sleep 2
if unbound-checkconf && systemctl is-active unbound; then
  echo ">> Otimização aplicada com sucesso. Monitore com make status/logs."
else
  echo "ERRO: Falha na validação. Verifique journalctl -u unbound."
  exit 1
fi
