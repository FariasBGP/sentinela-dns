# Sentinela-DNS 🛡️

Automação para instalação e monitoramento do **Unbound DNS** com métricas no **Prometheus** e dashboards no **Grafana**.  
Um verdadeiro sentinela para a sua infraestrutura DNS.

## Recursos

- Instalação automatizada do Unbound
- Exporters para Prometheus:
  - `node_exporter`
  - `unbound_exporter`
- Configuração de métricas no Unbound
- Provisionamento opcional do Grafana com datasource Prometheus e dashboards
- Snippets prontos para Prometheus externo

## Uso rápido (como root)

```bash
apt-get update -y
apt-get install -y git
git clone https://github.com/FariasBGP/sentinela-dns.git
cd sentinela-dns
chmod +x scripts/*.sh

# Pré-check
sh scripts/preflight.sh          # apenas verifica
sh scripts/preflight.sh --fix    # tenta corrigir pendências simples

# Instalar (somente Unbound + exporters)
sh scripts/install.sh

# Com Grafana
WITH_GRAFANA=yes sh scripts/install.sh

# Com Prometheus local
WITH_PROM_LOCAL=yes sh scripts/install.sh
