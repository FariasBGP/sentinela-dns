# Sentinela-DNS

Automação completa para instalação, monitoramento e visualização de métricas do **Unbound DNS** com **Prometheus** e **Grafana**.

---

## Recursos principais

- Instalação automática de:
  - **Unbound** com métricas e hardening
  - **unbound_exporter**
  - **node_exporter**
  - **Prometheus**
  - **Grafana** (datasource Prometheus + dashboards provisionados)
- Scripts auxiliares:
  - `scripts/preflight.sh` → pré-checagem de dependências
  - `scripts/install.sh`   → instalação full auto
  - `scripts/health.sh`    → health-check de serviços, portas e endpoints
- Dashboard inicial do Grafana para Unbound (`unbound_overview.json`), já integrado por provisionamento

---

## Requisitos

- **Debian 12 (Bookworm)** ou compatível  
- Acesso root (`su -`)  
- Conexão com a internet (para baixar pacotes e plugins)

---

## Instalação rápida

Clone o repositório:

```bash
git clone https://github.com/FariasBGP/sentinela-dns.git
cd sentinela-dns
```

Execute o instalador:

```bash
make install
```

Valide se tudo está ok:

```bash
make health
```

Acesse no navegador:

- **Grafana**: http://SEU_IP:3000 (usuário: `admin`, senha inicial: `admin`)
- **Prometheus**: http://SEU_IP:9090
- **Unbound exporter**: http://SEU_IP:9167/metrics
- **Node exporter**: http://SEU_IP:9100/metrics

---

## Guia de uso do `make`

- **make preflight**  
  Executa o script de pré-checagem (dependências, versões, etc.).

- **make install**  
  Roda o instalador full-auto (`scripts/install.sh`).

- **make health**  
  Executa o health check (`scripts/health.sh`).

- **make grafana-sync**  
  Copia o dashboard do repositório para o diretório do Grafana e reinicia.

- **make prometheus-reload**  
  Reinicia o Prometheus e lista os targets ativos.

- **make status**  
  Mostra status dos serviços principais + portas em uso.

- **make logs**  
  Exibe os últimos logs de Grafana, Prometheus e unbound_exporter.

- **make fix**  
  Tenta correções básicas (restart Grafana/Prometheus + health endpoints).

- **make clean**  
  Limpa caches APT (não remove pacotes instalados).

- **make dashboard-export**  
  *(em breve)* Exporta dashboards modificados no Grafana para o repositório.

---

## Exemplos de uso

```bash
# Instalar/atualizar toda a stack
make install

# Conferir se está tudo saudável
make health

# Sincronizar dashboard atualizado do Git → Grafana
make grafana-sync

# Reiniciar Prometheus e ver se os jobs estão "up"
make prometheus-reload

# Verificar status dos serviços
make status

# Consultar logs recentes
make logs

# (em breve) Exportar dashboards do Grafana para o repositório
make dashboard-export
```

---

## Licença

Este projeto está sob a licença **MIT**. Consulte o arquivo [LICENSE].

