# Makefile — Sentinela-DNS
# Use: make install | make health | make grafana-sync | make status | ...

SHELL := /bin/bash

# Raiz do repo e caminhos
REPO_ROOT := $(shell pwd)
SCRIPTS    := $(REPO_ROOT)/scripts

# >>> Grafana (provisioning)
DASH_SRC_DIR    := $(REPO_ROOT)/grafana/provisioning/dashboards
GRAFANA_PROV_DIR:= /etc/grafana/provisioning/dashboards
# (nomes padrão que vamos procurar, mas o alvo copia QUALQUER .json/.yaml no diretório)
DASH_JSON       := $(DASH_SRC_DIR)/sentinela-unbound-main.json
DASH_YAML       := $(DASH_SRC_DIR)/sentinela-unbound.yaml

.PHONY: preflight install health grafana-sync prometheus-reload status logs fix clean

preflight:
	@echo ">> Pré-check..."
	@chmod +x $(SCRIPTS)/preflight.sh || true
	@$(SCRIPTS)/preflight.sh

install:
	@echo ">> Instalando/atualizando Sentinela-DNS..."
	@chmod +x $(SCRIPTS)/install.sh || true
	@$(SCRIPTS)/install.sh

health:
	@echo ">> Checando saúde dos serviços..."
	@chmod +x $(SCRIPTS)/health.sh || true
	@$(SCRIPTS)/health.sh

grafana-sync:
	@echo ">> Sincronizando dashboards (provisioning) para o Grafana..."
	@if [ ! -d "$(DASH_SRC_DIR)" ]; then \
	  echo "ERRO: diretório de origem não existe: $(DASH_SRC_DIR)"; exit 1; \
	fi
	@mkdir -p "$(GRAFANA_PROV_DIR)"
	# Copia todos .json e .yaml (se existirem)
	@if ls "$(DASH_SRC_DIR)"/*.json >/dev/null 2>&1 || ls "$(DASH_SRC_DIR)"/*.yaml >/dev/null 2>&1; then \
	  cp -f $(DASH_SRC_DIR)/*.json "$(GRAFANA_PROV_DIR)" 2>/dev/null || true; \
	  cp -f $(DASH_SRC_DIR)/*.yaml "$(GRAFANA_PROV_DIR)" 2>/dev/null || true; \
	  chown -R grafana:grafana "$(GRAFANA_PROV_DIR)" || true; \
	  chmod 0644 "$(GRAFANA_PROV_DIR)"/* || true; \
	  systemctl restart grafana-server; \
	  echo "OK: arquivos copiados para $(GRAFANA_PROV_DIR) e grafana-server reiniciado."; \
	  echo "Dica: Grafana → Dashboards → Browse (pasta 'DNS/Unbound')."; \
	else \
	  echo "AVISO: não encontrei .json/.yaml em $(DASH_SRC_DIR)"; \
	fi

prometheus-reload:
	@echo ">> Reiniciando Prometheus..."
	@systemctl restart prometheus
	@sleep 3
	@curl -fsS "http://127.0.0.1:9090/api/v1/targets" \
	  | jq -r '.data.activeTargets[] | "\(.labels.job) -> \(.health) \(.discoveredLabels.__address__)"' | sort || true

status:
	@echo ">> Status dos serviços..."
	@systemctl --no-pager --full status unbound unbound_exporter prometheus grafana-server prometheus-node-exporter || true
	@echo ">> Portas ouvindo..."
	@ss -tuln | grep -E ':(53|9100|9167|9090|3000)\b' || true

logs:
	@echo ">> Logs recentes (grafana/prometheus/unbound_exporter)..."
	@journalctl -u grafana-server -n 120 --no-pager || true
	@journalctl -u prometheus -n 120 --no-pager || true
	@journalctl -u unbound_exporter -n 120 --no-pager || true

fix:
	@echo ">> Tentando correções básicas (Grafana/Prometheus)..."
	@systemctl enable grafana-server prometheus || true
	@systemctl restart grafana-server prometheus || true
	@sleep 3
	@echo ">> Health endpoints:"
	@for u in http://127.0.0.1:9100/metrics http://127.0.0.1:9167/metrics http://127.0.0.1:9090/-/ready http://127.0.0.1:3000/api/health; do \
	  printf "%s -> " $$u; curl -fsS --max-time 5 $$u >/dev/null && echo OK || echo FAIL; \
	done

clean:
	@echo ">> Limpando caches APT (não remove pacotes instalados)..."
	@apt-get clean
	@echo ">> Feito."
