# Makefile — Sentinela-DNS
# Use: make install | make health | make grafana-sync | make status | ...

SHELL := /bin/bash
REPO_ROOT := $(shell pwd)
SCRIPTS := $(REPO_ROOT)/scripts
DASH_SRC := $(REPO_ROOT)/grafana/provisioning/dashboards/unbound_overview.json
DASH_DST_DIR := /var/lib/grafana/dashboards/unbound
DASH_DST := $(DASH_DST_DIR)/unbound_overview.json

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
	@echo ">> Sincronizando dashboard para Grafana..."
	@mkdir -p $(DASH_DST_DIR)
	@if [ -f "$(DASH_SRC)" ]; then \
	  cp -f "$(DASH_SRC)" "$(DASH_DST)"; \
	  systemctl restart grafana-server; \
	  echo "OK: copiado $(DASH_SRC) -> $(DASH_DST) e reiniciado grafana-server"; \
	else \
	  echo "AVISO: dashboard não encontrado em $(DASH_SRC)"; \
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
