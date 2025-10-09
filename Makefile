# Makefile — Sentinela-DNS (Debian 12/13)
SHELL := /bin/bash
REPO_ROOT := $(shell pwd)
SCRIPTS   := $(REPO_ROOT)/scripts

.PHONY: preflight install health grafana-sync status logs fix clean test prometheus-reset optimize

preflight:
	@echo ">> Pré-check..."
	@chmod +x $(SCRIPTS)/preflight.sh || true
	@$(SCRIPTS)/preflight.sh

install:
	@echo ">> Instalando/atualizando Sentinela-DNS..."
	@chmod +x $(SCRIPTS)/install.sh || true
	@$(SCRIPTS)/install.sh

health:
	@echo ">> Checando saúde dos serviços (incluindo Unbound)..."
	@chmod +x $(SCRIPTS)/health.sh || true
	@$(SCRIPTS)/health.sh

grafana-sync:
	@echo ">> Sincronizando dashboards para o Grafana..."
	@if [ ! -d "$(REPO_ROOT)/grafana/provisioning/dashboards" ]; then \
	  echo "ERRO: dashboards não encontrados."; exit 1; \
	fi
	@install -d /etc/grafana/provisioning/dashboards /var/lib/grafana/dashboards/unbound
	# Copia somente .yaml para provisioning
	@find $(REPO_ROOT)/grafana/provisioning/dashboards -maxdepth 1 -type f -name '*.yaml' -print0 | xargs -0 -I{} cp -f {} /etc/grafana/provisioning/dashboards/ 2>/dev/null || true
	# Copia somente .json para a pasta de dashboards
	@find $(REPO_ROOT)/grafana/provisioning/dashboards -maxdepth 1 -type f -name '*.json' -print0 | xargs -0 -I{} cp -f {} /var/lib/grafana/dashboards/unbound/ 2>/dev/null || true
	@chown -R grafana:grafana /var/lib/grafana/dashboards || true
	@chmod 0644 /etc/grafana/provisioning/dashboards/* 2>/dev/null || true
	@chmod 0644 /var/lib/grafana/dashboards/unbound/* 2>/dev/null || true
	@systemctl restart grafana-server || true
	@echo "Grafana: dashboards sincronizados."

status:
	@echo ">> Status dos serviços..."
	@systemctl --no-pager --full status unbound unbound_exporter prometheus grafana-server prometheus-node-exporter || true
	@echo ">> Portas ouvindo..."
	@ss -tuln | grep -E ':(53|8953|9090|9167|3000)\b' || true

logs:
	@echo ">> Logs recentes (unbound/prometheus/exporters/grafana)..."
	@journalctl -u unbound -n 120 --no-pager || true
	@journalctl -u prometheus -n 120 --no-pager || true
	@journalctl -u unbound_exporter -n 120 --no-pager || true
	@journalctl -u grafana-server -n 120 --no-pager || true

fix:
	@echo ">> Tentando correções básicas..."
	@systemctl enable grafana-server prometheus unbound_exporter || true
	@systemctl restart grafana-server prometheus unbound_exporter || true
	@sleep 3
	@echo ">> Endpoints de saúde:"
	@for u in \
	  http://127.0.0.1:9100/metrics \
	  http://127.0.0.1:9167/metrics \
	  http://127.0.0.1:9090/-/ready \
	  http://127.0.0.1:3000/api/health ; do \
	    printf "%s -> " $$u; \
	    curl -fsS --max-time 5 $$u >/dev/null && echo OK || echo FAIL; \
	  done

clean:
	@echo ">> Limpando caches..."
	@apt-get clean || true
	@echo "Feito."

test: preflight install health status logs
	@echo ">> Testes completos finalizados."

prometheus-reset:
	@echo ">> Resetando prometheus.yml para template padrão..."
	@cp -a /etc/prometheus/prometheus.yml /etc/prometheus/prometheus.yml.bak.$$(date +%F-%H%M%S) 2>/dev/null || true
	@cat > /etc/prometheus/prometheus.yml <<-'YAML'
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
	YAML
	@which promtool >/dev/null 2>&1 && promtool check config /etc/prometheus/prometheus.yml || true
	@systemctl restart prometheus
	@systemctl --no-pager --full status prometheus || true

optimize:
	@echo ">> Otimizando Unbound com base em hardware..."
	@chmod +x $(SCRIPTS)/optimize.sh || true
	@$(SCRIPTS)/optimize.sh
