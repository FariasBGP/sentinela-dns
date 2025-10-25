#!/usr/bin/env python3
#
# Sentinela-DNS — Agente (Fase 1)
#
# Este serviço corre em background, contacta a API central
# para obter a lista de bloqueios e aplica-a no Unbound.
#

import requests
import json
import os
import sys
import subprocess
import time
import configparser
from contextlib import contextmanager

# --- Constantes ---
CONFIG_FILE = "/etc/sentinela/agent.conf"
BLOCK_FILE = "/etc/unbound/unbound.conf.d/92-sentinela-blocklist.conf"
# Ficheiro para guardar o "estado" da última lista de bloqueio
STATE_FILE = "/var/lib/sentinela/last_state.json"
POLL_INTERVAL = 60  # Segundos entre cada verificação

@contextmanager
def Mbox(msg):
    """Helper visual para logs"""
    print("=" * (len(msg) + 4))
    print(f"[ {msg} ]")
    print("=" * (len(msg) + 4))
    yield
    print("-" * (len(msg) + 4))

def read_config():
    """Lê o ficheiro de configuração .conf"""
    try:
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)
        api_url = config['api']['url']
        api_key = config['api']['key']
        return api_url, api_key
    except Exception as e:
        print(f"ERRO: Não foi possível ler o ficheiro de configuração {CONFIG_FILE}: {e}")
        return None, None

def fetch_remote_config(url, api_key):
    """Contacta a API central para obter a nova configuração."""
    try:
        headers = {'Authorization': f'Bearer {api_key}'}
        # Timeout de 10 segundos
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Lança um erro se o status for 4xx ou 5xx
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"ERRO: Falha ao contactar a API em {url}: {e}")
        return None

def get_current_state():
    """Lê o último estado guardado em disco."""
    try:
        if not os.path.exists(STATE_FILE):
            return None
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"AVISO: Não foi possível ler o ficheiro de estado: {e}")
        return None

def write_new_state(config_data):
    """Guarda o novo estado em disco."""
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, 'w') as f:
            json.dump(config_data, f)
    except Exception as e:
        print(f"ERRO: Falha ao escrever o ficheiro de estado: {e}")

def write_unbound_config(config_data):
    """Escreve o ficheiro de configuração do Unbound."""
    blocklist = config_data.get('blocklist', [])
    redirect_ip_v4 = config_data.get('settings', {}).get('redirect_ip_v4', '127.0.0.1')
    redirect_ip_v6 = config_data.get('settings', {}).get('redirect_ip_v6', '::1')

    try:
        with open(BLOCK_FILE, 'w') as f:
            f.write("# ARQUIVO GERADO AUTOMATICAMENTE PELO AGENTE SENTINELA-DNS\n")
            f.write("# NÃO EDITE ESTE FICHEIRO MANUALMENTE\n")
            f.write("server:\n")

            if not blocklist:
                f.write("  # Nenhuma regra de bloqueio ativa.\n")

            for domain in blocklist:
                domain = domain.strip()
                if domain:
                    f.write(f"  # Bloqueando {domain}\n")
                    f.write(f"  local-zone: \"{domain}\" redirect\n")
                    f.write(f"  local-data: \"{domain} A {redirect_ip_v4}\"\n")
                    f.write(f"  local-data: \"{domain} AAAA {redirect_ip_v6}\"\n\n")
        return True
    except Exception as e:
        print(f"ERRO: Falha ao escrever o ficheiro {BLOCK_FILE}: {e}")
        return False

def reload_unbound():
    """Valida e aplica a nova configuração do Unbound."""
    try:
        # 1. Validar
        cp = subprocess.run(['unbound-checkconf'], capture_output=True, text=True)
        if cp.returncode != 0:
            print(f"ERRO: unbound-checkconf falhou! Saída:\n{cp.stderr}")
            return False

        # 2. Recarregar
        cp = subprocess.run(['unbound-control', 'reload'], capture_output=True, text=True)
        if cp.returncode != 0:
            print(f"ERRO: unbound-control reload falhou! Saída:\n{cp.stderr}")
            return False

        print("Configuração do Unbound recarregada com sucesso.")
        return True
    except Exception as e:
        print(f"ERRO: Exceção ao executar o unbound-control: {e}")
        return False

def main_loop():
    """Loop principal do agente."""
    with Mbox("Serviço Agente Sentinela-DNS Iniciado"):
        print(f"A monitorizar {CONFIG_FILE} e {BLOCK_FILE}")
        print(f"Intervalo de verificação: {POLL_INTERVAL} segundos")

    while True:
        try:
            api_url, api_key = read_config()
            if not api_url:
                time.sleep(POLL_INTERVAL)
                continue

            print(f"A verificar {api_url} por novas configurações...")
            remote_config = fetch_remote_config(api_url, api_key)

            if not remote_config:
                print("Falha ao obter configuração remota. A tentar novamente mais tarde.")
                time.sleep(POLL_INTERVAL)
                continue

            current_state = get_current_state()

            if current_state == remote_config:
                print("Nenhuma alteração detetada. A dormir.")
            else:
                with Mbox("Alteração de configuração detetada!"):
                    print(f"Configuração antiga: {current_state}")
                    print(f"Configuração nova: {remote_config}")
                    print("A aplicar nova configuração...")

                    if write_unbound_config(remote_config):
                        if reload_unbound():
                            print("Sucesso! A guardar novo estado.")
                            write_new_state(remote_config)
                        else:
                            print("ERRO: Falha ao recarregar o Unbound. O estado não será atualizado.")
                    else:
                        print("ERRO: Falha ao escrever o ficheiro de configuração.")

        except Exception as e:
            print(f"ERRO INESPERADO no loop principal: {e}")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        print("\nAgente Sentinela-DNS terminado pelo utilizador.")
        sys.exit(0)
