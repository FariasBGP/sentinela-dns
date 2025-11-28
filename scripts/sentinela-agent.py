#!/usr/bin/env python3
#
# Sentinela-DNS — Agente v3.2 (Híbrido + Fix Nomes de Zona)
#
import requests
import json
import os
import sys
import subprocess
import time
import configparser
from contextlib import contextmanager

# --- Configuração Dinâmica ---
# Permite passar o ficheiro de configuração como argumento (para modo Híbrido)
if len(sys.argv) > 1:
    CONFIG_FILE = sys.argv[1]
    # Cria um ficheiro de estado único para esta instância
    STATE_FILE = f"/var/lib/sentinela/state_{os.path.basename(CONFIG_FILE)}.json"
else:
    CONFIG_FILE = "/etc/sentinela/agent.conf"
    STATE_FILE = "/var/lib/sentinela/last_state.json"

POLL_INTERVAL = 60

# Caminhos Unbound
UNBOUND_BLOCK_FILE = "/etc/unbound/unbound.conf.d/92-sentinela-blocklist.conf"
UNBOUND_IFACE_FILE = "/etc/unbound/unbound.conf.d/63-listen-interfaces.conf"

# Caminhos NSD
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
    for url in url_list:
        try:
            print(f"  A baixar lista externa: {url}")
            r = requests.get(url, timeout=15); r.raise_for_status()
            return set(line.strip() for line in r.text.splitlines() if line.strip())
        except Exception as e:
            print(f"  AVISO: Falha em {url}: {e}")
    return None

# --- LÓGICA RECURSIVA (UNBOUND) ---
def apply_recursive(config):
    print(">>> Modo: RECURSIVO (Unbound)")
    
    bind_ips = config['settings'].get('bind_ip', '0.0.0.0').split()
    try:
        with open(UNBOUND_IFACE_FILE, 'w') as f:
            f.write("server:\n")
            for ip in bind_ips:
                f.write(f"  interface: {ip}\n")
            f.write("  port: 53\n  do-udp: yes\n  do-tcp: yes\n")
    except Exception as e: print(f"Erro interfaces: {e}")

    priv_list = set(config.get('blocklist_private', []))
    ext_urls = config.get('blocklist_external_urls', [])
    ext_list = set()
    
    if ext_urls:
        cached = get_current_state().get('cached_ext_list', []) if get_current_state() else []
        res = fetch_external_blocklist(ext_urls)
        ext_list = res if res is not None else set(cached)
        if res is not None: config['cached_ext_list'] = list(ext_list)

    final_list = list(priv_list | ext_list)
    redirect_v4 = config['settings'].get('redirect_ip_v4', '127.0.0.1')
    redirect_v6 = config['settings'].get('redirect_ip_v6', '::1')

    try:
        with open(UNBOUND_BLOCK_FILE, 'w') as f:
            f.write("# SENTINELA-DNS BLOCKLIST\nserver:\n")
            for d in sorted(final_list):
                d = d.strip().replace("http://", "").replace("https://", "").split("/")[0]
                if d:
                    f.write(f"  local-zone: \"{d}\" redirect\n")
                    f.write(f"  local-data: \"{d} A {redirect_v4}\"\n")
                    f.write(f"  local-data: \"{d} AAAA {redirect_v6}\"\n")
    except Exception as e: print(f"Erro blocklist: {e}")

    if subprocess.run(['unbound-checkconf'], capture_output=True).returncode == 0:
        subprocess.run(['systemctl', 'restart', 'unbound'])
        print("Unbound recarregado.")

# --- LÓGICA AUTORITATIVA (NSD) ---
def apply_authoritative(config):
    print(">>> Modo: AUTORITATIVO (NSD)")
    
    os.makedirs(NSD_ZONES_DIR, exist_ok=True)
    
    bind_ips = config['settings'].get('bind_ip', '0.0.0.0').split()
    zonas = config.get('zonas', [])
    
    try:
        with open(NSD_MAIN_CONF, 'w') as f:
            f.write("server:\n")
            for ip in bind_ips:
                f.write(f"  ip-address: {ip}\n")
            f.write("  port: 53\n  username: nsd\n  zonesdir: \"/etc/nsd/zones\"\n\n")
            f.write("remote-control:\n  control-enable: yes\n  control-interface: 127.0.0.1\n\n")
            
            for z in zonas:
                # CORREÇÃO: Sanitização do nome do arquivo da zona
                # 1. Remove ponto final (evita ..zone)
                # 2. Troca / por _ (evita erro de diretório em CIDR como 192.168.0.0/24)
                safe_filename = z['nome'].strip('.').replace('/', '_') + ".zone"
                f.write(f"zone:\n  name: \"{z['nome']}\"\n  zonefile: \"{safe_filename}\"\n")
    except Exception as e: print(f"Erro escrita nsd.conf: {e}")

    for z in zonas:
        # Aplica a mesma sanitização aqui para criar o arquivo
        safe_filename = z['nome'].strip('.').replace('/', '_') + ".zone"
        zfile = os.path.join(NSD_ZONES_DIR, safe_filename)
        try:
            with open(zfile, 'w') as f:
                f.write(f"$ORIGIN {z['nome']}.\n$TTL {z['ttl']}\n")
                f.write(f"@ IN SOA ns1.{z['nome']}. {z['email'].replace('@', '.')} (\n")
                f.write(f" {z['serial']} 3600 1800 604800 86400 )\n")
                f.write(f"  IN NS ns1.{z['nome']}.\n  IN NS ns2.{z['nome']}.\n\n")
                
                for reg in z['registros']:
                    h = reg['host']
                    if h == '@': h = ''
                    v = reg['valor']
                    if reg['tipo'] in ['CNAME', 'NS', 'PTR'] and not v.endswith('.'): v += '.'
                    f.write(f"{h}\tIN\t{reg['tipo']}\t{v}\n")
        except Exception as e: print(f"Erro escrita zona {z['nome']}: {e}")

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
    base_name = os.path.basename(CONFIG_FILE)
    with Mbox(f"Sentinela-Agente Iniciado ({base_name})"): pass
    while True:
        try:
            api_url, api_key = read_config()
            if not api_url: time.sleep(POLL_INTERVAL); continue
            
            print("Verificando API...")
            remote = fetch_remote_config(api_url, api_key)
            
            if remote:
                current = get_current_state()
                r_clean = remote.copy()
                if 'cached_ext_list' in r_clean: del r_clean['cached_ext_list']
                c_clean = current.copy() if current else {}
                if 'cached_ext_list' in c_clean: del c_clean['cached_ext_list']

                if c_clean == r_clean:
                    print("Sem alterações.")
                else:
                    mode = remote.get('mode')
                    if mode == 'recursive':
                        # Não desligamos o NSD aqui para permitir operação híbrida
                        subprocess.run(['systemctl', 'start', 'unbound'], capture_output=True)
                        apply_recursive(remote)
                    elif mode == 'authoritative':
                        # Não desligamos o Unbound aqui para permitir operação híbrida
                        apply_authoritative(remote)
                    
                    write_new_state(remote)
        except Exception as e: print(f"Erro loop: {e}")
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    try: main_loop()
    except KeyboardInterrupt: sys.exit(0)
