#!/usr/bin/env bash
#
# Sentinela-DNS — manage-blocklist.sh (Prova de Conceito - Fase 0)
#
# Este script gera um ficheiro de configuração modular para o Unbound
# com uma lista de domínios a bloquear e, em seguida, aplica as
# alterações "a quente" usando unbound-control reload.
#

set -euo pipefail

# --- CONFIGURAÇÃO ---

# O ficheiro onde as regras de bloqueio serão escritas.
# O prefixo 92- garante que ele seja carregado após as configs principais.
BLOCK_FILE="/etc/unbound/unbound.conf.d/92-sentinela-blocklist.conf"

# O IP para onde os domínios bloqueados serão redirecionados.
# 127.0.0.1 (loopback) é uma escolha segura e comum.
REDIRECT_IP_V4="127.0.0.1"
REDIRECT_IP_V6="::1"

# A lista de domínios para bloquear (para este teste).
# Use um array bash para facilitar.
DOMAINS_TO_BLOCK=(
  "exemplo-de-bloqueio-1.com"
  "site-malicioso-teste.net"
  "alan.com" # Apenas para um teste fácil de validar
)

# --- FIM DA CONFIGURAÇÃO ---

main() {
  # Este script precisa de privilégios de root
  if [[ $EUID -ne 0 ]]; then
    echo "ERRO: Este script precisa ser executado como root (ex: sudo ./scripts/manage-blocklist.sh)" 1>&2
    exit 1
  fi

  echo "A gerar novo ficheiro de bloqueio em $BLOCK_FILE..."

  # Passo 1: Limpa o ficheiro antigo e escreve o cabeçalho (>)
  echo "# ARQUIVO GERADO AUTOMATICAMENTE PELO PAINEL SENTINELA-DNS" > "$BLOCK_FILE"
  echo "# NÃO EDITE ESTE FICHEIRO MANUALMENTE" >> "$BLOCK_FILE"
  echo "server:" >> "$BLOCK_FILE"

  # Passo 2: Adiciona as regras de bloqueio para cada domínio (>>)
  for domain in "${DOMAINS_TO_BLOCK[@]}"; do
    echo "  # Bloqueando $domain" >> "$BLOCK_FILE"
    echo "  local-zone: \"$domain\" redirect" >> "$BLOCK_FILE"
    echo "  local-data: \"$domain A $REDIRECT_IP_V4\"" >> "$BLOCK_FILE"
    echo "  local-data: \"$domain AAAA $REDIRECT_IP_V6\"" >> "$BLOCK_FILE"
    echo "" >> "$BLOCK_FILE"
  done

  echo "Ficheiro de configuração gerado."

  # Passo 3: Validar a nova configuração
  echo "A validar a configuração do Unbound..."
  if ! unbound-checkconf; then
    echo "ERRO: A configuração gerada é inválida!" 1>&2
    echo "A reverter para um ficheiro vazio para evitar falhas." 1>&2
    # Medida de segurança: cria um ficheiro vazio para não quebrar o Unbound
    echo "server:" > "$BLOCK_FILE"
    exit 1
  fi

  # Passo 4: Aplicar as alterações "a quente"
  echo "Configuração válida. A aplicar com 'unbound-control reload'..."
  if unbound-control reload; then
    echo "Sucesso! As novas regras de bloqueio estão ativas."
  else
    echo "ERRO: Falha ao executar 'unbound-control reload'." 1>&2
    echo "Verifique se o Unbound está a correr e se o remote-control está configurado." 1>&2
    exit 1
  fi
}

# Executa a função principal
main
