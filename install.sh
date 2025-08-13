#!/usr/bin/env bash
set -Eeuo pipefail

# Instalador do DogWatch para uso via GitHub (git clone) OU via one-liner (curl)
# - Se executado dentro do diretório do repositório (arquivos presentes), instala direto.
# - Se executado "solo" (via curl), clona o repo para /tmp e instala a partir de lá.

REPO_URL_DEFAULT="https://github.com/<seu-usuario>/<dogwatch>.git"
REPO_URL="${REPO_URL:-$REPO_URL_DEFAULT}"

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Este instalador deve ser executado como root (use sudo)."
    exit 1
  fi
}

main() {
  require_root
  local virt
  virt="$(systemd-detect-virt 2>/dev/null || echo unknown)"
  if [[ "$virt" != "none" ]]; then
    echo "[dogwatch] Aviso: ambiente virtual detectado ($virt); prosseguindo com a instalação..."
  fi
  apt-get update -y || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y git curl ca-certificates || true

  if [[ -f "./dogwatch.sh" && -f "./dogwatch.service" ]]; then
    echo "[dogwatch] Instalando a partir do diretório atual..."
    bash ./dogwatch.sh install
  else
    echo "[dogwatch] Executando em modo one-liner; clonando o repositório..."
    tmpdir="$(mktemp -d)"
    git clone "$REPO_URL" "$tmpdir"
    cd "$tmpdir"
    bash ./dogwatch.sh install
  fi

  install -m 0644 ./dogwatch.service /etc/systemd/system/dogwatch.service
  systemctl daemon-reload
  systemctl enable --now dogwatch.service

  /opt/dogwatch/dogwatch.sh ensure-ports >/dev/null 2>&1 || true
  systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true
  if command -v ss >/dev/null 2>&1; then
    ss -H -ltn 2>/dev/null | awk -v p=16309 '{gsub(/\[|\]/,"",$4); n=split($4,a,":"); if (a[n]==p){found=1; exit}} END {exit !found}' || \
      echo "[dogwatch] Aviso: porta 16309 não detectada como aberta" >&2
  fi
  echo "[dogwatch] Instalação concluída. Use: /opt/dogwatch/dogwatch.sh"
}

main "$@"
