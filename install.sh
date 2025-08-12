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
  echo "[dogwatch] Instalação concluída. Use: /opt/dogwatch/dogwatch.sh --menu"
}

main "$@"
