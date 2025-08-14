#!/usr/bin/env bash
set -Eeuo pipefail

# Instalador do DogWatch (repo local ou one-liner)
# - Se arquivos estiverem no diretório atual, instala a partir dele.
# - Caso contrário, clona REPO_URL (branch BRANCH) em /tmp e instala.

REPO_URL_DEFAULT="https://github.com/<seu-usuario>/<dogwatch>.git"
REPO_URL="${REPO_URL:-$REPO_URL_DEFAULT}"
BRANCH="${BRANCH:-main}"

export DEBIAN_FRONTEND=noninteractive

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Este instalador deve ser executado como root (use sudo)."
    exit 1
  fi
}

have_file() { [[ -f "$1" ]]; }

install_prereqs() {
  apt-get update -y || true
  apt-get install -y --no-install-recommends git curl ca-certificates || true
}

run_core_install() {
  bash ./dogwatch.sh install
}

enable_service_if_needed() {
  # Se o serviço já foi instalado e habilitado pelo dogwatch.sh, não repita.
  if systemctl list-unit-files | grep -q '^dogwatch\.service'; then
    systemctl daemon-reload || true
    systemctl enable --now dogwatch.service || true
  fi
}

post_checks() {
  # Abre portas (idempotente) e checa SSH
  /opt/dogwatch/dogwatch.sh ensure-ports >/dev/null 2>&1 || true
  systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true

  # Verificação final de conectividade na porta padrão (16309 por default)
  local port="${PRIMARY_SSH_PORT:-16309}"
  if command -v nc >/dev/null 2>&1; then
    if ! nc -w2 -z 127.0.0.1 "$port" >/dev/null 2>&1 && ! nc -w2 -z ::1 "$port" >/dev/null 2>&1; then
      echo "[dogwatch] Aviso: porta $port não detectada como aberta localmente" >&2
    fi
  fi

  # Relatório final do próprio DogWatch
  /opt/dogwatch/dogwatch.sh status || true
}

main() {
  require_root

  local virt
  virt="$(systemd-detect-virt 2>/dev/null || echo unknown)"
  if [[ "$virt" != "none" ]]; then
    echo "[dogwatch] Aviso: ambiente virtual detectado ($virt); prosseguindo com a instalação..."
  fi

  install_prereqs

  if have_file "./dogwatch.sh" && have_file "./dogwatch.service"; then
    echo "[dogwatch] Instalando a partir do diretório atual..."
    run_core_install
  else
    echo "[dogwatch] One-liner: clonando o repositório ($REPO_URL @ $BRANCH)..."
    tmpdir="$(mktemp -d)"
    git clone --branch "$BRANCH" --depth 1 "$REPO_URL" "$tmpdir"
    cd "$tmpdir"
    run_core_install
  fi

  # dogwatch.sh install já copia o .service e habilita; apenas garanta o enable/daemon-reload
  enable_service_if_needed

  post_checks

  echo "[dogwatch] Instalação concluída. Binário: /opt/dogwatch/dogwatch.sh"
}

main "$@"
