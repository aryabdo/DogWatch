#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL_DEFAULT="https://github.com/<seu-usuario>/<dogwatch>.git"
REPO_URL="${REPO_URL:-$REPO_URL_DEFAULT}"

say() { echo "[dogwatch] $*"; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Este instalador deve ser executado como root (use sudo)."
    exit 1
  fi
}

# --- UFW helpers ---
ufw_disable_safely() {
  if have_cmd ufw; then
    say "Desativando UFW temporariamente..."
    LC_ALL=C LANG=C ufw --force disable >/dev/null 2>&1 || true
  fi
}

read_ports_from_env() {
  local env_file="/etc/dogwatch/config.env"
  PRIMARY_SSH_PORT="16309"
  EMERGENCY_SSH_PORT="22"
  if [[ -f "$env_file" ]]; then
    # shellcheck disable=SC1090
    source "$env_file"
    PRIMARY_SSH_PORT="${PRIMARY_SSH_PORT:-16309}"
    EMERGENCY_SSH_PORT="${EMERGENCY_SSH_PORT:-22}"
  fi
  export PRIMARY_SSH_PORT EMERGENCY_SSH_PORT
}

ufw_enable_with_ports() {
  read_ports_from_env

  # garante pacote
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ufw >/dev/null 2>&1 || true
  hash -r

  if have_cmd ufw; then
    say "Reativando UFW e garantindo portas essenciais..."

    # força backend nftables e desliga logging
    mkdir -p /etc/ufw
    if [[ -f /etc/ufw/ufw.conf ]]; then
      grep -q '^BACKEND=' /etc/ufw/ufw.conf \
        && sed -i 's/^BACKEND=.*/BACKEND=nftables/' /etc/ufw/ufw.conf \
        || echo 'BACKEND=nftables' >> /etc/ufw/ufw.conf
      grep -q '^LOGLEVEL=' /etc/ufw/ufw.conf \
        && sed -i 's/^LOGLEVEL=.*/LOGLEVEL=off/' /etc/ufw/ufw.conf \
        || echo 'LOGLEVEL=off' >> /etc/ufw/ufw.conf
    else
      printf '%s\n' 'ENABLED=no' 'LOGLEVEL=off' 'BACKEND=nftables' > /etc/ufw/ufw.conf || true
    fi
    # (opcional) evita ruído do logging IPv6 em alguns ambientes
    if [[ -f /etc/default/ufw ]]; then
      sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw || true
    fi

    # zera regras e define políticas
    LC_ALL=C LANG=C ufw --force reset >/dev/null 2>&1 || true
    LC_ALL=C LANG=C ufw logging off >/dev/null 2>&1 || true
    LC_ALL=C LANG=C ufw default deny incoming >/dev/null 2>&1 || true
    LC_ALL=C LANG=C ufw default allow outgoing >/dev/null 2>&1 || true

    # abre portas
    LC_ALL=C LANG=C ufw allow "${PRIMARY_SSH_PORT}/tcp" >/dev/null 2>&1 || true
    LC_ALL=C LANG=C ufw allow "${EMERGENCY_SSH_PORT}/tcp" >/dev/null 2>&1 || true

    # habilita; suprime apenas o ruído de logging
    LC_ALL=C LANG=C ufw --force enable >/dev/null 2>&1 || true

    # checagem de sanidade
    if ! systemctl is-active --quiet ufw 2>/dev/null; then
      say "Aviso: UFW não ficou ativo; tentando habilitar novamente."
      LC_ALL=C LANG=C ufw --force enable >/dev/null 2>&1 || true
    fi
    LC_ALL=C LANG=C ufw status verbose || true
  else
    say "Aviso: UFW não está disponível; prosseguindo sem UFW."
  fi
}

check_listen_port() {
  local port="$1"
  if have_cmd ss; then
    if ss -ltnH 2>/dev/null | awk -v p="$port" '
      $1=="LISTEN" {
        gsub(/[\[\]]/,"",$4);
        n=split($4,a,":");
        if (a[n]==p){found=1; exit}
      }
      END{exit !found}'; then
      say "Porta ${port} detectada como ABERTA."
    else
      say "Aviso: porta ${port} não foi detectada como aberta." >&2
    fi
  fi
}

install_from_here_or_clone() {
  if [[ -f "./dogwatch.sh" && -f "./dogwatch.service" ]]; then
    say "Instalando a partir do diretório atual..."
    bash ./dogwatch.sh install
  else
    say "Executando em modo one-liner; clonando o repositório..."
    local tmpdir
    tmpdir="$(mktemp -d)"
    git clone "$REPO_URL" "$tmpdir"
    cd "$tmpdir"
    bash ./dogwatch.sh install
  fi
}

main() {
  require_root

  # pré-requisitos básicos
  apt-get update -y || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y git curl ca-certificates || true

  # desativa UFW no começo
  ufw_disable_safely

  # instala DogWatch (do diretório ou do repo)
  say "Instalando a partir do diretório atual..."
  say "Instalando dependências..."
  install_from_here_or_clone

  # garante unit file e serviço
  if [[ -f "./dogwatch.service" ]]; then
    install -m 0644 ./dogwatch.service /etc/systemd/system/dogwatch.service
  fi
  systemctl daemon-reload
  systemctl enable --now dogwatch.service || true

  # reativa UFW + portas
  ufw_enable_with_ports

  # garante portas também via DogWatch (independe de UFW)
  if [[ -x /opt/dogwatch/dogwatch.sh ]]; then
    /opt/dogwatch/dogwatch.sh ensure-ports >/dev/null 2>&1 || true
  fi

  # reinicia ssh e confere
  systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true
  read_ports_from_env
  check_listen_port "$PRIMARY_SSH_PORT"

  say "Instalação concluída. Binário: /opt/dogwatch/dogwatch.sh"
  say "Status do serviço:"
  systemctl status dogwatch --no-pager || true
}

main "$@"
