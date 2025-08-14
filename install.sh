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

apt_quiet_install() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" >/dev/null 2>&1 || true
}

# --- portas a partir do config.env (se existir) ---
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

# --- UFW helpers ---
ufw_disable_safely() {
  if have_cmd ufw; then
    say "Desativando UFW temporariamente..."
    LC_ALL=C LANG=C ufw --force disable >/dev/null 2>&1 || true
  fi
}

ufw_enable_with_ports() {
  read_ports_from_env
  apt_quiet_install ufw
  hash -r

  if have_cmd ufw; then
    say "Reativando UFW e garantindo portas essenciais..."
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
    [[ -f /etc/default/ufw ]] && sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw || true

    LC_ALL=C LANG=C ufw --force reset >/dev/null 2>&1 || true
    LC_ALL=C LANG=C ufw logging off >/dev/null 2>&1 || true
    LC_ALL=C LANG=C ufw default deny incoming >/dev/null 2>&1 || true
    LC_ALL=C LANG=C ufw default allow outgoing >/dev/null 2>&1 || true

    LC_ALL=C LANG=C ufw allow "${PRIMARY_SSH_PORT}/tcp" >/dev/null 2>&1 || true
    LC_ALL=C LANG=C ufw allow "${EMERGENCY_SSH_PORT}/tcp" >/dev/null 2>&1 || true

    LC_ALL=C LANG=C ufw --force enable >/dev/null 2>&1 || true
    LC_ALL=C LANG=C ufw status verbose || true
  else
    say "Aviso: UFW não está disponível; prosseguindo sem UFW."
  fi
}

# --- checagem de porta de escuta ---
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

# --- instala a partir do diretório atual ou clona o repo ---
install_from_here_or_clone() {
  if [[ -f "./dogwatch.sh" ]]; then
    say "Instalando a partir do diretório atual..."
    bash ./dogwatch.sh install
  else
    say "Clonando o repositório..."
    local tmpdir
    tmpdir="$(mktemp -d)"
    apt_quiet_install git
    git clone "$REPO_URL" "$tmpdir"
    cd "$tmpdir"
    bash ./dogwatch.sh install
  fi
}

# --- cria a unit Early Safelane (executa ensure-ports antes da rede) ---
write_safelane_unit() {
  cat >/etc/systemd/system/dogwatch-safelane.service <<'UNIT'
[Unit]
Description=DogWatch Early Safelane (abre portas críticas antes da rede)
Documentation=man:systemd.unit(5)
After=local-fs.target
RequiresMountsFor=/opt/dogwatch
ConditionFileIsExecutable=/opt/dogwatch/dogwatch.sh
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
# pequeno atraso para UFW/firewalld/nft inicializarem
ExecStartPre=/bin/sleep 3
# 'ensure-ports' chama load_env internamente (sem "unbound variable")
ExecStart=/bin/bash -lc '/opt/dogwatch/dogwatch.sh ensure-ports || true'
RemainAfterExit=yes
SuccessExitStatus=0 1 2

[Install]
WantedBy=network-pre.target
UNIT
  chmod 0644 /etc/systemd/system/dogwatch-safelane.service
}

main() {
  require_root

  # Pré-requisitos
  apt-get update -y >/dev/null 2>&1 || true
  apt_quiet_install curl ca-certificates iproute2 netcat-openbsd jq rsync openssh-server nftables iptables ufw git

  # (opcional) segurar firewalld para evitar conflitos
  if command -v apt-mark >/dev/null 2>&1; then apt-mark hold firewalld >/dev/null 2>&1 || true; fi

  # Desativa UFW no começo para não atrapalhar a instalação
  ufw_disable_safely

  # Instala o DogWatch (cria /opt/dogwatch/dogwatch.sh e o serviço principal)
  install_from_here_or_clone

  # Garante que o serviço principal esteja enable/now
  systemctl daemon-reload
  systemctl enable --now dogwatch.service || true

  # Cria e ativa o SAFELANE (instalado pelo install.sh)
  write_safelane_unit
  systemctl daemon-reload
  systemctl enable --now dogwatch-safelane.service || true

  # Reativa UFW e libera as portas essenciais
  ufw_enable_with_ports

  # Reforça as portas também via DogWatch (independe de UFW)
  if [[ -x /opt/dogwatch/dogwatch.sh ]]; then
    /bin/bash -lc '/opt/dogwatch/dogwatch.sh ensure-ports || true'
  fi

  # Reinicia SSH e confere
  systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true
  read_ports_from_env
  check_listen_port "$PRIMARY_SSH_PORT"

  say "Instalação concluída. Binário: /opt/dogwatch/dogwatch.sh"
  say "Status do serviço principal:"
  systemctl status dogwatch --no-pager || true
  say "Status do safelane:"
  systemctl status dogwatch-safelane --no-pager || true
}

main "$@"
