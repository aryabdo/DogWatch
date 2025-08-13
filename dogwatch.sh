#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="1.2.0"
PROG="dogwatch"

# ------------- Helpers -------------
say() { echo "[$PROG] $*"; }
ts() { date +"%Y-%m-%d %H:%M:%S"; }

log() {
  local level="${1:-INFO}"; shift || true
  local msg="$*"
  [[ "${LOG_LEVEL:-INFO}" == "DEBUG" || "$level" != "DEBUG" ]] || return 0
  mkdir -p "${LOG_DIR:-/var/log/dogwatch}"
  echo "$(ts) [$level] $msg" | tee -a "${LOG_DIR:-/var/log/dogwatch}/$PROG.log" >/dev/null
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Este script deve ser executado como root."
    exit 1
  fi
}

get_boot_id() {
  cat /proc/sys/kernel/random/boot_id 2>/dev/null
}

set_pending_hash() {
  local hash="$1"
  local pending_file="$STATE_DIR/pending.hash"
  if [[ -f "$pending_file" ]] && [[ "$(cat "$pending_file" 2>/dev/null)" == "$hash" ]]; then
    return 0
  fi
  if [[ "${STRICT_PENDING_CONNECTIVITY:-1}" == "1" ]]; then
    if ! connectivity_healthy; then
      log WARN "Alteração detectada, mas conectividade não está saudável; pendência não criada (aguardando saúde)."
      return 1
    fi
  fi
  echo "$hash" > "$pending_file"
  get_boot_id > "$STATE_DIR/pending.boot_id" || true
  log INFO "Configuração alterada detectada; aguardando promoção."
}

promote_pending_if_stable() {
  local pending_file="$STATE_DIR/pending.hash"
  [[ -f "$pending_file" ]] || return 0
  local streak
  streak="$(cat "$STATE_DIR/normal_streak" 2>/dev/null || echo 0)"
  if (( streak >= PENDING_STABLE_CYCLES )); then
    local pending_boot current_boot
    pending_boot="$(cat "$STATE_DIR/pending.boot_id" 2>/dev/null || echo)"
    current_boot="$(get_boot_id)"
    if [[ -f "$STATE_DIR/admin_ack" || "$current_boot" != "$pending_boot" ]]; then
      cp "$pending_file" "$STATE_DIR/last_good.hash"
      rm -f "$pending_file" "$STATE_DIR/pending.boot_id" "$STATE_DIR/admin_ack"
      log INFO "Configuração pendente promovida para last_good.hash."
    fi
  fi
}

# ------------- Firewall detection -------------
detect_firewalls() {
  local detected=()
  command -v ufw >/dev/null 2>&1 && detected+=(ufw)
  systemctl list-unit-files 2>/dev/null | grep -q '^firewalld.service' && detected+=(firewalld)
  command -v nft >/dev/null 2>&1 && detected+=(nftables)
  command -v iptables >/dev/null 2>&1 && detected+=(iptables)
  FIREWALLS="${FIREWALLS:-}"
  FIREWALLS="${FIREWALLS:+$FIREWALLS }${detected[*]}"
  FIREWALLS="$(echo $FIREWALLS | tr ' ' '\n' | sort -u | tr '\n' ' ')"
  export FIREWALLS
}

# ------------- Defaults/Paths -------------
DATA_DIR_DEFAULT="/opt/dogwatch"
BACKUP_DIR_DEFAULT="$DATA_DIR_DEFAULT/backups"
LOG_DIR_DEFAULT="/var/log/dogwatch"
STATE_DIR_DEFAULT="$DATA_DIR_DEFAULT/state"
ENV_FILE="/etc/dogwatch/config.env"

mkdir -p /etc/dogwatch || true

# ------------- Load env -------------
load_env() {
  # Defaults
  export DATA_DIR="${DATA_DIR:-$DATA_DIR_DEFAULT}"
  export BACKUP_DIR="${BACKUP_DIR:-$BACKUP_DIR_DEFAULT}"
  export LOG_DIR="${LOG_DIR:-$LOG_DIR_DEFAULT}"
  export STATE_DIR="${STATE_DIR:-$STATE_DIR_DEFAULT}"
  export LOG_LEVEL="${LOG_LEVEL:-INFO}"
  export PRIMARY_SSH_PORT="${PRIMARY_SSH_PORT:-16309}"
  export EMERGENCY_SSH_PORT="${EMERGENCY_SSH_PORT:-22}"
  export RESTORE_EMERGENCY_PORTS="${RESTORE_EMERGENCY_PORTS:-16309}"
  export EMERGENCY_WINDOW_ON_000="${EMERGENCY_WINDOW_ON_000:-1}"
  export EMERGENCY_TTL_HOURS="${EMERGENCY_TTL_HOURS:-12}"
  export REQUIRE_ICMP_AND_HTTP="${REQUIRE_ICMP_AND_HTTP:-1}"
  export MANDATORY_OPEN_PORTS="${MANDATORY_OPEN_PORTS:-"$PRIMARY_SSH_PORT"}"
  export EXTRA_PORTS="${EXTRA_PORTS:-""}"
  export PREFERRED_INTERFACES="${PREFERRED_INTERFACES:-""}"
  export PING_TARGETS="${PING_TARGETS:-"1.1.1.1 8.8.8.8"}"
  export HTTP_TARGETS="${HTTP_TARGETS:-"https://www.google.com https://cloudflare.com"}"
  export MANUAL_OVERRIDE_PORTS="${MANUAL_OVERRIDE_PORTS:-0}"
  export MONITOR_INTERVAL_SECONDS="${MONITOR_INTERVAL_SECONDS:-300}"
  export BACKUP_INTERVAL_SECONDS="${BACKUP_INTERVAL_SECONDS:-1800}"
  export MAX_ROTATING_BACKUPS="${MAX_ROTATING_BACKUPS:-10}"
  export FIREWALLS="${FIREWALLS:-"ufw firewalld nftables iptables"}"
  export AGGRESSIVE_REPAIR="${AGGRESSIVE_REPAIR:-1}"
  export CURL_BIN="${CURL_BIN:-$(command -v curl || echo /usr/bin/curl)}"
  export NC_BIN="${NC_BIN:-$(command -v nc || echo /usr/bin/nc)}"
  export JQ_BIN="${JQ_BIN:-$(command -v jq || echo /usr/bin/jq)}"
  export RSYNC_BIN="${RSYNC_BIN:-$(command -v rsync || echo /usr/bin/rsync)}"
  export SYSCTL_BIN="${SYSCTL_BIN:-$(command -v sysctl || echo /usr/sbin/sysctl)}"
  export PUBLIC_IP_SERVICE="${PUBLIC_IP_SERVICE:-https://ifconfig.me}"
  export PENDING_STABLE_CYCLES="${PENDING_STABLE_CYCLES:-2}"
  export STRICT_PENDING_CONNECTIVITY="${STRICT_PENDING_CONNECTIVITY:-1}"
  export STOP_SERVICE_ON_SUCCESS="${STOP_SERVICE_ON_SUCCESS:-0}"

  [[ -f "$ENV_FILE" ]] && source "$ENV_FILE" || true
  detect_firewalls

  mkdir -p "$DATA_DIR" "$BACKUP_DIR" "$LOG_DIR" "$STATE_DIR"
  chmod 700 "$DATA_DIR" "$BACKUP_DIR" "$STATE_DIR" || true
}

# ------------- Install/Uninstall -------------
install_self() {
  require_root
  load_env

  say "Instalando dependências..."
  apt-get update -y || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl jq rsync netcat-openbsd iproute2 ufw wireguard-tools \
    rclone ddclient dnsutils lsof nmap speedtest-cli > /dev/null

  say "Instalando arquivos..."
  mkdir -p "$DATA_DIR"
  install -m 0755 "$(realpath "$0")" "$DATA_DIR/$PROG.sh"
  if [[ -f ./config.env.example ]]; then
    install -m 0644 ./config.env.example "$ENV_FILE"
  else
    mkdir -p "$(dirname "$ENV_FILE")"
    cat > "$ENV_FILE" <<'EOF'
PRIMARY_SSH_PORT="16309"
EMERGENCY_SSH_PORT="22"
RESTORE_EMERGENCY_PORTS="16309"
EMERGENCY_WINDOW_ON_000=1
EMERGENCY_TTL_HOURS="12"
REQUIRE_ICMP_AND_HTTP=1
MANDATORY_OPEN_PORTS="16309"
EXTRA_PORTS=""
PREFERRED_INTERFACES=""
PING_TARGETS="1.1.1.1 8.8.8.8"
HTTP_TARGETS="https://www.google.com https://cloudflare.com"
MANUAL_OVERRIDE_PORTS=0
LOG_LEVEL="INFO"
DATA_DIR="/opt/dogwatch"
BACKUP_DIR="$DATA_DIR/backups"
LOG_DIR="/var/log/dogwatch"
STATE_DIR="$DATA_DIR/state"
MONITOR_INTERVAL_SECONDS=300
BACKUP_INTERVAL_SECONDS=1800
MAX_ROTATING_BACKUPS=10
FIREWALLS="ufw firewalld nftables iptables"
AGGRESSIVE_REPAIR=1
STOP_SERVICE_ON_SUCCESS=0
EOF
  fi

  install -m 0644 "./$PROG.service" "/etc/systemd/system/$PROG.service"
  systemctl daemon-reload
  systemctl enable "$PROG.service" || true

  say "Criando backup inicial 0.0..."
  first_run_bootstrap

  say "Instalação concluída."
  say "Inicie com: systemctl start $PROG.service"
}

uninstall_self() {
  require_root
  load_env
  say "Parando serviço..."
  systemctl disable --now "$PROG.service" || true
  rm -f "/etc/systemd/system/$PROG.service"
  systemctl daemon-reload

  say "Removendo arquivos (mantendo backups em $BACKUP_DIR)..."
  rm -f "$DATA_DIR/$PROG.sh" || true
  rm -f "$ENV_FILE" || true
  rm -rf "$STATE_DIR" || true
  rm -rf "$LOG_DIR" || true

  say "Pronto. Backups preservados em: $BACKUP_DIR"
}

# ------------- Backup/Restore -------------
backup_items_list() {
  # Lista de caminhos/artefatos a incluir
  cat <<'EOF'
/etc/hosts
/etc/hostname
/etc/resolv.conf
/etc/netplan
/etc/network
/etc/sysctl.conf
/etc/sysctl.d
/etc/ssh
/root/.ssh
/etc/ufw
/etc/firewalld
/etc/nftables.conf
/etc/iptables
/etc/iptables.rules
/etc/iptables/rules.v4
/etc/iptables/rules.v6
/etc/fail2ban
/etc/hosts.allow
/etc/hosts.deny
/etc/wireguard
/etc/systemd/system/wg-quick@.service
/etc/systemd/system/wg-quick@*.service
/etc/rclone
/etc/ddclient.conf
/etc/dnsmasq.conf
/etc/dnsmasq.d
/etc/NetworkManager
/etc/modprobe.d
/etc/modules-load.d
/var/lib/ufw
EOF
}

snapshot_commands() {
  # Comandos cujas saídas serão salvas para diagnóstico
  cat <<'EOF'
ip a
ip r
ss -lntup
$SYSCTL_BIN -a
ufw status verbose || true
nft list ruleset || true
iptables-save || true
systemctl status ssh --no-pager || true
systemctl status ufw --no-pager || true
systemctl status firewalld --no-pager || true
systemctl status wg-quick@* --no-pager || true
EOF
}

backup_snapshot() {
  require_root
  load_env
  local label="${1:-auto}"
  local stamp
  stamp="$(date +'%Y%m%d-%H%M%S')"
  local dir="$BACKUP_DIR/$stamp-$label"
  mkdir -p "$dir/files" "$dir/cmd" "$dir/meta"

  # Copia arquivos/diretórios existentes
  while read -r item; do
    [[ -z "$item" ]] && continue
    if [[ -e "$item" || "$item" == *"*"* ]]; then
      rsync -aR --delete --relative $item "$dir/files/" 2>/dev/null || true
    fi
  done < <(backup_items_list)

  # Saídas de comandos
  while read -r cmd; do
    [[ -z "$cmd" ]] && continue
    sh -c "$cmd" > "$dir/cmd/$(echo "$cmd" | tr ' /@*' '____').txt" 2>&1 || true
  done < <(snapshot_commands)

  # Metadados
  (uname -a; lsb_release -a 2>/dev/null || true; date) > "$dir/meta/system.txt"
  (command -v curl >/dev/null 2>&1 && { curl -s https://api.ipify.org || true; echo; }) > "$dir/meta/public_ip.txt" || true
  echo "$VERSION" > "$dir/meta/$PROG.version"

  # Atualiza rotação (mantém 10, preserva 0.0)
  rotate_backups

  echo "$dir"
}

rotate_backups() {
  # Mantém MAX_ROTATING_BACKUPS mais recentes, preservando backup 0.0
  local keep="$MAX_ROTATING_BACKUPS"
  mapfile -t snaps < <(find "$BACKUP_DIR" -maxdepth 1 -type d -printf "%P\n" | sort -r)
  local count=0
  for s in "${snaps[@]}"; do
    [[ "$s" == "000-initial" || -z "$s" ]] && continue
    count=$((count+1))
    if (( count > keep )); then
      rm -rf "$BACKUP_DIR/$s" || true
    fi
  done
}

first_run_bootstrap() {
  load_env
  if [[ ! -d "$BACKUP_DIR/000-initial" ]]; then
    mkdir -p "$BACKUP_DIR/000-initial"
    local path
    path="$(backup_snapshot "backup-0.0")"
    # Move conteúdo para 000-initial
    shopt -s dotglob
    mv "$path"/* "$BACKUP_DIR/000-initial"/ 2>/dev/null || true
    rmdir "$path" || true
    shopt -u dotglob
    log INFO "Backup 0.0 criado em $BACKUP_DIR/000-initial"
  else
    log DEBUG "Backup 0.0 já existe."
  fi
  # Salva hash da última configuração 'boa'
  compute_current_hash > "$STATE_DIR/last_good.hash" || true
}

list_backups() {
  load_env
  find "$BACKUP_DIR" -maxdepth 1 -mindepth 1 -type d -printf "%P\n" | sort
}

restore_snapshot() {
  require_root
  load_env
  local snap="$1"
  local dir="$BACKUP_DIR/$snap"
  if [[ ! -d "$dir" ]]; then
    echo "Snapshot não encontrado: $snap"
    exit 1
  fi
  log INFO "Restaurando snapshot: $snap"

  # Desabilita firewalls antes de restaurar
  safe_disable_firewalls

  # Restaura arquivos sem apagar itens que não estejam no backup
  while IFS= read -r src; do
    dest="/$(basename "$src")"
    if [[ -d "$src" ]]; then
      rsync -a "$src/" "$dest/" 2>/dev/null || true
    else
      rsync -a "$src" "$dest" 2>/dev/null || true
    fi
  done < <(find "$dir/files" -mindepth 1 -maxdepth 1)

  # Reaplica configurações de rede para garantir conectividade
  if command -v netplan >/dev/null 2>&1; then
    netplan generate >/dev/null 2>&1 || true
    netplan apply || true
  fi
  systemctl restart systemd-networkd 2>/dev/null || true
  systemctl restart NetworkManager 2>/dev/null || true
  systemctl restart networking 2>/dev/null || true
  reset_remote_access
  if [[ "$snap" == "000-initial" && "$EMERGENCY_WINDOW_ON_000" == "1" ]]; then
    ensure_ports_open "$PRIMARY_SSH_PORT $RESTORE_EMERGENCY_PORTS $EMERGENCY_SSH_PORT"
  else
    ensure_ports_open "$RESTORE_EMERGENCY_PORTS"
  fi

  log INFO "Reiniciando servidor..."
  sleep 20
  sudo reboot || reboot
}

compute_current_hash() {
  # Hash cumulativo das configs relevantes (arquivos + status ufw/nft + sshd)
  local tmp
  tmp="$(mktemp)"
  while read -r item; do
    [[ -z "$item" ]] && continue
    if [[ -e "$item" ]]; then
      find "$item" -type f -exec sha256sum {} \; 2>/dev/null
    fi
  done < <(backup_items_list) >> "$tmp" 2>/dev/null || true

  {
    ufw status verbose 2>/dev/null || true
    nft list ruleset 2>/dev/null || true
    iptables-save 2>/dev/null || true
    ss -lntup 2>/dev/null || true
    ip a 2>/dev/null || true
    ip r 2>/dev/null || true
  } >> "$tmp" 2>/dev/null
  sha256sum "$tmp" | awk '{print $1}'
  rm -f "$tmp"
}

connectivity_healthy() {
  local ports="$MANDATORY_OPEN_PORTS"
  ports="$(echo $ports)"
  has_outbound_internet || return 1
  listening_on_ports $ports >/dev/null || return 1
  has_remote_access || return 1
  return 0
}

# ------------- Connectivity Checks -------------
has_outbound_internet() {
  # Testa ping ICMP e HTTP com múltiplos alvos e retries
  local ping_ok=1 http_ok=1
  for ip in $PING_TARGETS; do
    for _ in {1..3}; do
      if ping -c1 -W1 "$ip" >/dev/null 2>&1; then
        log DEBUG "Ping OK: $ip"
        ping_ok=0
        break 2
      fi
    done
  done
  for url in $HTTP_TARGETS; do
    for _ in {1..3}; do
      local output status body
      output="$($CURL_BIN -m3 -sS "$url" -w 'HTTPSTATUS:%{http_code}' 2>/dev/null)"
      status="${output##*HTTPSTATUS:}"
      body="${output%HTTPSTATUS:*}"
      if [[ -n "$body" && "$status" =~ ^[0-9]+$ && "$status" -lt 400 ]]; then
        log DEBUG "HTTP OK: $url ($status)"
        http_ok=0
        break 2
      fi
    done
  done
  if [[ "${REQUIRE_ICMP_AND_HTTP:-1}" == "1" ]]; then
    [[ $ping_ok -eq 0 && $http_ok -eq 0 ]]
  else
    [[ $ping_ok -eq 0 || $http_ok -eq 0 ]]
  fi
}

has_remote_access() {
  # Verifica se portas obrigatórias estão acessíveis via IP público.
  # Alguns ambientes não permitem testar o próprio IP público (hairpin NAT).
  # Caso o teste remoto falhe, fazemos um fallback para IPs locais para evitar
  # falsos negativos.
  local ip
  ip="$($CURL_BIN -fsS "$PUBLIC_IP_SERVICE" 2>/dev/null | tr -d '\r\n' || echo)"
  local ports="$MANDATORY_OPEN_PORTS"
  ports="$(echo $ports)"
  local candidates=(127.0.0.1)
  while IFS= read -r addr; do
    [[ -n "$addr" ]] && candidates+=("$addr")
  done < <(ip -o -4 addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
  for p in $ports; do
    if [[ -n "$ip" ]] && $NC_BIN -w2 -z "$ip" "$p" >/dev/null 2>&1; then
      log DEBUG "Porta remota OK: $ip:$p"
      continue
    fi
    for candidate in "${candidates[@]}"; do
      if $NC_BIN -w2 -z "$candidate" "$p" >/dev/null 2>&1; then
        log DEBUG "Porta local OK (fallback): $candidate:$p"
        continue 2
      fi
    done
    log DEBUG "Porta remota falhou: $ip:$p"
    return 1
  done
  return 0
}

listening_on_ports() {
  local ports="$*"
  local missing=()

  if command -v ss >/dev/null 2>&1; then
    for p in $ports; do
      if ss -lnt "sport = :$p" 2>/dev/null | grep -q "."; then
        log DEBUG "Listening on $p"
      else
        missing+=("$p")
      fi
    done
  else
    for p in $ports; do
      if $NC_BIN -z 127.0.0.1 "$p" >/dev/null 2>&1 || \
         $NC_BIN -z ::1 "$p" >/dev/null 2>&1; then
        log DEBUG "Listening on $p"
      else
        missing+=("$p")
      fi
    done
  fi

  if (( ${#missing[@]} > 0 )); then
    log DEBUG "Não está ouvindo em: ${missing[*]}"
    echo "${missing[*]}"
    return 1
  fi
  return 0
}

firewall_allows_ports() {
  local ports="$*"
  local blocked=()
  for fw in $FIREWALLS; do
    case "$fw" in
      ufw)
        if command -v ufw >/dev/null 2>&1; then
          local status
          status="$(ufw status | tr '[:upper:]' '[:lower:]')"
          if ! echo "$status" | grep -q "inactive"; then
            for p in $ports; do
              if echo "$status" | grep -qE "\\b${p}/tcp\\b.*allow|\\b${p}\\b.*allow"; then
                :
              else
                blocked+=("$p")
              fi
            done
          fi
        fi
        ;;
      firewalld)
        if systemctl is-active --quiet firewalld 2>/dev/null; then
          local plist
          plist="$(firewall-cmd --permanent --list-ports 2>/dev/null || true)"
          for p in $ports; do
            echo "$plist" | grep -qw "${p}/tcp" || blocked+=("$p")
          done
        fi
        ;;
      nftables)
        if command -v nft >/dev/null 2>&1; then
          local rules
          rules="$(nft list ruleset 2>/dev/null || true)"
          for p in $ports; do
            echo "$rules" | grep -qw "dport $p" || blocked+=("$p")
          done
        fi
        ;;
      iptables)
        if command -v iptables >/dev/null 2>&1; then
          local rules
          rules="$(iptables -L INPUT -n 2>/dev/null || true)"
          for p in $ports; do
            echo "$rules" | grep -qw "dpt:$p" || blocked+=("$p")
          done
        fi
        ;;
    esac
  done
  if (( ${#blocked[@]} > 0 )); then
    log DEBUG "Portas potencialmente bloqueadas nos firewalls: ${blocked[*]}"
    return 1
  fi
  return 0
}

ensure_ports_open() {
  local ports="${*:-${MANDATORY_OPEN_PORTS} ${EXTRA_PORTS}}"
  ports="$(echo $ports)" # normaliza espaços
  for fw in $FIREWALLS; do
    case "$fw" in
      ufw)
        if command -v ufw >/dev/null 2>&1; then
          ufw --force enable || true
          for p in $ports; do
            ufw allow "$p/tcp" || true
          done
        fi
        ;;
      firewalld)
        if systemctl is-active --quiet firewalld 2>/dev/null; then
          for p in $ports; do
            firewall-cmd --add-port="$p/tcp" --permanent || true
            firewall-cmd --reload || true
          done
        fi
        ;;
      nftables)
        if command -v nft >/dev/null 2>&1; then
          for p in $ports; do
            nft add rule inet filter input tcp dport "$p" accept 2>/dev/null || true
          done
          nft list ruleset >/etc/nftables.conf 2>/dev/null || true
          systemctl restart nftables 2>/dev/null || true
        fi
        ;;
      iptables)
        if command -v iptables >/dev/null 2>&1; then
          for p in $ports; do
            iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport "$p" -j ACCEPT || true
          done
          mkdir -p /etc/iptables
          iptables-save >/etc/iptables/rules.v4 2>/dev/null || true
        fi
        ;;
    esac
  done
}

safe_disable_firewalls() {
  # Desativa firewalls se atrapalham conectividade (apenas durante restauração)
  for fw in $FIREWALLS; do
    case "$fw" in
      ufw)
        command -v ufw >/dev/null 2>&1 && ufw --force disable || true
        ;;
      firewalld)
        if systemctl is-active --quiet firewalld 2>/dev/null; then
          systemctl stop firewalld || true
          systemctl disable firewalld || true
        fi
        ;;
      nftables)
        command -v nft >/dev/null 2>&1 && nft flush ruleset 2>/dev/null || true
        ;;
      iptables)
        command -v iptables >/dev/null 2>&1 && iptables -F 2>/dev/null || true
        ;;
    esac
  done
}

reset_remote_access() {
  load_env
  # Garantir acesso SSH por senha de qualquer IP e limpar bloqueios
  if [[ -f /etc/ssh/sshd_config ]]; then
    sed -i '/^PasswordAuthentication/d;/^PermitRootLogin/d;/^AllowUsers/d;/^DenyUsers/d;/^AllowGroups/d;/^DenyGroups/d;/^ListenAddress/d' /etc/ssh/sshd_config
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
  fi
  : > /etc/hosts.deny || true
  if command -v fail2ban-client >/dev/null 2>&1; then
    fail2ban-client unban --all || true
  fi
  if command -v passwd >/dev/null 2>&1; then
    passwd -u root 2>/dev/null || true
  fi
  for fw in $FIREWALLS; do
    case "$fw" in
      ufw)
        command -v ufw >/dev/null 2>&1 && ufw --force reset || true
        ;;
      firewalld)
        if systemctl is-active --quiet firewalld 2>/dev/null; then
          firewall-cmd --permanent --delete-all-rich-rules 2>/dev/null || true
          firewall-cmd --permanent --delete-all-rules 2>/dev/null || true
          firewall-cmd --reload 2>/dev/null || true
        fi
        ;;
      nftables)
        command -v nft >/dev/null 2>&1 && nft flush ruleset 2>/dev/null || true
        ;;
      iptables)
        if command -v iptables >/dev/null 2>&1; then
          iptables -F 2>/dev/null || true
          iptables -X 2>/dev/null || true
        fi
        ;;
    esac
  done
  ensure_ports_open
  ssh_safe_reload || true
}

ssh_safe_reload() {
  if sshd -t 2>/dev/null; then
    systemctl reload ssh 2>/dev/null || systemctl restart ssh 2>/dev/null || true
  else
    log WARN "sshd_config inválido; reload abortado"
    return 1
  fi
}

ssh_set_dual_port_mode() {
  load_env
  sed -i '/^Port/d' /etc/ssh/sshd_config 2>/dev/null || true
  {
    echo "Port $PRIMARY_SSH_PORT"
    echo "Port $EMERGENCY_SSH_PORT"
  } >> /etc/ssh/sshd_config
  ensure_ports_open "$PRIMARY_SSH_PORT $EMERGENCY_SSH_PORT"
  ssh_safe_reload || return 1
  sleep 2
  if $NC_BIN -z 127.0.0.1 "$PRIMARY_SSH_PORT" >/dev/null 2>&1; then
    sed -i '/^Port/d' /etc/ssh/sshd_config
    echo "Port $PRIMARY_SSH_PORT" >> /etc/ssh/sshd_config
    ssh_safe_reload || return 1
    return 0
  else
    log ERROR "Falha ao validar porta $PRIMARY_SSH_PORT"
    return 1
  fi
}

ssh_set_permissive_mode() {
  local reason="$1"
  load_env
  sed -i '/^PasswordAuthentication/d;/^PermitRootLogin/d;/^AllowUsers/d;/^Port/d' /etc/ssh/sshd_config 2>/dev/null || true
  echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
  echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
  echo "Port $PRIMARY_SSH_PORT" >> /etc/ssh/sshd_config
  echo "Port $EMERGENCY_SSH_PORT" >> /etc/ssh/sshd_config
  ensure_ports_open "$PRIMARY_SSH_PORT $EMERGENCY_SSH_PORT"
  ssh_safe_reload || true
  echo "$(date +%s) $EMERGENCY_TTL_HOURS $reason" > "$STATE_DIR/ssh_permissive.mode"
  log WARN "Modo SSH permissivo ativado ($reason)"
}

ssh_set_restricted_mode() {
  load_env
  sed -i '/^PasswordAuthentication/d;/^PermitRootLogin/d;/^AllowUsers/d;/^Port/d' /etc/ssh/sshd_config 2>/dev/null || true
  echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
  echo "PermitRootLogin no" >> /etc/ssh/sshd_config
  echo "AllowUsers aasn" >> /etc/ssh/sshd_config
  echo "Port $PRIMARY_SSH_PORT" >> /etc/ssh/sshd_config
  ssh_safe_reload || true
  ensure_ports_open "$PRIMARY_SSH_PORT"
  for fw in $FIREWALLS; do
    case "$fw" in
      ufw)
        command -v ufw >/dev/null 2>&1 && ufw delete allow "$EMERGENCY_SSH_PORT/tcp" >/dev/null 2>&1 || true ;;
      firewalld)
        if systemctl is-active --quiet firewalld 2>/dev/null; then
          firewall-cmd --remove-port="$EMERGENCY_SSH_PORT/tcp" --permanent 2>/dev/null || true
          firewall-cmd --reload 2>/dev/null || true
        fi ;;
      nftables)
        command -v nft >/dev/null 2>&1 && nft delete rule inet filter input tcp dport "$EMERGENCY_SSH_PORT" accept 2>/dev/null || true ;;
      iptables)
        command -v iptables >/dev/null 2>&1 && iptables -D INPUT -p tcp --dport "$EMERGENCY_SSH_PORT" -j ACCEPT 2>/dev/null || true ;;
    esac
  done
  rm -f "$STATE_DIR/ssh_permissive.mode" || true
  log INFO "Modo SSH restrito aplicado"
}

ssh_check_ttl_and_restrict_if_needed() {
  load_env
  local file="$STATE_DIR/ssh_permissive.mode"
  [[ -f "$file" ]] || return 0
  read -r start ttl reason < "$file"
  local now
  now="$(date +%s)"
  local expire=$((start + ttl*3600))
  if (( now >= expire )); then
    log WARN "Janela permissiva expirada; aplicando modo restrito"
    ssh_set_restricted_mode
  fi
}

apply_server_baseline() {
  load_env
  log INFO "Aplicando baseline do servidor"
  if [[ ! -e /sys/class/net/eno1 ]]; then
    log WARN "Interface eno1 não encontrada; abortando baseline de rede"
    return 1
  fi
  cat > /etc/netplan/01-dogwatch.yaml <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    eno1:
      dhcp4: no
      addresses: [192.168.15.150/24]
      gateway4: 192.168.15.1
EOF
  netplan try --timeout 60 >/dev/null 2>&1 <<<"y" || netplan apply >/dev/null 2>&1 || true
  ssh_set_dual_port_mode || return 1
  ssh_set_restricted_mode || return 1
  if command -v ufw >/dev/null 2>&1; then
    ufw --force reset >/dev/null 2>&1 || true
    ufw default deny incoming >/dev/null 2>&1 || true
    ufw allow "${PRIMARY_SSH_PORT}/tcp" >/dev/null 2>&1 || true
    ufw limit "${PRIMARY_SSH_PORT}/tcp" >/dev/null 2>&1 || true
    ufw deny "${EMERGENCY_SSH_PORT}/tcp" >/dev/null 2>&1 || true
    ufw --force enable >/dev/null 2>&1 || true
  fi
  if [[ -d /etc/fail2ban ]]; then
    sed -i "s/^port=.*/port=${PRIMARY_SSH_PORT}/" /etc/fail2ban/jail.local 2>/dev/null || true
    systemctl restart fail2ban >/dev/null 2>&1 || true
  fi
  if has_outbound_internet && has_remote_access; then
    log INFO "Baseline aplicada com sucesso"
  else
    log WARN "Falha na conectividade após baseline"
    attempt_restore_queue || true
  fi
}

detect_external_vs_internal() {
  # Retorna 0 se parece externo, 1 se interno
  # Heurística: sem internet de saída E hash de configs não mudou => externo
  # Se hash mudou OU firewall/sshd listening problem OU acesso remoto falhou => interno
  if has_outbound_internet; then
    # Tem internet: se portas não estão abertas/listening, firewall bloqueia ou acesso remoto falha => interno
    local ports="$MANDATORY_OPEN_PORTS"
    ports="$(echo $ports)"
    if listening_on_ports $ports && firewall_allows_ports $ports && has_remote_access; then
      # Tudo parece ok
      echo "normal"
      return 2
    else
      echo "internal"
      return 1
    fi
  else
    # Sem saída: compara hash
    local current="$(compute_current_hash || echo "x")"
    local last_good="$(cat "$STATE_DIR/last_good.hash" 2>/dev/null || echo "y")"
    if [[ "$current" == "$last_good" ]]; then
      echo "external"
      return 0
    else
      echo "internal"
      return 1
    fi
  fi
}

status_report() {
  load_env
  local green='\033[32m' yellow='\033[33m' red='\033[31m' reset='\033[0m'
  local listen_ports="${MANDATORY_OPEN_PORTS}"
  listen_ports="$(echo $listen_ports)"
  local fw_ports="${MANDATORY_OPEN_PORTS} ${EXTRA_PORTS}"
  fw_ports="$(echo $fw_ports)"

  if [[ -f "$STATE_DIR/pending.hash" ]]; then
    echo -e "${yellow}Configuração pendente: aguardando estabilização${reset}"
  fi

  if [[ -f "$STATE_DIR/restore_queue.txt" ]]; then
    local idx total next
    idx="$(cat "$STATE_DIR/restore_index" 2>/dev/null || echo 0)"
    total="$(wc -l < "$STATE_DIR/restore_queue.txt" 2>/dev/null || echo 0)"
    next="$(sed -n "$((idx+1))p" "$STATE_DIR/restore_queue.txt" 2>/dev/null || echo "-" )"
    echo -e "${yellow}Fila de restauração ativa (índice $idx de $((total-1)))${reset}"
    echo -e "${yellow}Próximo snapshot no reboot: $next${reset}"
  fi

  if [[ -f "$STATE_DIR/ssh_permissive.mode" ]]; then
    local start ttl reason now remain
    read -r start ttl reason < "$STATE_DIR/ssh_permissive.mode"
    now="$(date +%s)"
    remain=$((start + ttl*3600 - now))
    if (( remain > 0 )); then
      local hrs=$((remain/3600))
      local mins=$(((remain%3600)/60))
      echo -e "${yellow}Janela permissiva ativa ($reason) - restante: ${hrs}h${mins}m${reset}"
    else
      echo -e "${red}Janela permissiva expirada${reset}"
    fi
  fi

  if [[ "${STOP_SERVICE_ON_SUCCESS:-0}" == "1" ]]; then
    echo -e "${yellow}STOP_SERVICE_ON_SUCCESS habilitado${reset}"
  fi

  if has_outbound_internet; then
    echo -e "${green}Internet de saída: OK${reset}"
  else
    echo -e "${red}Internet de saída: FALHA - verifique conexão/DNS${reset}"
  fi

  if has_remote_access; then
    echo -e "${green}Acesso remoto: OK${reset}"
  else
    echo -e "${red}Acesso remoto: FALHA - possível IP/porta incorreta${reset}"
  fi

  local missing_ports
  if missing_ports=$(listening_on_ports $listen_ports); then
    echo -e "${green}Portas ouvindo: $listen_ports${reset}"
  else
    echo -e "${red}Portas não estão ouvindo: $missing_ports - iniciar serviços ou ajustar firewall${reset}"
  fi

  if firewall_allows_ports $fw_ports; then
    echo -e "${green}Firewall permite portas necessárias${reset}"
  else
    echo -e "${yellow}Firewall bloqueando portas - execute ensure-ports${reset}"
  fi

  local state="$(detect_external_vs_internal || true)"
  case "$state" in
    normal)
      echo -e "${green}Status geral: normal${reset}"
      ;;
    internal)
      echo -e "${red}Status geral: interno - verificar serviços/firewall ou restaurar backup${reset}"
      ;;
    external)
      echo -e "${yellow}Status geral: external - possível falha de provedor/rota${reset}"
      ;;
  esac
}

setup_restore_queue() {
  load_env
  mapfile -t snaps < <(find "$BACKUP_DIR" -maxdepth 1 -mindepth 1 -type d -printf "%P\n" | sort -r)
  snaps_sorted=()
  for s in "${snaps[@]}"; do [[ "$s" != "000-initial" ]] && snaps_sorted+=("$s"); done
  snaps_sorted+=("000-initial")
  printf "%s\n" "${snaps_sorted[@]}" > "$STATE_DIR/restore_queue.txt"
  echo 0 > "$STATE_DIR/restore_index"
}

attempt_restore_queue() {
  load_env
  [[ -f "$STATE_DIR/restore_queue.exhausted" ]] && { log WARN "Fila de restauração já esgotada."; return 1; }
  [[ -f "$STATE_DIR/restore_queue.txt" ]] || setup_restore_queue
  local idx total snap
  idx="$(cat "$STATE_DIR/restore_index" 2>/dev/null || echo 0)"
  total="$(wc -l < "$STATE_DIR/restore_queue.txt")"
  if (( idx >= total )); then
    log WARN "Fila de restauração esgotada."
    rm -f "$STATE_DIR/restore_queue.txt" "$STATE_DIR/restore_index"
    touch "$STATE_DIR/restore_queue.exhausted"
    return 1
  fi
  snap="$(sed -n "$((idx+1))p" "$STATE_DIR/restore_queue.txt")"
  log INFO "Tentando restauração: $snap"
  if [[ "$snap" == "000-initial" && "$EMERGENCY_WINDOW_ON_000" == "1" ]]; then
    ssh_set_permissive_mode "000-initial" || true
    ensure_ports_open "$PRIMARY_SSH_PORT $RESTORE_EMERGENCY_PORTS $EMERGENCY_SSH_PORT"
  else
    ensure_ports_open "$RESTORE_EMERGENCY_PORTS"
  fi
  echo $((idx+1)) > "$STATE_DIR/restore_index"
  restore_snapshot "$snap"
}

finalize_restore_queue() {
  load_env
  if [[ -f "$STATE_DIR/restore_queue.txt" ]]; then
    if has_outbound_internet; then
      compute_current_hash > "$STATE_DIR/last_good.hash" || true
      rm -f "$STATE_DIR/restore_queue.txt" "$STATE_DIR/restore_index"
      touch "$STATE_DIR/restore_queue.exhausted"
      log INFO "Fila de restauração concluída com sucesso"
      if [[ "${STOP_SERVICE_ON_SUCCESS:-0}" == "1" ]]; then
        systemctl disable --now "$PROG.service" || true
      fi
    fi
  fi
}

# ------------- Daemon Loops -------------
daemon_loop() {
  require_root
  load_env
  say "Iniciando daemon $PROG v$VERSION"
  # Garante backup inicial
  first_run_bootstrap
  # Garante portas obrigatórias
  ensure_ports_open
  ssh_check_ttl_and_restrict_if_needed

  local last_backup_ts=0
  while true; do
    ssh_check_ttl_and_restrict_if_needed
    # Backups rotativos a cada 30 min
    local now
    now="$(date +%s)"
    if (( now - last_backup_ts >= BACKUP_INTERVAL_SECONDS )); then
      backup_snapshot "auto" >/dev/null 2>&1 || true
      last_backup_ts="$now"
      log INFO "Backup automático concluído."
    fi

    # Monitoramento de 5 em 5 min (mas o loop pode rodar mais frequente)
    local assessment
    assessment="$(detect_external_vs_internal || true)"
    log DEBUG "Diagnóstico: $assessment"
    local streak
    streak="$(cat "$STATE_DIR/normal_streak" 2>/dev/null || echo 0)"
    case "$assessment" in
      normal)
        streak=$((streak + 1))
        echo "$streak" > "$STATE_DIR/normal_streak"
        local current_hash last_hash
        current_hash="$(compute_current_hash || echo x)"
        last_hash="$(cat "$STATE_DIR/last_good.hash" 2>/dev/null || echo y)"
        if [[ "$current_hash" != "$last_hash" ]]; then
          set_pending_hash "$current_hash"
        fi
        finalize_restore_queue || true
        ;;
      external)
        echo 0 > "$STATE_DIR/normal_streak"
        log WARN "Problema de conectividade parece EXTERNO (provedor/rota). Nenhuma ação tomada."
        ;;
      internal)
        echo 0 > "$STATE_DIR/normal_streak"
        log WARN "Problema de conectividade INTERNAMENTE detectado. Iniciando autorreparo..."
        ensure_ports_open
        attempt_restore_queue || true
        ;;
      *)
        echo 0 > "$STATE_DIR/normal_streak"
        log DEBUG "Estado desconhecido."
        ;;
    esac
    promote_pending_if_stable

    sleep "$MONITOR_INTERVAL_SECONDS"
  done
}

# ------------- Menu Interativo -------------
menu() {
  require_root
  load_env
  while true; do
    clear
    status_report
    echo
    cat <<EOF
================= DOGWATCH (v$VERSION) =================
1) Status geral
2) Ver logs (tail -f)
3) Backup agora
4) Listar backups
5) Restaurar backup
6) Portas - abrir/fechar/listar
7) Firewalls - status/ativar/desativar
8) Listas (UFW) - whitelist/blacklist
9) Diagnósticos (ping/http/listen/firewall)
10) Velocidade (speedtest-cli)
11) Instalar/checar dependências
12) Configurações (editar config.env)
13) Remover solução (mantém backups)
14) Aplicar baseline do servidor
15) Fechar acesso emergencial (porta 22)
0) Sair
============================================================
EOF
    read -rp "Escolha: " op
    case "$op" in
      1)
        echo "Status serviço:"
        systemctl status "$PROG.service" --no-pager || true
        echo
        status_report
        read -rp "Enter para continuar..." _ ;;
      2)
        echo "Pressione Ctrl+C para sair."
        tail -f "$LOG_DIR/$PROG.log" || true ;;
      3)
        local path
        path=$(backup_snapshot "manual")
        echo "Backup criado em: $path"
        read -rp "Enter para continuar..." _ ;;
      4)
        list_backups; read -rp "Enter para continuar..." _ ;;
      5)
        list_backups
        read -rp "Digite o nome do snapshot para restaurar: " s
        restore_snapshot "$s"
        echo "Restauração solicitada."
        read -rp "Enter para continuar..." _ ;;
      6)
        echo "Portas obrigatórias atuais: $MANDATORY_OPEN_PORTS"
        echo "Portas extras: $EXTRA_PORTS"
        echo "a) Abrir porta"
        echo "b) Fechar porta (apenas extras)"
        echo "c) Listar listening (ss) e UFW"
        read -rp "Opção: " po
        case "$po" in
          a)
            read -rp "Porta TCP a abrir: " p
            if [[ -n "${p//[^0-9]/}" ]]; then
              EXTRA_PORTS="$(echo "$EXTRA_PORTS $p" | xargs -n1 | sort -u | xargs)"
              sed -i "s/^EXTRA_PORTS=.*/EXTRA_PORTS=\"$EXTRA_PORTS\"/" "$ENV_FILE"
              MANUAL_OVERRIDE_PORTS=1; sed -i "s/^MANUAL_OVERRIDE_PORTS=.*/MANUAL_OVERRIDE_PORTS=1/" "$ENV_FILE"
              ensure_ports_open
              echo "Porta $p adicionada e aberta."
            fi ;;
          b)
            read -rp "Porta TCP a fechar (somente se estiver em EXTRA_PORTS): " p
            if echo " $EXTRA_PORTS " | grep -q " $p "; then
              EXTRA_PORTS="$(echo "$EXTRA_PORTS" | tr ' ' '\n' | grep -v "^$p$" | xargs)"
              sed -i "s/^EXTRA_PORTS=.*/EXTRA_PORTS=\"$EXTRA_PORTS\"/" "$ENV_FILE"
              # UFW remove rule
              ufw delete allow "$p/tcp" || true
              echo "Porta $p removida de EXTRA_PORTS e bloqueada no UFW (se presente)."
            else
              echo "Porta não está em EXTRA_PORTS."
            fi ;;
          c)
            ss -lntup || true
            echo
            ufw status verbose || true
            ;;
        esac
        read -rp "Enter para continuar..." _ ;;
      7)
        echo "Firewalls:"
        echo "- UFW: $(systemctl is-enabled ufw 2>/dev/null || true) / $(systemctl is-active ufw 2>/dev/null || true)"
        echo "- firewalld: $(systemctl is-enabled firewalld 2>/dev/null || true) / $(systemctl is-active firewalld 2>/dev/null || true)"
        echo "a) Ativar UFW"
        echo "b) Desativar UFW"
        echo "c) Parar e desabilitar firewalld"
        read -rp "Opção: " fo
        case "$fo" in
          a) ufw --force enable; ensure_ports_open; echo "UFW ativado." ;;
          b) ufw --force disable; echo "UFW desativado." ;;
          c) systemctl stop firewalld || true; systemctl disable firewalld || true; echo "firewalld desativado." ;;
        esac
        read -rp "Enter para continuar..." _ ;;
      8)
        echo "Listas UFW:"
        echo "a) Adicionar IP à whitelist (allow)"
        echo "b) Adicionar IP à blacklist (deny)"
        echo "c) Remover regra por número"
        echo "d) Listar regras numeradas"
        read -rp "Opção: " lo
        case "$lo" in
          a) read -rp "IP/CIDR para permitir: " ip; ufw allow from "$ip" || true ;;
          b) read -rp "IP/CIDR para negar: " ip; ufw deny from "$ip" || true ;;
          c) ufw status numbered; read -rp "Número da regra para deletar: " n; yes | ufw delete "$n" || true ;;
          d) ufw status numbered || true ;;
        esac
        read -rp "Enter para continuar..." _ ;;
      9)
        status_report
        echo
        echo "Ping/HTTP:"
        has_outbound_internet && echo "Internet de saída: OK" || echo "Internet de saída: FALHA"
        echo "Listening (ss):"; ss -lntup || true
        echo "UFW:"; ufw status verbose || true
        echo "nft:"; nft list ruleset || true
        read -rp "Enter para continuar..." _ ;;
      10)
        command -v speedtest >/dev/null 2>&1 && speedtest || speedtest-cli || true
        read -rp "Enter para continuar..." _ ;;
      11)
        install_self ;;
      12)
        ${EDITOR:-nano} "$ENV_FILE" ;;
      13)
        uninstall_self ;;
      14)
        apply_server_baseline; read -rp "Enter para continuar..." _ ;;
      15)
        ssh_set_restricted_mode; echo "Acesso emergencial fechado."; read -rp "Enter para continuar..." _ ;;
      0) exit 0 ;;
      *) echo "Opção inválida"; sleep 1 ;;
    esac
  done
}

# ------------- CLI -------------
case "${1:-}" in
  install) install_self ;;
  uninstall) uninstall_self ;;
  daemon) daemon_loop ;;
  backup-now) backup_snapshot "manual" ;;
  restore) restore_snapshot "${2:-}";;
  list-backups) list_backups ;;
  ensure-ports) ensure_ports_open ;;
  status) status_report ;;
  "") menu ;;
  *)
    cat <<EOF
$PROG v$VERSION
Uso: $0 [comando]

Comandos:
  install           Instala dependências, cria serviço e backup 0.0
  uninstall         Remove serviço/arquivos (mantém backups)
  daemon            Inicia o loop de monitoramento/backup (usado pelo systemd)
  backup-now        Executa backup imediato (snapshot)
  list-backups      Lista snapshots disponíveis
  restore <snap>    Restaura snapshot
  ensure-ports      Garante portas obrigatórias abertas
  status            Exibe diagnóstico atual com cores
  (sem argumento)   Interface interativa

Exemplos:
  $0 install
  $0
  systemctl enable --now $PROG.service

EOF
    ;;
esac
