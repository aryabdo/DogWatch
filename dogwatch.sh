#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="1.2.9"
PROG="dogwatch"

# ------------- Helpers -------------
say() { echo "[$PROG] $*"; }
ts() { date +"%Y-%m-%d %H:%M:%S"; }
log() {
  local level="${1:-INFO}"; shift || true
  local msg="$*"
  [[ "${LOG_LEVEL:-INFO}" == "DEBUG" || "$level" != "DEBUG" ]] || return 0
  local _dir="${LOG_DIR:-/var/log/dogwatch}"
  mkdir -p "$_dir"
  printf "%s [%s] %s\n" "$(ts)" "$level" "$msg" >> "$_dir/$PROG.log"
}
require_root() { if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then echo "Este script deve ser executado como root."; exit 1; fi; }
get_boot_id() { cat /proc/sys/kernel/random/boot_id 2>/dev/null; }

# ------------- Firewall detection -------------
detect_firewalls() {
  local detected=()
  command -v ufw >/dev/null 2>&1 && detected+=(ufw)
  systemctl list-unit-files 2>/dev/null | grep -q '^firewalld\.service' && detected+=(firewalld)
  command -v nft >/dev/null 2>&1 && detected+=(nftables)
  command -v iptables >/dev/null 2>&1 && detected+=(iptables)
  systemctl list-unit-files 2>/dev/null | grep -q '^shorewall\.service' && detected+=(shorewall)
  command -v csf >/dev/null 2>&1 && detected+=(csf)
  command -v ferm >/dev/null 2>&1 && detected+=(ferm)
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
  export DATA_DIR="${DATA_DIR:-$DATA_DIR_DEFAULT}"
  export BACKUP_DIR="${BACKUP_DIR:-$BACKUP_DIR_DEFAULT}"
  export LOG_DIR="${LOG_DIR:-$LOG_DIR_DEFAULT}"
  export STATE_DIR="${STATE_DIR:-$STATE_DIR_DEFAULT}"
  export LOG_LEVEL="${LOG_LEVEL:-INFO}"

  export PRIMARY_SSH_PORT="${PRIMARY_SSH_PORT:-16309}"
  export EMERGENCY_SSH_PORT="${EMERGENCY_SSH_PORT:-22}"
  export ALLOW_USERS="${ALLOW_USERS:-aasn}"

  export RESTORE_EMERGENCY_PORTS="${RESTORE_EMERGENCY_PORTS:-16309}"
  export EMERGENCY_WINDOW_ON_000="${EMERGENCY_WINDOW_ON_000:-1}"
  export REQUIRE_ICMP_AND_HTTP="${REQUIRE_ICMP_AND_HTTP:-1}"
  export REQUIRE_PUBLIC_REMOTE="${REQUIRE_PUBLIC_REMOTE:-1}"   # endurecido por padrão

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

  export FIREWALL_APPLY_RETRIES="${FIREWALL_APPLY_RETRIES:-10}"
  export FIREWALL_APPLY_INTERVAL="${FIREWALL_APPLY_INTERVAL:-1}"
  export ENFORCE_SINGLE_FIREWALL="${ENFORCE_SINGLE_FIREWALL:-ufw}"
  export HOLD_FIREWALLD="${HOLD_FIREWALLD:-1}"
  export SSH_PERMIT_ROOT="${SSH_PERMIT_ROOT:-no}"
  export SSH_PASSWORD_AUTH="${SSH_PASSWORD_AUTH:-no}"
  export REMOTE_ONLY_REPAIR="${REMOTE_ONLY_REPAIR:-1}"
  export REMOTE_ONLY_REPAIR_CYCLES="${REMOTE_ONLY_REPAIR_CYCLES:-3}"
  export RESTORE_AUTO_REBOOT="${RESTORE_AUTO_REBOOT:-1}"

  export AUTO_RESTORE_FIXED_IP="${AUTO_RESTORE_FIXED_IP:-1}"
  export FIXED_IP_RESTORE_MIN_INTERVAL="${FIXED_IP_RESTORE_MIN_INTERVAL:-900}"
  export NETPLAN_RESTORE_REVERT_SECONDS="${NETPLAN_RESTORE_REVERT_SECONDS:-180}"
  export INTERFACE_WATCH="${INTERFACE_WATCH:-}"

  [[ -f "$ENV_FILE" ]] && source "$ENV_FILE" || true

  EMERGENCY_TTL_HOURS="${EMERGENCY_TTL_HOURS:-12}"
  EMERGENCY_TTL_HOURS="${EMERGENCY_TTL_HOURS//[^0-9]/}"
  [[ -z "$EMERGENCY_TTL_HOURS" ]] && EMERGENCY_TTL_HOURS=12
  export EMERGENCY_TTL_HOURS

  detect_firewalls
  mkdir -p "$DATA_DIR" "$BACKUP_DIR" "$LOG_DIR" "$STATE_DIR"
  chmod 700 "$DATA_DIR" "$BACKUP_DIR" "$STATE_DIR" || true
}

# ------------- Linked services -------------
linked_services_list() {
  # Retorna lista de serviços vinculados que existem no host
  local candidates=(dogwatch.service ssh.service sshd.service ufw.service firewalld.service nftables.service NetworkManager.service systemd-networkd.service networking.service fail2ban.service)
  local svc
  for svc in "${candidates[@]}"; do
    systemctl list-unit-files | awk '{print $1}' | grep -qx "$svc" && echo "$svc"
  done
  # Instâncias de wg-quick@
  systemctl list-units --type=service --all 2>/dev/null | awk '/wg-quick@/{print $1}'
}
services_action() {
  local action="$1"
  mapfile -t _svcs < <(linked_services_list)
  for s in "${_svcs[@]}"; do
    systemctl "$action" "$s" >/dev/null 2>&1 || true
  done
  say "Ação '$action' aplicada a: ${_svcs[*]}"
}
print_service_statuses() {
  mapfile -t _svcs < <(linked_services_list)
  local s
  for s in "${_svcs[@]}"; do
    local en="$(systemctl is-enabled "$s" 2>/dev/null || echo unknown)"
    local ac="$(systemctl is-active "$s" 2>/dev/null || echo unknown)"
    printf " - %-28s  enabled=%-8s active=%s\n" "$s" "$en" "$ac"
  done
}

# ------------- Pending state -------------
set_pending_hash() {
  local hash="$1"
  local pending_file="$STATE_DIR/pending.hash"
  if [[ -f "$pending_file" ]] && [[ "$(cat "$pending_file" 2>/dev/null)" == "$hash" ]]; then return 0; fi
  if [[ "${STRICT_PENDING_CONNECTIVITY:-1}" == "1" ]]; then
    if ! connectivity_healthy; then log WARN "Alteração detectada, mas conectividade não está saudável; pendência não criada (aguardando saúde)."; return 1; fi
  fi
  echo "$hash" > "$pending_file"
  get_boot_id > "$STATE_DIR/pending.boot_id" || true
  log INFO "Configuração alterada detectada; aguardando promoção."
}
promote_pending_if_stable() {
  local pending_file="$STATE_DIR/pending.hash"
  [[ -f "$pending_file" ]] || return 0
  local streak; streak="$(cat "$STATE_DIR/normal_streak" 2>/dev/null || echo 0)"
  if (( streak >= PENDING_STABLE_CYCLES )); then
    cp "$pending_file" "$STATE_DIR/last_good.hash"
    rm -f "$pending_file" "$STATE_DIR/pending.boot_id" "$STATE_DIR/admin_ack"
    log INFO "Configuração pendente promovida automaticamente para last_good.hash."
  fi
}

# ------------- SSH config -------------
ensure_sshd_include() {
  local main="/etc/ssh/sshd_config" incdir="/etc/ssh/sshd_config.d"
  install -d -m 0755 "$incdir"
  sed -i '/^[[:space:]]*Include[[:space:]]\+\/etc\/ssh\/sshd_config\.d\/\*\.conf[[:space:]]*$/d' "$main"
  if grep -q '^[[:space:]]*Match[[:space:]]' "$main"; then
    local ln; ln="$(grep -n '^[[:space:]]*Match[[:space:]]' "$main" | head -n1 | cut -d: -f1)"
    sed -i "${ln}i Include /etc/ssh/sshd_config.d/*.conf" "$main"
  else
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$main"
  fi
  chmod 0644 "$main" 2>/dev/null || true
}
ssh_safe_reload() {
  local sshd_bin; sshd_bin="$(command -v sshd 2>/dev/null || true)"
  [[ -z "$sshd_bin" ]] && { log WARN "sshd não encontrado; reload abortado"; return 1; }
  if "$sshd_bin" -t 2>/dev/null; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || \
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
  else
    log WARN "sshd_config inválido; reload abortado"; return 1
  fi
}
ssh_set_dual_port_mode() {
  load_env; ensure_sshd_include
  cat > /etc/ssh/sshd_config.d/99-dogwatch.conf <<EOF
# Managed by dogwatch
Port $PRIMARY_SSH_PORT
Port $EMERGENCY_SSH_PORT
PasswordAuthentication ${SSH_PASSWORD_AUTH}
PermitRootLogin ${SSH_PERMIT_ROOT}
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::
EOF
  chmod 0644 /etc/ssh/sshd_config.d/99-dogwatch.conf
  ssh_safe_reload || true
  sleep 1
  if ss_port_listens "$PRIMARY_SSH_PORT" && ss_port_listens "$EMERGENCY_SSH_PORT"; then return 0; fi
  command -v sshd >/dev/null 2>&1 && { sshd -T 2>/dev/null | grep -E '^(port|listenaddress|addressfamily) ' | while read -r L; do log DEBUG "sshd -T: $L"; done; } || true
  log ERROR "Ainda não escuta em $PRIMARY_SSH_PORT e/ou $EMERGENCY_SSH_PORT"; return 1
}
ssh_set_permissive_mode() {
  local reason="$1"
  load_env; ensure_sshd_include
  cat > /etc/ssh/sshd_config.d/99-dogwatch.conf <<EOF
# Managed by dogwatch (permissive window)
Port $PRIMARY_SSH_PORT
Port $EMERGENCY_SSH_PORT
PasswordAuthentication yes
PermitRootLogin prohibit-password
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::
EOF
  salvage_open_ports "$PRIMARY_SSH_PORT $EMERGENCY_SSH_PORT"
  ssh_safe_reload || true
  echo "$(date +%s) $EMERGENCY_TTL_HOURS $reason" > "$STATE_DIR/ssh_permissive.mode"
  log WARN "Modo SSH permissivo ativado ($reason)"
}
ssh_set_restricted_mode() {
  load_env; ensure_sshd_include
  cat > /etc/ssh/sshd_config.d/99-dogwatch.conf <<EOF
# Managed by dogwatch (restricted)
Port $PRIMARY_SSH_PORT
PasswordAuthentication ${SSH_PASSWORD_AUTH}
PermitRootLogin ${SSH_PERMIT_ROOT}
EOF
  [[ -n "${ALLOW_USERS:-}" ]] && echo "AllowUsers $ALLOW_USERS" >> /etc/ssh/sshd_config.d/99-dogwatch.conf
  ssh_safe_reload || true
  for fw in $FIREWALLS; do
    case "$fw" in
      ufw) command -v ufw >/dev/null 2>&1 && LC_ALL=C LANG=C ufw delete allow "$EMERGENCY_SSH_PORT/tcp" >/dev/null 2>&1 || true ;;
      firewalld)
        if systemctl is-active --quiet firewalld 2>/dev/null; then firewall-cmd --remove-port="$EMERGENCY_SSH_PORT/tcp" --permanent 2>/dev/null || true; firewall-cmd --reload 2>/dev/null || true; fi ;;
      nftables) command -v nft >/dev/null 2>&1 && nft flush chain inet dogwatch input 2>/dev/null || true ;;
      iptables)
        command -v iptables >/dev/null 2>&1 && iptables -D INPUT -p tcp --dport "$EMERGENCY_SSH_PORT" -j ACCEPT 2>/dev/null || true
        command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true ;;
    esac
  done
  ensure_ports_open "$PRIMARY_SSH_PORT"
  rm -f "$STATE_DIR/ssh_permissive.mode" || true
  log INFO "Modo SSH restrito aplicado"
}
ssh_check_ttl_and_restrict_if_needed() {
  load_env
  local file="$STATE_DIR/ssh_permissive.mode"
  [[ -f "$file" ]] || return 0
  read -r start ttl reason < "$file"
  local now; now="$(date +%s)"
  local expire=$((start + ttl*3600))
  if (( now >= expire )); then log WARN "Janela permissiva expirada; aplicando modo restrito"; ssh_set_restricted_mode; fi
}

# ------------- Firewall / Port helpers -------------
wait_ufw_apply() {
  local ports="$*"; local tries="${FIREWALL_APPLY_RETRIES:-10}"; local int="${FIREWALL_APPLY_INTERVAL:-1}"
  local status ok p
  while (( tries-- > 0 )); do
    status="$(LC_ALL=C LANG=C ufw status 2>/dev/null || true)"; ok=1
    for p in $ports; do awk -v port="${p}/tcp" '($1==port || $1==port" (v6)") && $2 ~ /^ALLOW/ {f=1} END{exit !f}' <<<"$status" || { ok=0; break; }; done
    (( ok )) && return 0; sleep "$int"
  done
  return 1
}
init_nft_chain() {
  command -v nft >/dev/null 2>&1 || return 0
  mkdir -p /etc/nftables.d
  grep -q 'include "/etc/nftables.d/*.nft"' /etc/nftables.conf 2>/dev/null || echo 'include "/etc/nftables.d/*.nft"' >> /etc/nftables.conf
  nft list table inet dogwatch >/dev/null 2>&1 || { nft add table inet dogwatch 2>/dev/null || true; nft add chain inet dogwatch input '{ type filter hook input priority -300 ; policy accept; }' 2>/dev/null || true; }
  [[ -f /etc/nftables.d/dogwatch.nft ]] || cat > /etc/nftables.d/dogwatch.nft <<'EOF'
table inet dogwatch { chain input { type filter hook input priority -300; policy accept; } }
EOF
  systemctl list-unit-files 2>/dev/null | grep -q '^nftables\.service' && systemctl enable --now nftables >/dev/null 2>&1 || true
  nft -f /etc/nftables.conf >/dev/null 2>&1 || true
}
ss_port_listens() {
  local p="$1"
  ss -H -ltn "sport = :$p" 2>/dev/null | grep -q . && return 0
  ss -ltn 2>/dev/null | awk -v p="$p" '$1=="LISTEN"{gsub(/[\[\]]/,"",$4); if ($4 ~ (":" p "$") || $4 ~ ("\\." p "$")) {found=1; exit}} END{exit !found}' && return 0
  $NC_BIN -w2 -z 127.0.0.1 "$p" >/dev/null 2>&1 && return 0
  $NC_BIN -w2 -z ::1 "$p"       >/dev/null 2>&1 && return 0
  return 1
}
listening_on_ports() {
  local ports="$*"; local missing=()
  for p in $ports; do if ss_port_listens "$p"; then log DEBUG "Listening on $p"; else missing+=("$p"); fi; done
  if (( ${#missing[@]} )); then
    log DEBUG "Não está ouvindo em: ${missing[*]}"
    command -v sshd >/dev/null 2>&1 && { sshd -T 2>/dev/null | grep -E '^port ' | while read -r L; do log DEBUG "sshd -T: $L"; done; } || true
    echo "${missing[*]}"; return 1
  fi
  return 0
}
firewalld_allow_ports() {
  local ports="$*"
  command -v firewall-cmd >/dev/null 2>&1 || return 0
  systemctl is-active --quiet firewalld || return 0
  local p; for p in $ports; do firewall-cmd --add-port="${p}/tcp" >/dev/null 2>&1 || true; firewall-cmd --permanent --add-port="${p}/tcp" >/dev/null 2>&1 || true; done
  firewall-cmd --reload >/dev/null 2>&1 || true
}
firewall_allows_ports() {
  local ports="$*"; local blocked=(); local UFW_STATUS=""
  command -v ufw >/dev/null 2>&1 && UFW_STATUS="$(LC_ALL=C LANG=C ufw status 2>/dev/null || true)"
  local fw p
  for fw in $FIREWALLS; do
    case "$fw" in
      ufw)
        if command -v ufw >/dev/null 2>&1 && grep -q '^Status: active' <<< "$UFW_STATUS"; then
          for p in $ports; do awk -v port="${p}/tcp" '($1==port || $1==port" (v6)") && $2 ~ /^ALLOW/ {f=1} END{exit !f}' <<< "$UFW_STATUS" || blocked+=("$p"); done
        fi ;;
      firewalld)
        if systemctl is-active --quiet firewalld 2>/dev/null; then
          local plist_rt plist_pm; plist_rt="$(firewall-cmd --list-ports 2>/dev/null || true)"; plist_pm="$(firewall-cmd --permanent --list-ports 2>/dev/null || true)"
          for p in $ports; do
            if grep -q '^Status: active' <<< "$UFW_STATUS"; then awk -v port="${p}/tcp" '($1==port || $1==port" (v6)") && $2 ~ /^ALLOW/ {f=1} END{exit !f}' <<< "$UFW_STATUS" && continue; fi
            (grep -qw "${p}/tcp" <<< "$plist_rt" || grep -qw "${p}/tcp" <<< "$plist_pm") || blocked+=("$p")
          done
        fi ;;
      nftables)
        if command -v nft >/dev/null 2>&1; then
          local rules policy has_input_hook; rules="$(nft list ruleset 2>/dev/null || true)"; grep -q 'hook input' <<< "$rules" && has_input_hook=1 || has_input_hook=0
          policy="$(awk '$1=="chain"&&$2=="input"{inchain=1} inchain && /policy/{print tolower($0); exit}' <<< "$rules")"
          if [[ $has_input_hook -eq 1 ]] && grep -Eq 'policy[[:space:]]+(drop|reject)' <<< "$policy"; then
            for p in $ports; do
              if grep -q '^Status: active' <<< "$UFW_STATUS"; then awk -v port="${p}/tcp" '($1==port || $1==port" (v6)") && $2 ~ /^ALLOW/ {f=1} END{exit !f}' <<< "$UFW_STATUS" && continue; fi
              grep -qwE "tcp[[:space:]]+dport[[:space:]]+$p[[:space:]].*(accept|counter accept)" <<< "$rules" || blocked+=("$p")
            done
          fi
        fi ;;
      iptables)
        if command -v iptables-save >/dev/null 2>&1; then
          local save pol; save="$(iptables-save 2>/dev/null || true)"
          pol="$(iptables -L INPUT -n 2>/dev/null | sed -n 's/^Chain INPUT (policy \([A-Z]*\)).*/\1/p')"
          if [[ "$pol" == "DROP" || "$pol" == "REJECT" ]]; then
            for p in $ports; do
              if grep -q '^Status: active' <<< "$UFW_STATUS"; then awk -v port="${p}/tcp" '($1==port || $1==port" (v6)") && $2 ~ /^ALLOW/ {f=1} END{exit !f}' <<< "$UFW_STATUS" && continue; fi
              grep -Eq -- "--dport[[:space:]]+$p\b.*-j[[:space:]]+ACCEPT" <<< "$save" || blocked+=("$p")
            done
          fi
        fi ;;
    esac
  done
  (( ${#blocked[@]} )) && { log DEBUG "Portas potencialmente bloqueadas nos firewalls: ${blocked[*]}"; return 1; }
  return 0
}

# salva-vidas multi-camada (evita lockout)
salvage_open_ports() {
  local ports="$(echo $*)"
  if command -v ufw >/dev/null 2>&1; then
    LC_ALL=C LANG=C ufw --force enable >/dev/null 2>&1 || true
    local p; for p in $ports; do LC_ALL=C LANG=C ufw allow "$p/tcp" >/dev/null 2>&1 || true; done
  fi
  firewalld_allow_ports "$ports"
  if command -v nft >/dev/null 2>&1; then
    init_nft_chain
    local p; for p in $ports; do nft list chain inet dogwatch input 2>/dev/null | grep -qw "tcp dport $p accept" || nft add rule inet dogwatch input tcp dport "$p" accept >/dev/null 2>&1 || true; done
    nft -f /etc/nftables.conf >/dev/null 2>&1 || true
  fi
  if command -v iptables >/dev/null 2>&1; then
    local p; for p in $ports; do iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport "$p" -j ACCEPT || true; done
    command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
  fi
}

_ENSURE_PORTS_GUARD=0
ensure_ports_open() {
  load_env
  local ports="${*:-${MANDATORY_OPEN_PORTS} ${EXTRA_PORTS}}"; ports="$(echo $ports)"
  [[ "${_ENSURE_PORTS_GUARD:-0}" == "1" ]] && { log DEBUG "ensure_ports_open guard ativo"; return 0; }
  _ENSURE_PORTS_GUARD=1
  local fw p
  for fw in $FIREWALLS; do
    case "$fw" in
      ufw)
        if command -v ufw >/dev/null 2>&1; then
          hash -r; LC_ALL=C LANG=C ufw --force enable >/dev/null 2>&1 || true
          for p in $ports; do LC_ALL=C LANG=C ufw allow "$p/tcp" >/dev/null 2>&1 || true; done
          wait_ufw_apply $ports || log WARN "UFW ainda não refletiu todas as regras; prosseguindo"
        fi ;;
      firewalld) systemctl is-active --quiet firewalld 2>/dev/null && firewalld_allow_ports "$ports" ;;
      nftables)
        if command -v nft >/dev/null 2>&1; then
          init_nft_chain; local rules=""
          for p in $ports; do
            nft list chain inet dogwatch input 2>/dev/null | grep -qw "tcp dport $p accept" || nft add rule inet dogwatch input tcp dport "$p" accept >/dev/null 2>&1 || true
            rules+="    tcp dport $p accept\n"
          done
          { echo "table inet dogwatch {"; echo "  chain input {"; echo "    type filter hook input priority -300; policy accept;"; printf "%b" "$rules"; echo "  }"; echo "}"; } > /etc/nftables.d/dogwatch.nft
          nft -f /etc/nftables.conf >/dev/null 2>&1 || true
        fi ;;
      iptables)
        if command -v iptables >/dev/null 2>&1; then
          for p in $ports; do iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport "$p" -j ACCEPT || true; done
          command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
        fi ;;
    esac
  done
  post_firewall_apply_verify || true
  _ENSURE_PORTS_GUARD=0
}
safe_disable_firewalls() {
  local fw
  for fw in $FIREWALLS; do
    case "$fw" in
      ufw) command -v ufw >/dev/null 2>&1 && LC_ALL=C LANG=C ufw --force disable || true ;;
      firewalld)
        if systemctl is-active --quiet firewalld 2>/dev/null; then systemctl stop firewalld || true; systemctl disable firewalld || true; systemctl mask firewalld || true; fi ;;
      nftables)
        if command -v nft >/dev/null 2>&1; then
          local rules; rules="$(nft list ruleset 2>/dev/null || true)"
          if grep -q 'hook input' <<< "$rules" && grep -Eq 'policy[[:space:]]+(drop|reject)' <<< "$rules"; then
            nft -f <(echo 'table inet dogwatch { chain input { type filter hook input priority -300; policy accept; } }') 2>/dev/null || true
          fi
          nft delete table inet dogwatch 2>/dev/null || true
        fi ;;
      iptables)
        if command -v iptables >/dev/null 2>&1; then
          iptables -P INPUT ACCEPT 2>/dev/null || true; iptables -P FORWARD ACCEPT 2>/dev/null || true; iptables -P OUTPUT ACCEPT 2>/dev/null || true; iptables -F 2>/dev/null || true
        fi ;;
    esac
  done
}
post_firewall_apply_verify() {
  load_env
  local ports="$(echo "${MANDATORY_OPEN_PORTS} ${EXTRA_PORTS}")"
  if listening_on_ports $ports >/dev/null 2>&1; then
    has_remote_access; local rc=$?
    if [[ $rc -eq 0 || $rc -eq 2 ]]; then log INFO "Verificação pós-firewall: acesso remoto OK"; return 0; fi
  fi
  log WARN "Verificação pós-firewall falhou; aplicando salvaguardas"
  salvage_open_ports "$PRIMARY_SSH_PORT $EMERGENCY_SSH_PORT"
  ssh_set_permissive_mode "pós-firewall-falha"
  return 1
}

# ------------- Install/Uninstall -------------
enforce_primary_ssh_port_early() {
  load_env; say "Configurando SSH para porta ${PRIMARY_SSH_PORT} (e ${EMERGENCY_SSH_PORT})…"
  ensure_sshd_include
  cat > /etc/ssh/sshd_config.d/99-dogwatch.conf <<EOF
# Managed by dogwatch (early)
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::
Port ${PRIMARY_SSH_PORT}
Port ${EMERGENCY_SSH_PORT}
PasswordAuthentication ${SSH_PASSWORD_AUTH}
PermitRootLogin ${SSH_PERMIT_ROOT}
EOF
  chmod 0644 /etc/ssh/sshd_config.d/99-dogwatch.conf || true
  if command -v semanage >/dev/null 2>&1; then semanage port -a -t ssh_port_t -p tcp "${PRIMARY_SSH_PORT}" 2>/dev/null || semanage port -m -t ssh_port_t -p tcp "${PRIMARY_SSH_PORT}" 2>/dev/null || true; fi
  systemctl list-unit-files | grep -q '^ssh\.socket' && systemctl disable --now ssh.socket >/dev/null 2>&1 || true
  systemctl daemon-reload || true
  systemctl list-unit-files | grep -q '^ssh\.service'  && { systemctl enable --now ssh  >/dev/null 2>&1 || true; systemctl restart ssh  >/dev/null 2>&1 || true; }
  systemctl list-unit-files | grep -q '^sshd\.service' && { systemctl enable --now sshd >/dev/null 2>&1 || true; systemctl restart sshd >/dev/null 2>&1 || true; }
  ssh_safe_reload || true
  for i in {1..10}; do if ss_port_listens "$PRIMARY_SSH_PORT"; then log INFO "sshd escutando em ${PRIMARY_SSH_PORT}"; return 0; fi; sleep 1; done
  log ERROR "sshd NÃO está escutando em ${PRIMARY_SSH_PORT}"; return 1
}
enforce_single_firewall() {
  load_env
  case "${ENFORCE_SINGLE_FIREWALL:-ufw}" in
    ufw)
      systemctl stop firewalld >/dev/null 2>&1 || true; systemctl disable firewalld >/dev/null 2>&1 || true; systemctl mask firewalld >/dev/null 2>&1 || true
      [[ "${HOLD_FIREWALLD:-1}" == "1" ]] && apt-mark hold firewalld >/dev/null 2>&1 || true
      command -v ufw >/dev/null 2>&1 && LC_ALL=C LANG=C ufw --force enable >/dev/null 2>&1 || true ;;
    firewalld)
      command -v ufw >/dev/null 2>&1 && LC_ALL=C LANG=C ufw --force disable >/dev/null 2>&1 || true
      systemctl enable --now firewalld >/dev/null 2>&1 || true
      firewalld_allow_ports "${PRIMARY_SSH_PORT} ${EMERGENCY_SSH_PORT}" ;;
    none) : ;;
  esac
}
install_pkgs() {
  local pkgs=("$@"); local attempt=0
  while (( attempt < 2 )); do
    local args=(install -y --no-install-recommends); (( attempt == 1 )) && args+=(--reinstall)
    DEBIAN_FRONTEND=noninteractive apt-get "${args[@]}" "${pkgs[@]}" >/dev/null && return 0
    attempt=$((attempt+1)); sleep 5
  done; return 1
}
install_self() {
  require_root; load_env
  say "Instalando dependências..."
  local virt; virt="$(systemd-detect-virt 2>/dev/null || echo unknown)"
  [[ "$virt" != "none" ]] && log WARN "Ambiente virtual detectado ($virt); prosseguindo mesmo assim"
  DEBIAN_FRONTEND=noninteractive apt-get update -y || true
  install_pkgs curl jq rsync netcat-openbsd iproute2 ufw nftables iptables openssh-server || log WARN "Falha ao instalar pacotes base"
  install_pkgs wireguard-tools rclone ddclient dnsutils lsof nmap speedtest-cli iptables-persistent || log WARN "Falha ao instalar pacotes extras"
  enforce_single_firewall || true
  enforce_primary_ssh_port_early
  ensure_ports_open "$PRIMARY_SSH_PORT $EMERGENCY_SSH_PORT"

  say "Instalando arquivos..."
  mkdir -p "$DATA_DIR"
  install -m 0755 "$(readlink -f "${BASH_SOURCE[0]}")" "$DATA_DIR/$PROG.sh"
  log INFO "Instalado $PROG v$VERSION em $DATA_DIR/$PROG.sh"

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
REQUIRE_PUBLIC_REMOTE=1
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
ENFORCE_SINGLE_FIREWALL="ufw"
HOLD_FIREWALLD=1
FIREWALL_APPLY_RETRIES=10
FIREWALL_APPLY_INTERVAL=1
SSH_PERMIT_ROOT="no"
SSH_PASSWORD_AUTH="no"
RESTORE_AUTO_REBOOT=1
REMOTE_ONLY_REPAIR=1
REMOTE_ONLY_REPAIR_CYCLES=3
AUTO_RESTORE_FIXED_IP=1
FIXED_IP_RESTORE_MIN_INTERVAL=900
NETPLAN_RESTORE_REVERT_SECONDS=180
# INTERFACE_WATCH=""
EOF
  fi

  if [[ -d /etc/fail2ban ]]; then
    mkdir -p /etc/fail2ban/jail.d
    if command -v crudini >/dev/null 2>&1; then
      crudini --set /etc/fail2ban/jail.d/dogwatch.local sshd port "$PRIMARY_SSH_PORT" >/dev/null 2>&1 || true
    else
      cat > /etc/fail2ban/jail.d/dogwatch.local <<EOF
[sshd]
port=${PRIMARY_SSH_PORT}
EOF
    fi
    systemctl restart fail2ban >/dev/null 2>&1 || true
  fi

  if [[ -f "./$PROG.service" ]]; then
    install -m 0644 "./$PROG.service" "/etc/systemd/system/$PROG.service"
  else
    cat >"/etc/systemd/system/$PROG.service" <<'UNIT'
[Unit]
Description=DogWatch daemon
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/opt/dogwatch/dogwatch.sh daemon
Restart=always
RestartSec=3
User=root
[Install]
WantedBy=multi-user.target
UNIT
  fi

  systemctl daemon-reload
  systemctl enable --now "$PROG.service" || true

  say "Criando backup inicial 0.0..."
  first_run_bootstrap

  say "Instalação concluída."
  say "Serviço iniciado."
}
uninstall_self() {
  require_root; load_env
  say "Parando serviço..."; systemctl disable --now "$PROG.service" || true
  rm -f "/etc/systemd/system/$PROG.service"; systemctl daemon-reload
  say "Removendo arquivos (mantendo backups em $BACKUP_DIR)..."
  rm -f "$DATA_DIR/$PROG.sh" "$ENV_FILE" 2>/dev/null || true
  rm -rf "$STATE_DIR" "$LOG_DIR" 2>/dev/null || true
  say "Pronto. Backups preservados em: $BACKUP_DIR"
}

# ------------- Backup/Restore -------------
backup_items_list() {
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
  cat <<'EOF'
ip a
ip r
ss -lntup
$SYSCTL_BIN -a
LC_ALL=C LANG=C ufw status verbose || true
nft list ruleset || true
iptables-save || true
systemctl status ssh --no-pager || true
systemctl status ufw --no-pager || true
systemctl status firewalld --no-pager || true
systemctl status wg-quick@* --no-pager || true
EOF
}
backup_snapshot() {
  require_root; load_env
  local label="${1:-auto}"
  local stamp; stamp="$(date +'%Y%m%d-%H%M%S')"
  local dir="$BACKUP_DIR/$stamp-$label"
  mkdir -p "$dir/files" "$dir/cmd" "$dir/meta"
  while read -r item; do
    [[ -z "$item" ]] && continue
    if [[ -e "$item" || "$item" == *"*"* ]]; then rsync -aR --delete --relative $item "$dir/files/" 2>/dev/null || true; fi
  done < <(backup_items_list)
  while read -r cmd; do [[ -z "$cmd" ]] && continue; sh -c "$cmd" > "$dir/cmd/$(echo "$cmd" | tr ' /@*' '____').txt" 2>&1 || true; done < <(snapshot_commands)
  (uname -a; lsb_release -a 2>/dev/null || true; date) > "$dir/meta/system.txt"
  (command -v curl >/dev/null 2>&1 && { curl -s https://api.ipify.org || true; echo; }) > "$dir/meta/public_ip.txt" || true
  echo "$VERSION" > "$dir/meta/$PROG.version"
  rotate_backups
  echo "$dir"
}
rotate_backups() {
  local keep="$MAX_ROTATING_BACKUPS"
  mapfile -t snaps < <(find "$BACKUP_DIR" -maxdepth 1 -type d -printf "%P\n" | sort -r)
  local count=0
  for s in "${snaps[@]}"; do
    [[ "$s" == "000-initial" || -z "$s" ]] && continue
    count=$((count+1)); if (( count > keep )); then rm -rf "$BACKUP_DIR/$s" || true; fi
  done
}
first_run_bootstrap() {
  load_env
  if [[ ! -d "$BACKUP_DIR/000-initial" ]]; then
    mkdir -p "$BACKUP_DIR/000-initial"
    local path; path="$(backup_snapshot "backup-0.0")"
    shopt -s dotglob; mv "$path"/* "$BACKUP_DIR/000-initial"/ 2>/dev/null || true; rmdir "$path" || true; shopt -u dotglob
    log INFO "Backup 0.0 criado em $BACKUP_DIR/000-initial"
  else
    log DEBUG "Backup 0.0 já existe."
  fi
  compute_current_hash > "$STATE_DIR/last_good.hash" || true
}
list_backups() { load_env; find "$BACKUP_DIR" -maxdepth 1 -mindepth 1 -type d -printf "%P\n" | sort; }
restore_snapshot() {
  require_root; load_env
  local snap="$1"; local dir="$BACKUP_DIR/$snap"
  if [[ ! -d "$dir" ]]; then echo "Snapshot não encontrado: $snap"; exit 1; fi
  log INFO "Restaurando snapshot: $snap"
  safe_disable_firewalls
  rsync -a "$dir/files"/ / 2>/dev/null || true

  # Restaurar explicitamente o 90-dogwatch-static.yaml (qualquer caso)
  if [[ -f "$dir/files/etc/netplan/90-dogwatch-static.yaml" ]]; then
    install -m 0600 "$dir/files/etc/netplan/90-dogwatch-static.yaml" "/etc/netplan/90-dogwatch-static.yaml"
  else
    # tenta a partir do 000-initial, se existir
    if [[ -f "$BACKUP_DIR/000-initial/files/etc/netplan/90-dogwatch-static.yaml" ]]; then
      install -m 0600 "$BACKUP_DIR/000-initial/files/etc/netplan/90-dogwatch-static.yaml" "/etc/netplan/90-dogwatch-static.yaml"
    fi
  fi

  if command -v netplan >/dev/null 2>&1; then netplan generate >/dev/null 2>&1 || true; netplan apply || true; fi
  systemctl restart systemd-networkd 2>/dev/null || true
  systemctl restart NetworkManager 2>/dev/null || true
  systemctl restart networking 2>/dev/null || true

  reset_remote_access
  if [[ "$snap" == "000-initial" && "$EMERGENCY_WINDOW_ON_000" == "1" ]]; then
    salvage_open_ports "$PRIMARY_SSH_PORT $RESTORE_EMERGENCY_PORTS $EMERGENCY_SSH_PORT"
  else
    salvage_open_ports "$RESTORE_EMERGENCY_PORTS"
  fi
  if [[ "${RESTORE_AUTO_REBOOT:-1}" == "1" ]]; then log INFO "Reiniciando servidor..."; sleep 20; reboot
  else log INFO "Restauração aplicada. Reinicie manualmente para completar."; fi
}
compute_current_hash() {
  local tmp; tmp="$(mktemp)"
  while read -r item; do
    [[ -z "$item" ]] && continue
    if [[ -e "$item" ]]; then find "$item" -type f -print0 2>/dev/null | sort -z | xargs -0 sha256sum 2>/dev/null; fi
  done < <(backup_items_list) >> "$tmp" 2>/dev/null || true
  { LC_ALL=C LANG=C ufw status verbose 2>/dev/null || true; nft list ruleset 2>/dev/null || true; iptables-save 2>/dev/null || true; ss -lntup 2>/dev/null || true; ip a 2>/dev/null || true; ip r 2>/dev/null || true; } >> "$tmp" 2>/dev/null
  sha256sum "$tmp" | awk '{print $1}'; rm -f "$tmp"
}
reset_remote_access() {
  load_env; ensure_sshd_include
  cat > /etc/ssh/sshd_config.d/99-dogwatch.conf <<EOF
Port $PRIMARY_SSH_PORT
Port $EMERGENCY_SSH_PORT
PasswordAuthentication ${SSH_PASSWORD_AUTH}
PermitRootLogin ${SSH_PERMIT_ROOT}
EOF
  : > /etc/hosts.deny || true
  command -v fail2ban-client >/dev/null 2>&1 && fail2ban-client unban --all || true
  command -v passwd >/dev/null 2>&1 && passwd -u root 2>/dev/null || true
  local fw
  for fw in $FIREWALLS; do
    case "$fw" in
      ufw) command -v ufw >/dev/null 2>&1 && LC_ALL=C LANG=C ufw --force reset || true ;;
      firewalld)
        if systemctl is-active --quiet firewalld 2>/dev/null; then firewall-cmd --permanent --delete-all-rich-rules 2>/dev/null || true; firewall-cmd --permanent --delete-all-rules 2>/dev/null || true; firewall-cmd --reload 2>/dev/null || true; fi ;;
      nftables) command -v nft >/dev/null 2>&1 && nft flush chain inet dogwatch input 2>/dev/null || true ;;
      iptables)
        if command -v iptables >/dev/null 2>&1; then iptables -P INPUT ACCEPT 2>/dev/null || true; iptables -F 2>/dev/null || true; command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true; fi ;;
    esac
  done
  salvage_open_ports "$PRIMARY_SSH_PORT $EMERGENCY_SSH_PORT"
  ssh_safe_reload || true
}

# ------------- Connectivity -------------
try_public_ip() {
  local ip
  for svc in "${PUBLIC_IP_SERVICE}" https://ifconfig.co https://api.ipify.org https://ipecho.net/plain; do
    ip="$($CURL_BIN -fsS "$svc" 2>/dev/null | tr -d '\r\n' || true)"; [[ -n "$ip" ]] && { echo "$ip"; return 0; }
  done; return 1
}
has_outbound_internet() {
  local ping_ok=1 http_ok=1
  local ip; for ip in $PING_TARGETS; do for _ in {1..3}; do if ping -c1 -W1 "$ip" >/dev/null 2>&1; then log DEBUG "Ping OK: $ip"; ping_ok=0; break 2; fi; done; done
  local url; for url in $HTTP_TARGETS; do for _ in {1..3}; do local output status body; output="$($CURL_BIN -m3 -sS "$url" -w 'HTTPSTATUS:%{http_code}' 2>/dev/null)"; status="${output##*HTTPSTATUS:}"; body="${output%HTTPSTATUS:*}"; if [[ -n "$body" && "$status" =~ ^[0-9]+$ && "$status" -lt 400 ]]; then log DEBUG "HTTP OK: $url ($status)"; http_ok=0; break 2; fi; done; done
  if [[ "${REQUIRE_ICMP_AND_HTTP:-1}" == "1" ]]; then [[ $ping_ok -eq 0 && $http_ok -eq 0 ]]; else [[ $ping_ok -eq 0 || $http_ok -eq 0 ]]; fi
}

# Hairpin-aware public check
has_remote_access() {
  local ip require_public ports candidates used_fallback=0
  require_public="${REQUIRE_PUBLIC_REMOTE:-1}"
  ip="$(try_public_ip || echo)"
  ports="$MANDATORY_OPEN_PORTS"; ports="$(echo $ports)"
  if [[ "$require_public" != "1" ]]; then
    candidates=(127.0.0.1); while IFS= read -r addr; do [[ -n "$addr" ]] && candidates+=("$addr"); done < <(ip -o -4 addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
  fi
  local p; for p in $ports; do
    if [[ -n "$ip" ]] && $NC_BIN -w2 -z "$ip" "$p" >/dev/null 2>&1; then
      if [[ "$require_public" == "1" ]]; then
        local src; src="$(ip -4 route get "$ip" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1)}}')"
        if [[ "$src" =~ ^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then log WARN "Conexão ao IP público $ip via origem privada $src (hairpin NAT) — NÃO considerar sucesso público."; return 2; fi
      fi
      log DEBUG "Porta remota OK: $ip:$p"; continue
    fi
    if [[ "$require_public" == "1" ]]; then log DEBUG "Porta remota falhou: $ip:$p"; return 1; fi
    local candidate; for candidate in "${candidates[@]}"; do if $NC_BIN -w2 -z "$candidate" "$p" >/dev/null 2>&1; then log DEBUG "Porta local OK (fallback): $candidate:$p"; used_fallback=1; continue 2; fi; done
    log DEBUG "Porta remota falhou: $ip:$p"; return 1
  done
  (( used_fallback )) && { log WARN "Possível hairpin NAT – acesso externo pode estar bloqueado"; return 2; }
  return 0
}
connectivity_healthy() {
  local ports="$MANDATORY_OPEN_PORTS"; ports="$(echo $ports)"
  has_outbound_internet || return 1
  listening_on_ports $ports >/dev/null || return 1
  has_remote_access || return 1
  return 0
}

# ------------- Estado -------------
detect_external_vs_internal() {
  local ports="$(echo $MANDATORY_OPEN_PORTS)"; ports="$(echo $ports)"
  if has_outbound_internet; then
    local missing=""; if ! missing=$(listening_on_ports $ports); then : ; else missing=""; fi
    has_remote_access; local rc=$?
    if [[ $rc -eq 0 ]]; then echo "normal"; return 2
    elif [[ $rc -eq 2 ]]; then echo "degradado"; return 3
    else
      if [[ -n "$missing" ]]; then echo "internal"; return 1; fi
      echo "external"; return 0
    fi
  else
    if listening_on_ports $ports >/dev/null 2>&1 && ss_port_listens "$PRIMARY_SSH_PORT"; then echo "external"; return 0; fi
    echo "internal"; return 1
  fi
}

# ------------- IP fixo: detecção & restauração -------------
default_iface() { ip route | awk '/default/ {print $5; exit}'; }
default_cidr() { local ifc="${1:-$(default_iface || true)}"; ip -o -4 addr show dev "$ifc" 2>/dev/null | awk '{print $4}' | head -n1; }
record_default_ip_state() { load_env; local ifc cidr; [[ -n "$INTERFACE_WATCH" ]] && ifc="$INTERFACE_WATCH" || ifc="$(default_iface || true)"; cidr="$(default_cidr "$ifc" || true)"; echo "${ifc:-none} ${cidr:-none}" > "$STATE_DIR/last_default_ip.txt"; }
default_ip_changed() {
  load_env; local ifc_now cidr_now; [[ -n "$INTERFACE_WATCH" ]] && ifc_now="$INTERFACE_WATCH" || ifc_now="$(default_iface || true)"; cidr_now="$(default_cidr "$ifc_now" || true)"
  if [[ ! -f "$STATE_DIR/last_default_ip.txt" ]]; then echo "first-sample"; return 2; fi
  local ifc_old cidr_old; read -r ifc_old cidr_old < "$STATE_DIR/last_default_ip.txt" || true
  if [[ "$ifc_now" != "$ifc_old" || "$cidr_now" != "$cidr_old" ]]; then echo "$ifc_old $cidr_old -> $ifc_now $cidr_now"; return 0; fi
  return 1
}
find_latest_netcfg_snapshot() {
  load_env; mapfile -t snaps < <(find "$BACKUP_DIR" -maxdepth 1 -mindepth 1 -type d -printf "%P\n" | sort -r)
  local s; for s in "${snaps[@]}"; do [[ -d "$BACKUP_DIR/$s/files/etc/netplan" || -d "$BACKUP_DIR/$s/files/etc/NetworkManager" || -d "$BACKUP_DIR/$s/files/etc/network" ]] && { echo "$BACKUP_DIR/$s"; return 0; }; done
  if [[ -d "$BACKUP_DIR/000-initial/files/etc/netplan" || -d "$BACKUP_DIR/000-initial/files/etc/NetworkManager" || -d "$BACKUP_DIR/000-initial/files/etc/network" ]]; then echo "$BACKUP_DIR/000-initial"; return 0; fi
  return 1
}
remote_success_guard() { load_env; has_outbound_internet || return 1; listening_on_ports "$PRIMARY_SSH_PORT" >/dev/null || return 1; has_remote_access; local rc=$?; [[ $rc -eq 0 ]]; }

restore_fixed_ip_from_backup() {
  load_env
  local snap; snap="$(find_latest_netcfg_snapshot)" || { log WARN "Nenhum snapshot com config de rede encontrado."; return 1; }
  rm -rf "$STATE_DIR/netplan-rollback" || true; mkdir -p "$STATE_DIR/netplan-rollback"
  rsync -a --delete /etc/netplan/ "$STATE_DIR/netplan-rollback/netplan/" 2>/dev/null || true
  rsync -a --delete /etc/NetworkManager/ "$STATE_DIR/netplan-rollback/NetworkManager/" 2>/dev/null || true
  rsync -a --delete /etc/network/ "$STATE_DIR/netplan-rollback/etc-network/" 2>/dev/null || true

  salvage_open_ports "$PRIMARY_SSH_PORT $EMERGENCY_SSH_PORT"

  [[ -d "$snap/files/etc/netplan" ]]        && rsync -a "$snap/files/etc/netplan/"/ /etc/netplan/ 2>/dev/null || true
  [[ -d "$snap/files/etc/NetworkManager" ]] && rsync -a "$snap/files/etc/NetworkManager/"/ /etc/NetworkManager/ 2>/dev/null || true
  [[ -d "$snap/files/etc/network" ]]        && rsync -a "$snap/files/etc/network/"/ /etc/network/ 2>/dev/null || true

  # Garantir 90-dogwatch-static.yaml e perms
  if [[ -f "$snap/files/etc/netplan/90-dogwatch-static.yaml" ]]; then
    install -m 0600 "$snap/files/etc/netplan/90-dogwatch-static.yaml" "/etc/netplan/90-dogwatch-static.yaml"
  fi

  if command -v netplan >/dev/null 2>&1; then netplan generate >/dev/null 2>&1 || true; netplan apply || true; fi
  systemctl restart NetworkManager 2>/dev/null || true
  systemctl restart networking 2>/dev/null || true
  systemctl restart systemd-networkd 2>/dev/null || true

  local guard="$DATA_DIR/netplan-revert.sh"
  cat > "$guard" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
STATE_DIR="/opt/dogwatch/state"
if [[ -d "$STATE_DIR/netplan-rollback" ]]; then
  rsync -a "$STATE_DIR/netplan-rollback/netplan/"/ /etc/netplan/ 2>/dev/null || true
  rsync -a "$STATE_DIR/netplan-rollback/NetworkManager/"/ /etc/NetworkManager/ 2>/dev/null || true
  rsync -a "$STATE_DIR/netplan-rollback/etc-network/"/ /etc/network/ 2>/dev/null || true
  if command -v netplan >/dev/null 2>&1; then netplan generate >/dev/null 2>&1 || true; netplan apply || true; fi
  systemctl restart NetworkManager 2>/dev/null || true
  systemctl restart networking 2>/dev/null || true
  systemctl restart systemd-networkd 2>/dev/null || true
fi
logger -t dogwatch "Rollback de Netplan executado a partir do backup em $STATE_DIR/netplan-rollback"
SH
  chmod +x "$guard"

  if command -v systemd-run >/dev/null 2>&1; then systemd-run --unit=dogwatch-netplan-revert --on-active="${NETPLAN_RESTORE_REVERT_SECONDS}s" "$guard" >/dev/null 2>&1 || true
  else nohup bash -c "sleep ${NETPLAN_RESTORE_REVERT_SECONDS}; \"$guard\"" >/dev/null 2>&1 & fi

  sleep 8
  if remote_success_guard; then
    systemctl stop dogwatch-netplan-revert.service >/dev/null 2>&1 || true
    rm -rf "$STATE_DIR/netplan-rollback" || true
    record_default_ip_state
    log INFO "Restauração do IP fixo concluída com SUCESSO PÚBLICO; rollback cancelado."
    ssh_set_restricted_mode || true
    return 0
  else
    log WARN "Acesso público não validado. Rollback automático em ${NETPLAN_RESTORE_REVERT_SECONDS}s permanece ativo."
    return 1
  fi
}

# ------------- Queue / finalize -------------
setup_restore_queue() {
  load_env
  mapfile -t snaps < <(find "$BACKUP_DIR" -maxdepth 1 -mindepth 1 -type d -printf "%P\n" | sort -r)
  snaps_sorted=(); local s; for s in "${snaps[@]}"; do [[ "$s" != "000-initial" ]] && snaps_sorted+=("$s"); done
  snaps_sorted+=("000-initial")
  printf "%s\n" "${snaps_sorted[@]}" > "$STATE_DIR/restore_queue.txt"
  echo 0 > "$STATE_DIR/restore_index"
}
attempt_restore_queue() {
  load_env; [[ -f "$STATE_DIR/restore_queue.txt" ]] || setup_restore_queue
  local idx total snap; idx="$(cat "$STATE_DIR/restore_index" 2>/dev/null || echo 0)"; total="$(wc -l < "$STATE_DIR/restore_queue.txt")"
  if (( idx >= total )); then log WARN "Fila de restauração esgotada."; rm -f "$STATE_DIR/restore_queue.txt" "$STATE_DIR/restore_index"; return 1; fi
  snap="$(sed -n "$((idx+1))p" "$STATE_DIR/restore_queue.txt")"
  log INFO "Tentando restauração: $snap"
  if [[ "$snap" == "000-initial" && "$EMERGENCY_WINDOW_ON_000" == "1" ]]; then ssh_set_permissive_mode "000-initial" || true; salvage_open_ports "$PRIMARY_SSH_PORT $RESTORE_EMERGENCY_PORTS $EMERGENCY_SSH_PORT"
  else salvage_open_ports "$RESTORE_EMERGENCY_PORTS"; fi
  echo $((idx+1)) > "$STATE_DIR/restore_index"
  restore_snapshot "$snap"
}
finalize_restore_queue() {
  load_env
  if [[ -f "$STATE_DIR/restore_queue.txt" ]]; then
    if has_outbound_internet; then
      compute_current_hash > "$STATE_DIR/last_good.hash" || true
      rm -f "$STATE_DIR/restore_queue.txt" "$STATE_DIR/restore_index"
      log INFO "Fila de restauração finalizada e resetada após estabilização"
      [[ "${STOP_SERVICE_ON_SUCCESS:-0}" == "1" ]] && systemctl disable --now "$PROG.service" || true
    fi
  fi
}

# ------------- Status -------------
status_report() {
  load_env
  local green='\033[32m' yellow='\033[33m' red='\033[31m' reset='\033[0m'
  echo -e "Serviços vinculados:"
  print_service_statuses
  if ! systemctl is-active --quiet "$PROG.service" 2>/dev/null; then echo -e "${yellow}Atenção: daemon $PROG não está ativo — restauração automática NÃO ocorrerá.${reset}"; fi

  local listen_ports="${MANDATORY_OPEN_PORTS}"; listen_ports="$(echo $listen_ports)"
  local fw_ports="${MANDATORY_OPEN_PORTS} ${EXTRA_PORTS}"; fw_ports="$(echo $fw_ports)"

  [[ -f "$STATE_DIR/pending.hash" ]] && echo -e "${yellow}Configuração pendente: aguardando estabilização${reset}"

  if [[ -f "$STATE_DIR/restore_queue.txt" ]]; then
    local idx total next; idx="$(cat "$STATE_DIR/restore_index" 2>/dev/null || echo 0)"; total="$(wc -l < "$STATE_DIR/restore_queue.txt" 2>/dev/null || echo 0)"; next="$(sed -n "$((idx+1))p" "$STATE_DIR/restore_queue.txt" 2>/dev/null || echo "-" )"
    echo -e "${yellow}Fila de restauração ativa (índice $idx de $((total-1)))${reset}"
    echo -e "${yellow}Próximo snapshot no reboot: $next${reset}"
  fi

  if [[ -f "$STATE_DIR/ssh_permissive.mode" ]]; then
    local start ttl reason now remain; read -r start ttl reason < "$STATE_DIR/ssh_permissive.mode"
    now="$(date +%s)"; remain=$((start + ttl*3600 - now))
    if (( remain > 0 )); then local hrs=$((remain/3600)); local mins=$(((remain%3600)/60)); echo -e "${yellow}Janela permissiva ativa ($reason) - restante: ${hrs}h${mins}m${reset}"; else ssh_set_restricted_mode; fi
  fi
  [[ "${STOP_SERVICE_ON_SUCCESS:-0}" == "1" ]] && echo -e "${yellow}STOP_SERVICE_ON_SUCCESS habilitado${reset}"

  has_outbound_internet && echo -e "${green}Internet de saída: OK${reset}" || echo -e "${red}Internet de saída: FALHA - verifique conexão/DNS${reset}"

  has_remote_access; local rc=$?
  if [[ $rc -eq 0 ]]; then echo -e "${green}Acesso remoto: OK${reset}"
  elif [[ $rc -eq 2 ]]; then echo -e "${yellow}Acesso remoto: DEGRADADO - possível hairpin NAT${reset}"
  else echo -e "${red}Acesso remoto: FALHA - possível IP/porta incorreta${reset}"; fi

  local missing_ports
  if missing_ports=$(listening_on_ports $listen_ports); then echo -e "${green}Portas ouvindo: $listen_ports${reset}"
  else echo -e "${red}Portas não estão ouvindo: $missing_ports - iniciar serviços ou ajustar firewall${reset}"; fi

  if firewall_allows_ports $fw_ports; then echo -e "${green}Firewall permite portas necessárias${reset}"
  else echo -e "${yellow}Firewall pode estar bloqueando portas - execute ensure-ports${reset}"; fi

  local state="$(detect_external_vs_internal || true)"
  case "$state" in
    normal)    echo -e "${green}Status geral: normal${reset}" ;;
    internal)  echo -e "${red}Status geral: interno - verificar serviços/firewall ou restaurar backup${reset}" ;;
    degradado) echo -e "${yellow}Status geral: degradado - possível hairpin NAT${reset}" ;;
    external)  echo -e "${yellow}Status geral: external - possível falha de provedor/rota${reset}" ;;
  esac
}
diagnostics_summary() {
  load_env
  local green='\033[32m' yellow='\033[33m' red='\033[31m' reset='\033[0m'
  has_outbound_internet && echo -e "${green}Internet de saída: OK${reset}" || echo -e "${red}Internet de saída: FALHA${reset}"
  has_remote_access; rc=$?
  case $rc in 0) echo -e "${green}Acesso remoto: OK${reset}";; 2) echo -e "${yellow}Acesso remoto: DEGRADADO (hairpin)${reset}";; *) echo -e "${red}Acesso remoto: FALHA${reset}";; esac
  local ports="$(echo $MANDATORY_OPEN_PORTS)"
  if missing=$(listening_on_ports $ports); then echo -e "${green}Portas ouvindo: $ports${reset}"; else echo -e "${red}Portas faltando: $missing${reset}"; fi
  detect_firewalls; if firewall_allows_ports $ports; then echo -e "${green}Firewall permite portas necessárias${reset}"; else echo -e "${yellow}Firewall pode estar bloqueando portas${reset}"; fi
  local state="$(detect_external_vs_internal || true)"
  case "$state" in normal) echo -e "${green}Status geral: normal${reset}";; degradado) echo -e "${yellow}Status geral: degradado${reset}";; internal) echo -e "${red}Status geral: interno${reset}";; external) echo -e "${yellow}Status geral: external${reset}";; esac
}

# ------------- Utilidades solicitadas -------------
menu_edit_static_yaml() {
  local fn="/etc/netplan/90-dogwatch-static.yaml"
  touch "$fn" && chmod 600 "$fn"
  "${EDITOR:-nano}" "$fn"
  chmod 600 "$fn" || true
  if command -v netplan >/dev/null 2>&1; then netplan generate || true; netplan apply || true; fi
}
menu_reset_restore_queue() {
  rm -f "$STATE_DIR/restore_queue.txt" "$STATE_DIR/restore_index"
  setup_restore_queue
  say "Fila de restauração resetada."
}
menu_replace_backups_and_lastgood() {
  require_root; load_env
  say "Substituindo backups pelos estados atuais e atualizando last_good.hash…"
  # Remove tudo exceto 000-initial
  find "$BACKUP_DIR" -maxdepth 1 -mindepth 1 -type d -printf "%P\n" | while read -r d; do [[ "$d" == "000-initial" ]] && continue; rm -rf "$BACKUP_DIR/$d" || true; done
  # Cria 10 snapshots novos
  local i; for i in $(seq 1 "${MAX_ROTATING_BACKUPS:-10}"); do backup_snapshot "replacement-$i" >/dev/null 2>&1 || true; sleep 1; done
  compute_current_hash > "$STATE_DIR/last_good.hash" || true
  say "Backups recriados e last_good.hash atualizado."
}

# ------------- Docker helpers -------------
docker_install() {
  require_root
  say "Instalando Docker e Docker Compose..."
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y docker.io docker-compose-plugin >/dev/null 2>&1 || true
  systemctl enable --now docker >/dev/null 2>&1 || true
  say "Docker instalado."
}

docker_uninstall() {
  require_root
  say "Removendo Docker e Docker Compose..."
  systemctl disable --now docker >/dev/null 2>&1 || true
  apt-get purge -y docker.io docker-compose-plugin >/dev/null 2>&1 || true
  rm -rf /var/lib/docker /etc/docker >/dev/null 2>&1 || true
  say "Docker removido."
}

docker_edit_daemon_config() {
  require_root
  mkdir -p /etc/docker
  "${EDITOR:-nano}" /etc/docker/daemon.json
  systemctl restart docker >/dev/null 2>&1 || true
}

docker_edit_compose() {
  require_root
  read -rp "Caminho do docker-compose.yml [/opt/dogwatch/docker-compose.yml]: " file
  file="${file:-/opt/dogwatch/docker-compose.yml}"
  mkdir -p "$(dirname "$file")"
  "${EDITOR:-nano}" "$file"
  read -rp "Executar 'docker compose up -d' nesse diretório? (s/N): " yn
  if [[ ${yn,,} == s ]]; then
    ( cd "$(dirname "$file")" && docker compose up -d ) || true
  fi
}

menu_docker() {
  require_root
  while true; do
    echo "Gerenciamento de Docker"
    echo "a) Instalar Docker e Docker Compose"
    echo "b) Desinstalar Docker e Docker Compose"
    echo "c) Editar daemon.json"
    echo "d) Editar docker-compose.yml"
    echo "e) Listar containers"
    echo "f) Remover container"
    echo "g) Voltar"
    read -rp "Opção: " dc
    case "$dc" in
      a) docker_install ; read -rp "Enter para continuar..." _ ;;
      b) docker_uninstall ; read -rp "Enter para continuar..." _ ;;
      c) docker_edit_daemon_config ;;
      d) docker_edit_compose ;;
      e) command -v docker >/dev/null 2>&1 && docker ps -a || echo "Docker não instalado"; read -rp "Enter para continuar..." _ ;;
      f) read -rp "Nome/ID do container: " cn; command -v docker >/dev/null 2>&1 && docker rm -f "$cn" || echo "Docker não instalado"; read -rp "Enter para continuar..." _ ;;
      g) break ;;
      *) echo "Opção inválida" ;;
    esac
  done
}

# ------------- Daemon -------------
daemon_loop() {
  require_root; load_env
  local virt; virt="$(systemd-detect-virt 2>/dev/null || echo unknown)"
  [[ "$virt" != "none" ]] && log WARN "Ambiente virtual detectado ($virt); prosseguindo mesmo assim"
  say "Iniciando daemon $PROG v$VERSION"
  log INFO "DogWatch versão $VERSION (bin: $(readlink -f "$0"))"
  enforce_single_firewall || true
  first_run_bootstrap
  ensure_ports_open
  if ! ssh_set_dual_port_mode; then log WARN "SSHD não validado; tentando apenas abrir firewall"; ensure_ports_open; fi
  ssh_check_ttl_and_restrict_if_needed
  [[ -f "$STATE_DIR/last_default_ip.txt" ]] || record_default_ip_state

  local last_backup_ts=0
  while true; do
    enforce_single_firewall || true
    ssh_check_ttl_and_restrict_if_needed
    local now; now="$(date +%s)"
    if (( now - last_backup_ts >= BACKUP_INTERVAL_SECONDS )); then backup_snapshot "auto" >/dev/null 2>&1 || true; last_backup_ts="$now"; log INFO "Backup automático concluído."; fi

    local assessment; assessment="$(detect_external_vs_internal || true)"; log DEBUG "Diagnóstico: $assessment"
    local streak; streak="$(cat "$STATE_DIR/normal_streak" 2>/dev/null || echo 0)"

    case "$assessment" in
      normal)
        streak=$((streak + 1)); echo "$streak" > "$STATE_DIR/normal_streak"
        record_default_ip_state
        local current_hash last_hash; current_hash="$(compute_current_hash || echo x)"; last_hash="$(cat "$STATE_DIR/last_good.hash" 2>/dev/null || echo y)"
        if [[ "$current_hash" != "$last_hash" ]]; then set_pending_hash "$current_hash"; fi
        finalize_restore_queue || true
        ;;
      external)
        echo 0 > "$STATE_DIR/normal_streak"
        log WARN "Conectividade classificada como EXTERNAL (sem evidência de falha interna). Nenhuma ação destrutiva."
        if [[ "${AUTO_RESTORE_FIXED_IP:-1}" == "1" ]]; then
          if default_ip_changed >/dev/null 2>&1; then
            local last_ts nowts; last_ts="$(cat "$STATE_DIR/last_fixed_ip_restore_ts" 2>/dev/null || echo 0)"; nowts="$(date +%s)"
            if (( nowts - last_ts >= ${FIXED_IP_RESTORE_MIN_INTERVAL:-900} )); then
              log WARN "Mudança do IP/CIDR local detectada durante falha pública; tentando restaurar IP fixo do snapshot."
              if restore_fixed_ip_from_backup; then echo "$nowts" > "$STATE_DIR/last_fixed_ip_restore_ts"; fi
            else
              log INFO "Mudança de IP local detectada, mas em cooldown; ignorando por enquanto."
            fi
          fi
        fi
        if [[ "${REMOTE_ONLY_REPAIR:-1}" == "1" ]]; then
          local pf="$STATE_DIR/public_fail_streak"; local pfs; pfs="$(cat "$pf" 2>/dev/null || echo 0)"; pfs=$((pfs+1)); echo "$pfs" > "$pf"
          if (( pfs >= ${REMOTE_ONLY_REPAIR_CYCLES:-3} )); then
            log WARN "Falha pública persistente. Abrindo janela permissiva e reforçando portas."
            salvage_open_ports "$PRIMARY_SSH_PORT $EMERGENCY_SSH_PORT $EXTRA_PORTS"; ssh_set_permissive_mode "remote-only-failure"; echo 0 > "$pf"
          fi
        fi
        ;;
      internal)
        echo 0 > "$STATE_DIR/normal_streak"
        log WARN "Problema de conectividade INTERNAMENTE detectado. Iniciando autorreparo..."
        ensure_ports_open
        [[ "${AGGRESSIVE_REPAIR:-1}" == "1" ]] && attempt_restore_queue || true
        ;;
      degradado)
        echo 0 > "$STATE_DIR/normal_streak"
        log WARN "Acesso remoto degradado detectado. Iniciando autorreparo..."
        ensure_ports_open
        [[ "${AGGRESSIVE_REPAIR:-1}" == "1" ]] && attempt_restore_queue || true
        ;;
      *) echo 0 > "$STATE_DIR/normal_streak"; log DEBUG "Estado desconhecido." ;;
    esac

    promote_pending_if_stable
    sleep "$MONITOR_INTERVAL_SECONDS"
  done
}

# ------------- CLI & Menu -------------
case "${1:-}" in
  install) install_self ;;
  uninstall) uninstall_self ;;
  daemon) daemon_loop ;;
  backup-now) backup_snapshot "manual" ;;
  restore) restore_snapshot "${2:-}" ;;
  list-backups) list_backups ;;
  ensure-ports) ensure_ports_open ;;
  status) status_report ;;
  repair-now) ensure_ports_open; detect_external_vs_internal >/dev/null || true; attempt_restore_queue || true ;;
  docker-install) docker_install ;;
  docker-uninstall) docker_uninstall ;;
  docker-config) docker_edit_daemon_config ;;
  docker-compose) docker_edit_compose ;;
  "")
    menu() {
      require_root; load_env
      while true; do
        clear
        status_report
        echo
        cat <<EOF
================= DOGWATCH (v$VERSION) =================
1) Status geral (com opção de ver log completo)
2) Logs ao vivo (journalctl -fu dogwatch.service)
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
14) Gerenciar serviços vinculados (start/stop/restart)
15) Editar /etc/netplan/90-dogwatch-static.yaml
16) Resetar fila de restauração
17) Substituir backups (10) e last_good.hash pelas configurações atuais
18) Fechar acesso emergencial (porta 22)
19) Gerenciar Docker e containers
0) Sair
============================================================
EOF
        read -rp "Escolha: " op
        case "$op" in
          1)
            echo
            read -rp "Ver log completo do dogwatch agora? (s/N): " yn
            [[ "${yn,,}" == "s" ]] && journalctl -u dogwatch.service --no-pager || true
            read -rp "Enter para continuar..." _ ;;
          2)
            echo "Pressione Ctrl+C para sair."
            journalctl -fu dogwatch.service || true ;;
          3)
            local path; path=$(backup_snapshot "manual"); echo "Backup criado em: $path"
            read -rp "Enter para continuar..." _ ;;
          4)
            list_backups; read -rp "Enter para continuar..." _ ;;
          5)
            list_backups; read -rp "Digite o nome do snapshot para restaurar: " s
            restore_snapshot "$s"; echo "Restauração solicitada."
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
                  grep -q '^EXTRA_PORTS=' "$ENV_FILE" || echo 'EXTRA_PORTS=""' >> "$ENV_FILE"
                  EXTRA_PORTS="$(echo "$EXTRA_PORTS $p" | xargs -n1 | sort -u | xargs)"
                  sed -i "s/^EXTRA_PORTS=.*/EXTRA_PORTS=\"$EXTRA_PORTS\"/" "$ENV_FILE"
                  grep -q '^MANUAL_OVERRIDE_PORTS=' "$ENV_FILE" || echo 'MANUAL_OVERRIDE_PORTS=0' >> "$ENV_FILE"
                  MANUAL_OVERRIDE_PORTS=1; sed -i "s/^MANUAL_OVERRIDE_PORTS=.*/MANUAL_OVERRIDE_PORTS=1/" "$ENV_FILE"
                  ensure_ports_open
                  echo "Porta $p adicionada e aberta no firewall."
                fi ;;
              b)
                read -rp "Porta TCP a fechar (somente se estiver em EXTRA_PORTS): " p
                if echo " $EXTRA_PORTS " | grep -q " $p "; then
                  EXTRA_PORTS="$(echo "$EXTRA_PORTS" | tr ' ' '\n' | grep -v "^$p$" | xargs)"
                  sed -i "s/^EXTRA_PORTS=.*/EXTRA_PORTS=\"$EXTRA_PORTS\"/" "$ENV_FILE"
                  command -v ufw >/dev/null 2>&1 && LC_ALL=C LANG=C ufw delete allow "$p/tcp" || true
                  echo "Porta $p removida de EXTRA_PORTS e (se UFW presente) bloqueada."
                else
                  echo "Porta não está em EXTRA_PORTS."
                fi ;;
              c)
                ss -lntup || true; echo
                if command -v ufw >/dev/null 2>&1; then LC_ALL=C LANG=C ufw status verbose 2>/dev/null || true; else echo "UFW: não instalado"; fi ;;
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
              a) if command -v ufw >/dev/null 2>&1; then LC_ALL=C LANG=C ufw --force enable; ensure_ports_open; echo "UFW ativado."; else echo "UFW não instalado."; fi ;;
              b) if command -v ufw >/dev/null 2>&1; then LC_ALL=C LANG=C ufw --force disable; echo "UFW desativado."; else echo "UFW não instalado."; fi ;;
              c) systemctl stop firewalld || true; systemctl disable firewalld || true; systemctl mask firewalld || true; echo "firewalld desativado." ;;
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
              a) read -rp "IP/CIDR para permitir: " ip; command -v ufw >/dev/null 2>&1 && LC_ALL=C LANG=C ufw allow from "$ip" || echo "UFW não instalado." ;;
              b) read -rp "IP/CIDR para negar: " ip; command -v ufw >/dev/null 2>&1 && LC_ALL=C LANG=C ufw deny from "$ip"  || echo "UFW não instalado." ;;
              c) if command -v ufw >/dev/null 2>&1; then LC_ALL=C LANG=C ufw status numbered; read -rp "Número da regra para deletar: " n; yes | LC_ALL=C LANG=C ufw delete "$n" || true; else echo "UFW não instalado."; fi ;;
              d) if command -v ufw >/dev/null 2>&1; then LC_ALL=C LANG=C ufw status numbered || true; else echo "UFW não instalado."; fi ;;
            esac
            read -rp "Enter para continuar..." _ ;;
          9) diagnostics_summary; read -rp "Enter para continuar..." _ ;;
          10) command -v speedtest >/dev/null 2>&1 && speedtest || speedtest-cli || true; read -rp "Enter para continuar..." _ ;;
          11) install_self ;;
          12) "${EDITOR:-nano}" "$ENV_FILE" ;;
          13) uninstall_self ;;
          14)
            echo "Ações para serviços vinculados:"
            echo "a) start"
            echo "b) stop"
            echo "c) restart"
            read -rp "Opção: " sa
            case "$sa" in
              a) services_action start ;;
              b) services_action stop ;;
              c) services_action restart ;;
              *) echo "Opção inválida." ;;
            esac
            read -rp "Enter para continuar..." _ ;;
          15) menu_edit_static_yaml; read -rp "Enter para continuar..." _ ;;
          16) menu_reset_restore_queue; read -rp "Enter para continuar..." _ ;;
          17) menu_replace_backups_and_lastgood; read -rp "Enter para continuar..." _ ;;
          18) ssh_set_restricted_mode; echo "Acesso emergencial fechado."; read -rp "Enter para continuar..." _ ;;
          19) menu_docker ;;
          0) exit 0 ;;
          *) echo "Opção inválida"; sleep 1 ;;
        esac
      done
    }; menu ;;
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
  restore <snap>    Restaura snapshot (inclui /etc/netplan/90-dogwatch-static.yaml)
  ensure-ports      Garante portas obrigatórias abertas
  status            Exibe diagnóstico atual com cores e serviços vinculados
  repair-now        Abre portas e tenta restauração imediatamente
  docker-install    Instala Docker e Docker Compose
  docker-uninstall  Remove Docker e Docker Compose
  docker-config     Edita /etc/docker/daemon.json
  docker-compose    Edita e aplica docker-compose.yml
  (sem argumento)   Interface interativa
EOF
    ;;
esac
