# DogWatch (v1.2.8)

DogWatch é um daemon em Bash para evitar lockout de SSH, manter portas críticas abertas, fazer backups/instantâneos de configuração e tentar autorreparo de rede/firewall/SSH em servidores Linux com systemd.

Público-alvo: admins que precisam de um “airbag” simples para mudanças de firewall/SSH/netplan que podem derrubar o acesso remoto.

Destaques

🔒 Anti-lockout: garante portas obrigatórias no UFW / firewalld / nftables / iptables.

🛟 Janela SSH permissiva automática em falhas pós-firewall (TTL configurável).

🧠 Detecção de estado: normal | internal | external | degradado (hairpin NAT).

🌐 Validação pública real (opcional): evita falso positivo em hairpin NAT.

💾 Backups rotativos (snapshot da configuração de rede/SSH/firewall e comandos úteis).

♻️ Fila de restauração com reinício opcional após aplicar snapshot.

🧷 IP fixo resiliente: restaura netplan de backup com rollback automático.

📜 Logs claros (arquivo próprio + systemd journal).

🧰 Menu interativo com operações comuns (status, logs ao vivo, backup/restore, portas, UFW, etc).

Requisitos

Distribuição baseada em Debian/Ubuntu com systemd.

Acesso root (via sudo) para instalar/executar.

Pacotes: bash, curl, jq, rsync, netcat-openbsd, iproute2, openssh-server, e pelo menos um entre ufw / firewalld / nftables / iptables (o script instala os faltantes no install).

Instalação

Clone este repositório e execute:

sudo ./dogwatch.sh install


O instalador vai:

Instalar dependências

Criar serviço dogwatch.service

Criar backup inicial 0.0

Iniciar o daemon

Binário principal: /opt/dogwatch/dogwatch.sh
Configuração: /etc/dogwatch/config.env
Logs: /var/log/dogwatch/dogwatch.log

Configuração

Ajuste /etc/dogwatch/config.env (criado no install). Principais chaves:

# Portas & SSH
PRIMARY_SSH_PORT="16309"
EMERGENCY_SSH_PORT="22"
SSH_PERMIT_ROOT="no"
SSH_PASSWORD_AUTH="no"
ALLOW_USERS="aasn"

# Conectividade e validação
REQUIRE_ICMP_AND_HTTP=1        # 1=ping E http; 0=ping OU http
REQUIRE_PUBLIC_REMOTE=0        # 1=exigir teste público real (sem hairpin)
PING_TARGETS="1.1.1.1 8.8.8.8"
HTTP_TARGETS="https://www.google.com https://cloudflare.com"

# Monitoramento e backup
MONITOR_INTERVAL_SECONDS=300
BACKUP_INTERVAL_SECONDS=1800
MAX_ROTATING_BACKUPS=10
LOG_LEVEL="INFO"               # DEBUG|INFO|WARN|ERROR

# Firewalls suportados e estratégia
FIREWALLS="ufw firewalld nftables iptables"
ENFORCE_SINGLE_FIREWALL="ufw"  # privilegia um para reduzir conflito

# Janela permissiva e autorreparo
EMERGENCY_TTL_HOURS="12"
AGGRESSIVE_REPAIR=1
REMOTE_ONLY_REPAIR=1
REMOTE_ONLY_REPAIR_CYCLES=3

# IP fixo resiliente (Netplan + rollback)
AUTO_RESTORE_FIXED_IP=1
FIXED_IP_RESTORE_MIN_INTERVAL=900
NETPLAN_RESTORE_REVERT_SECONDS=180
# INTERFACE_WATCH="" # defina para vigiar uma interface específica

# Portas obrigatórias e extras
MANDATORY_OPEN_PORTS="16309"
EXTRA_PORTS=""


Dica: mude LOG_LEVEL="DEBUG" temporariamente para investigar problemas.

Como funciona (resumo do loop)

Garante portas obrigatórias nos firewalls detectados.

Configura SSHD com porta primária e de emergência (modo restrito por padrão).

Avalia conectividade:

normal: tudo ok

internal: falha local (serviço/porta/firewall)

external: sem internet/rota, mas portas locais ok

degradado: hairpin/fallback (acesso local apenas)

Em falha interna: tenta autorreparo (abrir portas; fila de restauração).

Em falha externa: pode restaurar IP fixo do snapshot e agendar rollback.

Mantém backups rotativos e promove configuração estável a last_good.hash.

Uso rápido
Serviço
# Status do daemon
systemctl status dogwatch.service

# Iniciar/Parar/Reiniciar
sudo systemctl start dogwatch.service
sudo systemctl stop dogwatch.service
sudo systemctl restart dogwatch.service

CLI
# Diagnóstico com cores
sudo /opt/dogwatch/dogwatch.sh status

# Abrir (ou reforçar) portas obrigatórias
sudo /opt/dogwatch/dogwatch.sh ensure-ports

# Snapshot imediato
sudo /opt/dogwatch/dogwatch.sh backup-now

# Listar/restaurar snapshots
sudo /opt/dogwatch/dogwatch.sh list-backups
sudo /opt/dogwatch/dogwatch.sh restore 20250101-120000-manual

Menu interativo
sudo /opt/dogwatch/dogwatch.sh


Inclui: status, logs ao vivo, backup/restore, portas, UFW (whitelist/blacklist), diagnósticos, baseline (opcional), etc.

Logs (ao vivo)

Journal (serviço):

sudo journalctl -u dogwatch.service -n 200 -f


Arquivo do DogWatch:

sudo tail -F /var/log/dogwatch/dogwatch.log


Filtro de eventos de recuperação:

sudo journalctl -u dogwatch.service -f -n 0 \
| grep --line-buffered -E 'Diagnóstico:|pendente|promovid|Tentando restaura|Restaurando snapshot|pós-firewall|permissiv|restrito|Falha pública|EXTERNAL|INTERNAL|degradado|hairpin|Mudança do IP|Restauração do IP fixo|Rollback|Fila de restauração'

Backups & Restauração

Onde ficam: BACKUP_DIR (padrão: /opt/dogwatch/backups)

O que inclui: diretórios críticos como /etc/netplan, /etc/ssh, /etc/ufw, /etc/fail2ban, /etc/iptables*, /etc/nftables.conf, snapshots de comandos (ip a, ip r, ss -lntup, ufw status, nft list ruleset, etc.) e metadados.

Rotação: mantém MAX_ROTATING_BACKUPS + 000-initial.

Restaurar:

sudo /opt/dogwatch/dogwatch.sh restore <nome-do-snapshot>


Pode reiniciar automaticamente se RESTORE_AUTO_REBOOT=1.

Restauração de IP fixo (automática se habilitada): aplica Netplan do snapshot e agenda rollback em NETPLAN_RESTORE_REVERT_SECONDS se o acesso público não validar.

Estados e decisões do autorreparo

normal: promove hash pendente após N ciclos (PENDING_STABLE_CYCLES) e segue.

internal: abre portas, pode acionar fila de restore.

external: não destrutivo; tenta restaurar IP fixo se mudou; pode ativar janela permissiva após N ciclos de falha pública.

degradado: hairpin NAT detectado; trata como degradação sem assumir “OK público”.

Segurança

Requer root; modifica firewall e sshd_config.d/99-dogwatch.conf.

Janela permissiva SSH tem TTL (EMERGENCY_TTL_HOURS).

Respeita ALLOW_USERS/PermitRootLogin/PasswordAuthentication.

Evita conflito entre firewalls com ENFORCE_SINGLE_FIREWALL.

Desinstalação
sudo /opt/dogwatch/dogwatch.sh uninstall


Mantém os backups.

Solução de problemas

Sem internet, mas portas locais ok → estado external (não força restauração destrutiva).

Hairpin NAT → estado degradado; ajuste roteador/NAT ou habilite REQUIRE_PUBLIC_REMOTE=1.

Lento → aumente MONITOR_INTERVAL_SECONDS, BACKUP_INTERVAL_SECONDS, reduza PING_TARGETS/HTTP_TARGETS, defina ENFORCE_SINGLE_FIREWALL="ufw" e LOG_LEVEL="WARN".

Comandos disponíveis
install | uninstall | daemon | backup-now | list-backups | restore <snap> |
ensure-ports | status | repair-now | (sem argumento => menu interativo)

Licença

Defina a licença do projeto (ex.: MIT).

Aviso

O DogWatch abre/ajusta regras de firewall e reinicia serviços de rede/SSH quando necessário. Use em ambientes que você administra e teste em um host de homologação sempre que possível.
