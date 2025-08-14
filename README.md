# DogWatch (Ubuntu 24.04+)

Ferramenta para **controle de conexão**, **backups** de configs críticas e **autorreparo** (foco em restabelecer acesso remoto/SSH).  
Pronta para instalação direta via **GitHub** (`git clone`) ou via **one-liner** com `curl`.

> **Requisitos**: Ubuntu 24.04+, privilégios de root, systemd habilitado e ambiente não virtualizado (sem VMs/containers).

---

## Instalação (via GitHub clone)
```bash
sudo apt-get update -y && sudo apt-get install -y git
git clone https://github.com/aryabdo/DogWatch.git
cd DogWatch
sudo ./install.sh
# O instalador já habilita os serviços dogwatch e dogwatch-safelane
```

## Instalação (one-liner via `curl`)
```bash
curl -fsSL https://raw.githubusercontent.com/aryabdo/DogWatch/main/install.sh | \
  sudo REPO_URL=https://github.com/aryabdo/DogWatch.git bash
```

## Atualização
Se você instalou via **git clone**:
```bash
cd DogWatch
git pull
sudo ./install.sh   # reinstala arquivos e recarrega o serviço
sudo systemctl restart dogwatch.service
```

Se você usou o **one-liner**, repita o comando acima (ele baixa a última versão e reinstala).

> **Dica**: se atualizar manualmente o binário `/opt/dogwatch/dogwatch.sh`, reinicie o serviço com
> `sudo systemctl restart dogwatch` para que a nova versão seja carregada e evitar mensagens antigas.

## Remoção (mantém backups)
```bash
sudo /opt/dogwatch/dogwatch.sh uninstall
```

---

## Componentes
- `dogwatch.sh` — Daemon + CLI/menu.
- `dogwatch.service` — Serviço systemd principal (inicia no boot; reinicia se cair).
- `dogwatch-safelane.service` — Serviço systemd que abre portas essenciais antes da rede (gerado pelo install.sh).
- `config.env.example` — Exemplo copiado para `/etc/dogwatch/config.env` na instalação; ajuste depois conforme necessário.
- `install.sh` — Instalador que pode instalar a partir deste repositório ou via one-liner.
- `Makefile` — Atalhos (install/uninstall/menu/status/logs/pkg).

Backups: `/opt/dogwatch/backups/`  
Logs: `/var/log/dogwatch/dogwatch.log`

---

## Principais funcionalidades
- **Backup 0.0 (imutável)** na primeira execução + **backups a cada 30 min**, mantendo **10** (além do 0.0).
- **Monitoramento a cada 5 min**: `normal | external | internal | degradado`.
  - **external** (falha do provedor/rota): **não altera** o sistema.
  - **internal** (mudança local): **restauração automática** do snapshot mais novo → mais antigo (inclui 0.0), validando conexão após cada passo.
  - **degradado** (fallback para IP local; possível hairpin NAT): **restauração automática**.
- **Verifica acesso remoto** ao IP público e reverte para backups caso falhe, mesmo com internet disponível.
- **Garante portas**: `16309` (primária) e `22` (emergência); detecta firewalls instalados e abre portas necessárias automaticamente.
- **Fila de restauração persistente** testa snapshots do mais novo ao mais antigo a cada reboot e pode desativar o serviço automaticamente com `STOP_SERVICE_ON_SUCCESS=1` após sucesso.
- **Recuperação SSH**: habilita login por senha de qualquer IP, limpa blacklists e desbloqueia usuários para restabelecer acesso.
- **Menu interativo**: execute `dogwatch.sh` sem argumentos para backups, restauração, portas, firewalls, listas (UFW), diagnósticos, speedtest, editar config, etc.

> **Atenção**: Atua assertivamente em componentes de rede/segurança. Tenha console físico/virtual para contingência. Não execute em ambientes virtualizados.

## Licença
MIT (ajuste conforme sua política interna).
