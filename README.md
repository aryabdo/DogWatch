# DogWatch (Ubuntu 24.04+)

Ferramenta para **controle de conexão**, **backups** de configs críticas e **autorreparo** (foco em restabelecer acesso remoto/SSH).  
Pronta para instalação direta via **GitHub** (`git clone`) ou via **one-liner** com `curl`.

> **Requisitos**: Ubuntu 24.04+, privilégios de root e systemd habilitado.

---

## Instalação (via GitHub clone)
```bash
sudo apt-get update -y && sudo apt-get install -y git
git clone https://github.com/aryabdo/DogWatch.git
cd DogWatch
sudo ./install.sh
sudo systemctl enable --now dogwatch.service
```

## Instalação (one-liner via `curl`)
> Substitua `<seu-usuario>` e `<dogwatch>` pelo nome do seu repositório público no GitHub.

```bash
curl -fsSL https://raw.githubusercontent.com/aryabdo/DogWatch/main/install.sh | sudo bash
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

## Remoção (mantém backups)
```bash
sudo /opt/dogwatch/dogwatch.sh uninstall
```

---

## Componentes
- `dogwatch.sh` — Daemon + CLI/menu.
- `dogwatch.service` — Serviço systemd (inicia no boot; reinicia se cair).
- `config.env.example` — Exemplo copiado para `/etc/dogwatch/config.env` na instalação; ajuste depois conforme necessário.
- `install.sh` — Instalador que pode instalar a partir deste repositório ou via one-liner.
- `Makefile` — Atalhos (install/uninstall/menu/status/logs/pkg).

Backups: `/opt/dogwatch/backups/`  
Logs: `/var/log/dogwatch/dogwatch.log`

---

## Principais funcionalidades
- **Backup 0.0 (imutável)** na primeira execução + **backups a cada 30 min**, mantendo **10** (além do 0.0).
- **Monitoramento a cada 5 min**: `normal | external | internal`.
  - **external** (falha do provedor/rota): **não altera** o sistema.
  - **internal** (mudança local): **restauração automática** do snapshot mais novo → mais antigo (inclui 0.0), validando conexão após cada passo.
- **Garante portas**: `22` e **`16309`** sempre abertas; detecta firewalls instalados e abre portas necessárias automaticamente.
- **Recuperação SSH**: habilita login por senha de qualquer IP, limpa blacklists e desbloqueia usuários para restabelecer acesso.
- **Menu interativo**: execute `dogwatch.sh` sem argumentos para backups, restauração, portas, firewalls, listas (UFW), diagnósticos, speedtest, editar config, etc.

> **Atenção**: Atua assertivamente em componentes de rede/segurança. Tenha console físico/virtual para contingência.

## Licença
MIT (ajuste conforme sua política interna).
