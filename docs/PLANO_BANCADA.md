# Plano de bancada (dia da placa)

Objetivo do dia: sair com o ciclo completo rodando na BeagleBone e os ataques da
demo derrubando o dispositivo no painel. Tudo o que não depende da placa já está
pronto e testado (22 testes, demo simulada).

**Atenção:** leia antes a seção 4 de [REVISAO.md](REVISAO.md). A ordem do passo 4 tem um
problema conhecido: `setup_board.sh` exige `device.key`, enviada só depois dele.

## 0. Como eu (Claude) acesso a placa

O ambiente onde escrevi o código não consegue abrir SSH para a sua rede. As opções,
da melhor para a pior:

1. **Terminal web da placa pelo navegador do app.** Com a placa no USB, a
   imagem oficial expõe um IDE em `http://192.168.7.2:3000` (Cloud9 nas imagens
   antigas, VS Code nas Debian 10+). Com o app desktop aberto e esta conversa
   ligada ao seu computador, eu opero o terminal desse IDE pelo navegador
   embutido. Você só precisa estar logado nele.
2. **Pasta compartilhada.** Você conecta uma pasta pelo "+" do app; eu escrevo
   arquivos lá e você roda os comandos, colando a saída aqui.
3. **Manual.** Eu mando os comandos, você cola a saída.

## 1. Conexão e cópia do código (15 min)

```bash
ssh debian@192.168.7.2            # senha padrão: temppwd (troque depois)
date                              # se estiver em 2000, acerte: sudo date -s "2026-11-04 14:00"
```
No notebook, de dentro da pasta do projeto:
```bash
scp -r atebeagle kernel scripts systemd workload config debian@192.168.7.2:~/atebeagle/
```

## 2. Portão de decisão (10 min)

```bash
cd ~/atebeagle && sudo bash scripts/check_board.sh | tee board_report.txt
```
Cole o relatório no chat. Leitura rápida:

| Resultado | Caminho |
|---|---|
| `CONFIG_IMA=y` e log com muitas linhas | coletor `hybrid` (padrão). Siga. |
| `CONFIG_IMA=y` mas log só com boot_aggregate | adicionar `ima_policy=tcb` em `cmdline=` no `/boot/uEnv.txt`, reboot |
| `CONFIG_IMA` ausente | coletor `fs` agora (`setup_board.sh IP fs`); recompilar kernel só se sobrar tempo |
| headers do kernel presentes | compilar o `atebeagle_kint.ko` (passo 5) |
| sem headers | `sudo apt install linux-headers-$(uname -r)`; se não existir, L3 usa kallsyms |

## 3. Validador no notebook (10 min)

```bash
pip install cryptography scikit-learn
# No Git Bash: o projeto está no OneDrive e a chave da autoridade não pode ir para a nuvem.
export ATEBEAGLE_KEYS=/c/atebeagle/keys
bash scripts/provision.sh keys
cp config/validator.example.json validator.json   # colar a pubkey impressa acima e trocar admin_token
python3 -m atebeagle.validator --config validator.json
```
Abra `http://localhost:8700`. Libere a porta 8700 no firewall do notebook.

## 4. Instalação na placa (20 min)

```bash
sudo apt update && sudo apt install -y python3-cryptography rsync
sudo bash scripts/setup_board.sh 192.168.7.1        # ou "... fs" se não houver IMA
```
No notebook, com a placa limpa:
```bash
bash scripts/provision.sh baseline debian@192.168.7.2
bash scripts/provision.sh push debian@192.168.7.2
```
Teste um ciclo e depois ligue o serviço:
```bash
sudo python3 -m atebeagle.agent --config /etc/atebeagle/agent.json --once   # dentro de /opt/atebeagle/src
sudo systemctl enable --now atebeagle-agent atebeagle-workload
journalctl -u atebeagle-agent -f
```
Esperado: painel em TRUSTED, workload com dados chegando.

Falsos positivos prováveis no primeiro ciclo real: arquivos em `/usr/bin` lidos
pelo IMA que não estavam na baseline (ex.: atualizações do apt). Corrija
refazendo a baseline, nunca afrouxando a regra.

## 5. Módulo L3.1 (30 min, opcional)

```bash
cd ~/atebeagle/kernel && bash build.sh && sudo insmod atebeagle_kint.ko && sudo head -3 /proc/atebeagle_kint
echo atebeagle_kint | sudo tee /etc/modules-load.d/atebeagle.conf
sudo cp atebeagle_kint.ko /lib/modules/$(uname -r)/extra/ && sudo depmod
```
O módulo precisa carregar ANTES do primeiro ciclo do agente em cada boot,
senão a referência de boot é tirada sem ele e a troca de fonte vira FAIL.
Depois de instalar: `sudo rm /var/lib/atebeagle/l3_reference.json && sudo reboot`.

## 6. Ensaio da demo (30 min)

```bash
sudo bash scripts/attacks.sh tamper   # L2 ALTERED       -> REVOKED no próximo ciclo
sudo bash scripts/attacks.sh drop     # L2 UNAUTHORIZED
sudo bash scripts/attacks.sh module   # L3 MODULE_NEW
sudo bash scripts/attacks.sh silence  # dead man's switch (~150 s)
```
Entre um ataque e outro: `attacks.sh restore`, refazer baseline se necessário,
`curl -X POST -H 'X-Admin-Token: ...' -d '{"device_id":"bbb-01","pubkey":"..."}' http://localhost:8700/admin/reset`
e apagar `/var/lib/atebeagle/{epoch,chain}.json` na placa.

Para a apresentação, reduza `interval_s` para 15 em `/etc/atebeagle/agent.json`.

## Plano B

Se a placa falhar no dia: `python3 scripts/sim_demo.py --interval 5` reproduz a
mesma demo com o mesmo código e o mesmo painel.
