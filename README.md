# ATEBEAGLE

Atestação Remota Contínua de Integridade numa BeagleBone Black.
Segurança no Ciberespaço, Engenharia de Computação, UNIFOR. Grupo F.

A cada ciclo (60 s por padrão) o agente na placa mede o software em execução,
compara com uma baseline assinada, assina o veredito e o envia a um validador
externo. Qualquer falha, silêncio, replay ou quebra de cadeia revoga a chave do
dispositivo e corta o I/O do workload.

> **Em revisão.** Ataques medidos na placa real, com limites conhecidos. Antes de usar ou
> avaliar, leia [docs/REVISAO.md](docs/REVISAO.md): o que foi comprovado, o que não foi e
> os pontos de atenção.

## Demonstração na placa

No Windows, dê dois cliques em `atebeagle.bat` e escolha **Iniciar tudo**. O menu confere a
placa, acerta o relógio, sobe o validador e o console e abre as três telas:

| Tela | Endereço |
|---|---|
| Monitoramento | http://localhost:8700 |
| Pasteurizador | http://localhost:8701/planta |
| Ataques | http://localhost:8701/ |

Ele instala o que faltar (`cryptography`, `paramiko`) e procura o `validator.json` em
`D:\ATEBEAGLE-build`, `C:\ATEBEAGLE-build` e `C:\atebeagle`, ou em `ATEBEAGLE_BUILD`. Fechar o
menu não para o sistema; para isso existe a opção **Encerrar o sistema**. Suba cerca de 20 min
antes de apresentar: a detecção de anomalias aprende nesse tempo.

Os ataques da tela são reais e reversíveis. **Recuperar a placa** desfaz qualquer um deles.
A planta é simulada; o estado, a leitura e a autorização vêm da placa e do validador.

## Estrutura

```
atebeagle/            pacote Python (só stdlib + cryptography)
  collectors/ima.py   L2: parser do log do IMA (ima, ima-ng, ima-sig)
  collectors/fs.py    L2: hash direto (plano B sem IMA, e caminhos críticos)
  collectors/kernel.py L3.1: sys_call_table, módulos, taint + telemetria
  baseline.py         golden baseline assinada pela autoridade offline
  appraiser.py        matriz de decisão (PASS/FAIL)
  publisher.py        época monotônica, cadeia prev_hash, Ed25519, transporte
  gate.py             State-Gated I/O do lado da placa
  agent.py            laço contínuo na placa
  validator.py        validador, dead man's switch, revogação, tokens, painel
  anomaly.py          IA: Isolation Forest + z-score robusto
  dashboard.html      painel da demonstração
kernel/               módulo atebeagle_kint.ko (leitura da sys_call_table)
workload/sensor.py    workload de demonstração (temperatura do SoC)
scripts/
  check_board.sh      portão de decisão: o que a placa oferece
  provision.sh        chaves, baseline e envio (roda no notebook)
  setup_board.sh      instala o agente na placa
  attacks.sh          ataques controlados para a demo
  sim_demo.py         demo completa sem placa (ensaio e plano B)
  launcher.py         menu do atebeagle.bat
  attack_console.py   console de ataque, roda no PC (exige paramiko)
  attack_console.html tela de ataques
  plant_console.html  tela do pasteurizador
  gen_drawio.py       gera docs/arquitetura.drawio
systemd/              units do agente e do workload
docs/                 revisão, arquitetura, requisitos da ENT#8, matriz, plano de bancada
tests/                48 testes (ponta a ponta, plataforma, console e menu)
atebeagle.bat         menu para iniciar e verificar tudo
```

## Rodar agora, sem a placa

```bash
pip install cryptography pytest scikit-learn   # scikit-learn é opcional
python3 -m pytest -q
python3 scripts/sim_demo.py --interval 5       # abra http://localhost:8700
```

No Windows, em um terminal aberto na pasta do projeto:

```powershell
py -m pip install cryptography paramiko pytest scikit-learn
py -m pytest -q
py scripts\sim_demo.py --interval 5
```

A demo só exige `cryptography`; `pytest` serve para os testes. Sem `scikit-learn`, a
IA usa o z-score robusto. Rode pelo terminal, não com duplo clique: a janela do duplo
clique fecha sozinha em caso de erro e é nela que os comandos são digitados. O painel
não abre sozinho no navegador.

Comandos da demo: `tamper`, `drop`, `delete`, `module`, `miner`, `taint`, `silence`, `replay`,
`forge`, `chain`, `reset`, `quit`.

## Na placa

Roteiro passo a passo em [docs/PLANO_BANCADA.md](docs/PLANO_BANCADA.md). A ordem abaixo
tem um problema conhecido: `setup_board.sh` exige a chave antes do `push`. Veja a seção 4
de [docs/REVISAO.md](docs/REVISAO.md).

```bash
# notebook
bash scripts/provision.sh keys
python3 -m atebeagle.validator --config validator.json
# placa
sudo bash scripts/check_board.sh | tee board_report.txt
sudo bash scripts/setup_board.sh 192.168.7.1
# notebook (placa limpa)
bash scripts/provision.sh baseline debian@192.168.7.2
bash scripts/provision.sh push debian@192.168.7.2
# placa
sudo systemctl enable --now atebeagle-agent atebeagle-workload
sudo bash scripts/attacks.sh tamper
```
