# Instruções de revisão

Documento de trabalho do Grupo F. Registra o que foi feito no ATEBEAGLE, o que já foi
comprovado e o que ainda precisa ser revisado por uma pessoa antes da entrega da
ENT#8. Nada aqui substitui a leitura do código: confira cada item e marque a caixa
somente depois de verificar.

Revisado até 06/11/2026.

## 1. Atenção antes de tudo

Estes pontos podem atrapalhar a bancada ou a apresentação. Leia primeiro.

- [ ] **Teste na placa física ainda parcial** (ver seção 10). Boot pelo microSD, carga do
  `atebeagle_kint`, rede USB, serviços systemd e ciclos PASS do agente já rodaram na
  BeagleBone real, e em 06/11 também o validador com a configuração original e os ataques
  (seção 10.3). Falta a detecção de alteração na sys_call_table.
- [x] **Os 22 testes do núcleo passam no Python 3.7 da imagem** (Linux, ARM emulado via
  qemu). No Windows com Python 3.14 passam os 48, incluindo o console e o menu, que rodam
  só no PC e não foram testados no Python 3.7.
- [ ] **A ordem de instalação do plano está errada.** `scripts/setup_board.sh` encerra
  com erro se `/etc/atebeagle/device.key` não existir, mas o plano e o README só enviam
  a chave depois dele. Veja a seção 4.
- [ ] **A chave da autoridade não pode ir para a nuvem.** O projeto está no OneDrive.
  Use `export ATEBEAGLE_KEYS=/c/atebeagle/keys` no Git Bash antes de gerar as chaves.
  Nunca publique `keys/`, `*.key`, `validator.json` ou `baseline.json`.
- [ ] **Troque o `admin_token`.** O valor padrão está em `atebeagle/config.py` e neste
  repositório público. O validador escuta em `0.0.0.0`, então quem alcançar a porta
  8700 e souber o token consegue re-provisionar o dispositivo.
- [ ] **Troque a senha padrão da placa** (`temppwd`) assim que conectar.

## 2. O que foi comprovado e o que não foi

| Item | Situação | Como foi verificado |
|---|---|---|
| Testes automatizados | Núcleo no Windows e no Python 3.7 (ARM emulado); console e menu só no Windows | 22 nos dois; 48 no Windows |
| Ataques na placa real, com a configuração original | Comprovado em 06/11, exceto a sys_call_table | Console na placa real, seção 10.3 |
| Replay e veredito forjado na placa real | Comprovado em 06/11 | Veredito capturado em `usb0` e reenviado; eventos REPLAY e REJECT |
| Reboot com validador ativo | Medido uma vez, no caso mais favorável | Seção 10.3 |
| `tamper`, `drop`, `delete`, `module`, `chain` revogam | Comprovado em simulação | Roteiro consultando `/api/state` |
| `silence` revoga em cerca de 12 s (intervalo de 5 s) | Comprovado em simulação | Roteiro e captura de tela |
| `replay` e `forge` são recusados sem revogar | Comprovado em simulação | Roteiro e lista de eventos |
| `miner` leva a SUSPECT sem revogar | Comprovado em simulação | Roteiro e captura de tela |
| `taint` gera alerta e evento ALERT | Comprovado em simulação | Roteiro, teste e captura de tela |
| Sem SUSPECT falso depois do `reset` | Comprovado em simulação | Dois `reset` com a IA aquecida |
| Sem alarme falso com a demo parada | Comprovado antes das últimas mudanças | 83 ciclos, sem ataques |
| Painel em navegador | Comprovado | Chrome headless no notebook |
| Selo "SEM MEDIÇÃO" no silêncio | **Não visto na tela** | Só leitura do código |
| Limpeza de dados antigos em UNKNOWN | **Não visto na tela** | Só leitura do código |
| Texto "revisão humana" na etapa Reagir em alerta | **Não visto na tela** | Só leitura do código |
| Coletor IMA e híbrido com log real | **Não testado** | Só parser com arquivo de exemplo |
| Módulo `atebeagle_kint` | **Compila** (vermagic 4.19.94-ti-r42); não carregado na placa | Compilado com os headers do kernel na imagem |
| `provision.sh baseline` e `push` | **Não testados** | Só `keys` foi testado, com chaves descartáveis |
| `attacks.sh`: tamper/drop/delete | Comprovado na imagem ARM emulada | FAIL com ALTERED/UNAUTHORIZED/MISSING; restaura para PASS |
| `attacks.sh`: module/silence/netcut; `check_board.sh` | Comprovados na placa real | Seções 10.1 e 10.3 |

## 3. O que mudou e o que revisar

### 3.1 Execução no Windows

A demo não abria porque faltavam dependências, e ela ainda exigia o `pytest` sem
precisar dele.

| Mudança | Arquivo | O que revisar |
|---|---|---|
| Placa simulada fora do `conftest.py` | `tests/fakeboard.py` | A demo sobe só com `cryptography` |
| Espera por arquivo travado, apenas no Windows | `atebeagle/common.py`, `gate.py` | `retry_if_locked` não pode mudar nada no Linux |
| Porta exclusiva, apenas no Windows | `atebeagle/validator.py` | Segunda instância é recusada com mensagem clara |
| `reset` não ocorre no meio de um ciclo | `scripts/sim_demo.py` | Comando que falha não derruba a demo |

- [ ] Rode a demo em uma máquina limpa, seguindo só o README.
- [ ] No Windows, `chmod` não protege arquivos. Não confie no modo `0600` lá.

### 3.2 Painel

`atebeagle/dashboard.html` foi reescrito sem bibliotecas nem fontes externas, porque a
apresentação pode ocorrer sem internet. Mostra a BeagleBone em escala e o notebook
validador, o ciclo de 5 etapas, as camadas L3, L2, L1 e IA, a análise de adversários,
as 4 proteções do protocolo, as áreas do CyBOK, a faixa de ameaça, os achados, os
eventos e os dados do workload.

- [ ] Compare o painel com a Ideação (ENT#7), o pôster e os slides 11 a 15.
- [ ] Os LEDs do desenho refletem o estado no validador, não o LED físico. Deixe isso
  claro ao apresentar.
- [ ] O desenho é uma representação. Confira a posição dos componentes com a placa em
  mãos. microHDMI e microSD ficam no verso da placa real.
- [ ] Veja o rodapé: o repositório público traz só os nomes curtos. Para exibir os
  nomes completos, confirme antes com os colegas e edite o rodapé do painel.
- [ ] Veja se o painel fica legível no projetor da sala.

### 3.3 Comandos novos da demo

`delete`, `replay`, `forge`, `chain` e `taint`, em `scripts/sim_demo.py`.

- [ ] `replay` reenvia o último veredito capturado pela própria demo. Na placa, o
  caminho é `attacks.sh replay`, que exige um `veredito.json`, e **ainda não há
  ferramenta que capture esse arquivo**. Sem ela, o passo 4 do roteiro da ENT#8 precisa
  da demo simulada.
- [ ] `taint`, `forge` e `chain` existem só na demo. O `attacks.sh` não tem equivalente.
- [ ] Depois de `reset`, espere `TRUSTED` antes de usar `silence`. Antes do primeiro
  veredito o dead man's switch não arma, e o estado fica em UNKNOWN com o I/O bloqueado.
- [ ] Para o `miner`, espere o campo IA sair de "aquecendo" (cerca de 40 s com
  intervalo de 5 s).

### 3.4 Decisão: alerta

Decisão do grupo: basta mostrar que o alerta existe e ter conhecimento da ameaça.

- O veredito assinado continua com dois valores, PASS e FAIL.
- Alerta é PASS com achado de aviso, ou SUSPECT da IA.
- O painel diz o que foi detectado e o que o sistema fez. O validador registra o evento
  ALERT uma vez, e não a cada ciclo. Não há revogação.
- Na IA, a causa exibida é hipótese, por isso o texto diz "possível".

- [ ] Confira se o relatório descreve assim, e não como um terceiro veredito assinado.
- [ ] A lista de hipóteses (`HINT` no painel) foi escrita sem validação com dados reais.

### 3.5 Decisão: SUSPECT falso no início do agente

O primeiro ciclo refaz todos os hashes e demora mais, e a IA tratava isso como anomalia.
Agora o agente marca esse ciclo com `cold_start`, e o validador ignora só a duração dele.
Carga, processos e memória seguem avaliados, e o ciclo não entra no treino.

- [ ] Limite a registrar: `cold_start` é declarado pelo próprio dispositivo. Um agente
  comprometido poderia marcá-lo sempre e esconder a duração do ciclo. Como ele já
  controla a telemetria que envia, isso não abre uma capacidade nova, mas a banca pode
  perguntar.

### 3.6 Decisão: local das chaves

`scripts/provision.sh` recusa pasta sincronizada com OneDrive, Dropbox ou Google Drive,
e aceita outro local por `ATEBEAGLE_KEYS`.

- [ ] Guarde uma cópia offline da chave da autoridade. Sem ela, não dá para assinar uma
  nova baseline.
- [ ] A chave da autoridade nunca vai para a placa. Confira depois do `push`.

## 4. Pontos de atenção na bancada

Complementa `docs/PLANO_BANCADA.md`.

- [ ] **Ordem de instalação.** Sugestão, ainda não testada: gerar chaves; enviar
  `device.key` e `baseline_authority.pub` para `/etc/atebeagle`; rodar `setup_board.sh`;
  gerar a baseline com `provision.sh baseline`; rodar `provision.sh push`. O `setup` deve
  vir antes da baseline, porque ele instala os arquivos em `/opt/atebeagle` que a baseline
  mede. Ajuste o plano quando confirmar.
- [ ] **Baseline gerada no Windows.** `provision.sh baseline` extrai `/usr/bin` da placa
  no notebook. O NTFS não diferencia maiúsculas de minúsculas e lida mal com links
  simbólicos, então a baseline pode sair errada. Compare a contagem de arquivos com a
  placa. Se divergir, gere a lista de hashes em Linux. Também confira se `.bbb_root` não
  sincronizou com o OneDrive: ela fica na pasta do projeto.
- [ ] **Git Bash.** `bash` não está no PATH do PowerShell neste notebook, e `rsync` também
  não existe nele. Rode os scripts de notebook no Git Bash.
- [ ] **Coletor `fs`.** O `setup_board.sh` só define `/opt/atebeagle` e `/usr/local/bin`
  como caminhos do hash direto. No plano B, sem IMA, alterações em `/usr/bin` não são
  vistas, embora estejam na baseline. Não prometa essa cobertura.
- [ ] **Relógio da placa.** Fora da janela de 120 s, os vereditos são recusados. Acerte a
  data antes.
- [ ] **Firewall.** Libere a porta 8700 no notebook apenas para a rede da placa.
- [ ] **Sem TLS por padrão.** Vereditos são assinados, mas tokens e painel trafegam em
  HTTP. `/api/state` e o painel não têm autenticação. Aceitável em rede USB dedicada, não
  em rede aberta.
- [ ] **Falsos positivos.** Sempre refaça a baseline. Nunca afrouxe a regra.

## 5. Divergências a resolver nos textos

- [ ] **Rootkit "contido".** O slide 13 e o pôster dizem "contido" sem ressalva.
  `docs/ANALISE_L1.md` diz que um atacante em ring 0 pode falsificar o agente. O painel já
  separa os casos. Sugestão: "contido quando altera módulos ou syscalls". Responsáveis:
  Ana Julia e Marcos Mendes.
- [ ] **"Janela de detecção de até 60 s".** Vale para adulteração. No silêncio, a
  revogação leva até 150 s (2,5 intervalos). Com IMA, um arquivo só é remedido ao ser
  aberto de novo, e por isso os caminhos críticos usam hash direto. Reveja a frase na
  Ideação e nos slides.
- [ ] **Etapa Reagir.** Slides e pôster citam revogar a chave e inutilizar o sistema. O
  implementado corta o I/O do workload, para o serviço e acende o USR3. Descreva assim.
- [ ] **Nome da disciplina.** Parte dos documentos diz "Cibersegurança", parte "Segurança
  no Ciberespaço". Padronize.
- [ ] **Versão do processador.** Os documentos oficiais variam entre AM3358 e AM3359, e a
  foto do manual mostra AM3359. Confira na placa e ajuste o painel se preciso.
- [ ] **Slide 02b, "Por que CyBOK?".** O Roteiro prevê essa fala, e a apresentação em PDF
  não tem o slide. Decida se entra.

## 6. Pendências da entrega

- [ ] Rodar `sudo bash scripts/check_board.sh` e decidir entre coletor `hybrid` e `fs`.
- [ ] Compilar o módulo, se houver headers.
- [ ] Ensaiar os ataques na placa e medir os tempos reais. A Ideação promete aferir os
  valores definitivos na prova de conceito, e os tempos deste documento são de simulação.
- [ ] Completar `docs/ANALISE_L1.md` com a Ana Julia.
- [ ] Apresentação com demonstração ao vivo.
- [ ] Relatório final em ABNT.

## 7. Revisão por frente

Divisão baseada no Roteiro da equipe. Ajustem como preferirem.

| Integrante | Frente | Revisar |
|---|---|---|
| Nathan | Coordenação e integração | Seções 1, 5 e 6; relatório e publicação |
| Marcos Mendes | Placa e coleta L2 | Seção 4; coletores e baseline |
| Pedro Nobre | Kernel L3 | `collectors/kernel.py`, `kernel/atebeagle_kint.c` |
| Marcos Vinícius | Publicador e protocolo | `publisher.py`, `validator.py`, `replay` e `forge` |
| Ana Julia | Ameaças e L1 | `docs/ANALISE_L1.md`, seção 5 |
| Tales | Fundamentação | `docs/ENT8_REQUISITOS.md`, áreas do CyBOK no painel |

## 8. Comandos

```bash
python3 -m pytest -q                      # no Windows: py -m pytest -q
python3 scripts/sim_demo.py --interval 5  # no Windows: py scripts\sim_demo.py --interval 5
```

Abra `http://localhost:8700`. O painel é lido a cada requisição: para ver uma mudança no
HTML, recarregue a página. Mudanças em Python exigem reiniciar a demo.

Comandos: `tamper`, `drop`, `delete`, `module`, `miner`, `taint`, `silence`, `replay`,
`forge`, `chain`, `reset`, `quit`.

## 9. Imagem pré-provisionada (preparada no PC, fora do repositório)

Para adiantar a bancada, foi montada uma imagem Debian da placa (base 10.3 IoT, Buster,
kernel 4.19.94-ti-r42, com Cloud9) com o ATEBEAGLE já instalado, usando WSL + emulação
ARM (qemu) para operar o sistema da placa sem a placa. A imagem e os insumos ficam em
`D:\ATEBEAGLE-build` e **não são versionados**.

Já vem pronto na imagem:

- `python3-cryptography`, `pytest` e os headers do kernel; `apt` apontando para
  `archive.debian.org` (Buster saiu de suporte).
- Projeto em `/opt/atebeagle`; módulo `atebeagle_kint.ko` compilado e instalado em
  `/lib/modules/.../extra` (carrega no boot, antes do agente).
- Coletor `fs` (não há IMA neste kernel); baseline assinada e **verificada pelo Python
  3.7 da própria placa**; serviços `atebeagle-agent` e `atebeagle-workload` habilitados.
- Caminhos monitorados: `/usr/local/bin` e `/opt/atebeagle`.

Fora do Git (contêm segredos ou a `device.key`): as chaves, `validator.json` (com
`admin_token`) e a própria imagem. Passo a passo da gravação e dos testes na placa:
`D:\ATEBEAGLE-build\LEIA-ME.md`.

## 10. Primeiro boot na placa real (05/11/2026)

**Falso positivo corrigido.** O agente subia aos 17 s e registrava a referência L3 com 11
módulos; os módulos da PRU carregam por volta de 60 s. Os 10 restantes viravam
`MODULE_NEW`, o status ia a FAIL e o gate parava o workload e acendia o USR3 a cada boot.

Agora `scripts/wait-modules.sh` segura o agente até 120 s de uptime e 30 s sem mudanças,
com limite em 240 s. Depois do boot, 4 ciclos seguidos em PASS, sem achados e com 21
módulos na referência. Sem validador, o workload segue em `BLOQUEADO` por falta de token,
como esperado.

Também na placa: `/opt/atebeagle` estava com permissão 777 e foi corrigido para 755, e o
log do agente agora chega ao journal.

- [ ] A correção no repositório (`setup_board.sh`, unit do agente) **não foi testada por
  uma reinstalação**. Na placa, ela foi aplicada à mão, com um drop-in do systemd e
  `/etc/atebeagle/wait-modules.sh`. A imagem em `D:\ATEBEAGLE-build` não tem a correção.
- [ ] Sincronizar `src/` na placa exige nova baseline assinada, porque esses arquivos
  estão medidos.
- [ ] **Decisão do grupo:** a espera amplia a janela já documentada em `docs/ANALISE_L1.md`.
  Avaliar a lista de módulos permitidos na baseline assinada.
- [ ] **Relógio.** A placa não tem bateria de RTC e estava em 06/04/2020. Depois do acerto
  manual e de um reboot, ficou cerca de 20 s atrasada, dentro da janela de 120 s. Confira
  com `date -u` antes de cada demo, principalmente depois de ficar desligada.
- [ ] A senha padrão `temppwd` continua ativa.

### 10.1 Ataques na placa real (05/11/2026, intervalo de 60 s)

Validador temporário no notebook, com a chave pública e a baseline da própria placa, e
não a configuração original. Repetir com ela. O tempo depende do ponto do ciclo em que o
ataque cai.

| Teste | Resultado | Tempo |
|---|---|---|
| `tamper` | REVOKED, L2 ALTERED; USR3 aceso, workload parado | 53 s |
| `drop` | REVOKED, L2 UNAUTHORIZED; USR3 aceso, workload parado | 42 s |
| `delete` | REVOKED, L2 MISSING; USR3 aceso, workload parado | 42 s |
| `module` | REVOKED, L3 MODULE_NEW; USR3 aceso, workload parado | 41 s |
| `silence` (`attacks.sh`, SIGKILL) | **Não revogou**: `Restart=always` devolve o agente em 5 s | Mais de 3 min em TRUSTED |
| `systemctl stop` do agente | REVOKED, dead man's switch; USR3 apagado, workload ativo | 131 s |
| Replay e veredito forjado | Recusados com 403, sem revogar | Imediato |
| 18,7 min sem ataques | Só TRUSTED, sem SUSPECT, ALERT ou REVOKED | |
| Carga de CPU com a IA aquecida | SUSPECT (`cycle_ms`, z=21), sem revogar | 57 s |
| `netcut` | REVOKED, dead man's switch. **Medição não conclusiva**, ver abaixo | 140 s |

- [ ] **Corrigir o `silence`.** Como está, o ataque da demo não revoga. Decidir entre mudar
  o ataque (`systemctl stop`) ou o unit, e atualizar o roteiro.
- [ ] **Silêncio não aciona o gate local.** Sem agente, USR3 e workload não mudam na placa;
  o bloqueio vem do validador, que invalida os tokens. Descrever assim na apresentação.
- [ ] **Reinício espontâneo não explicado.** A placa reiniciou por volta de 20:06 UTC, no
  início do `netcut`, e o journal do boot anterior não foi preservado. Causa desconhecida:
  investigar alimentação pelo USB e repetir o `netcut`.
- [ ] **O relógio regride no reboot.** Nesse reinício a placa voltou cerca de 49 min. Fora
  da janela de 120 s os vereditos são recusados, então o relógio precisa ser acertado
  depois de **todo** boot.
- [ ] O teste de reboot com validador ativo não foi feito. Com 120 s de espera, somados ao
  boot, o silêncio pode chegar perto dos 150 s do dead man's switch.
- [ ] `attacks.sh restore` falhava depois de `delete` e foi corrigido no repositório. A
  cópia na placa mantém o bug até a próxima baseline: mova `/root/workload.py` à mão.
- [ ] Notebook em modo de espera interrompe o validador. Desative a suspensão na demo.
- `check_board.sh` confirmou: kernel sem IMA (`CONFIG_IMA` desligado), então o coletor é `fs`.

### 10.2 Continuar no desktop

Os testes acima foram feitos no notebook. `D:\ATEBEAGLE-build` (imagem original) fica no
desktop, e as chaves e o `validator.json` devem estar junto. O microSD já traz a correção
de boot: **não regrave com a imagem original**, que volta a ter o falso positivo.

O backup do microSD corrigido está no notebook, em `C:\atebeagle\backups`. Ele contém
`device.key`: copie só por pendrive, nunca por nuvem ou Git.

1. Baixe esta branch: `git fetch origin`, depois `git switch bancada-placa-real`.
2. Ligue a placa com um **cabo mini-USB de dados**. Dos três testados, um dava erro de
   descritor e outro não aparecia no PC. Espere pouco mais de 2 minutos.
3. Acerte o relógio pelo Git Bash:
   `ssh -t debian@192.168.7.2 "sudo date -u -s '$(date -u '+%Y-%m-%d %H:%M:%S')'"`
4. Confira o `validator.json`: a chave pública deve ser a da `device.key` da placa, e o
   `admin_token` não pode ser o padrão. Um `validator_state.json` antigo pode trazer REVOKED
   ou uma época maior que a da placa; nesse caso, comece com um arquivo de estado novo.
5. Suba o validador: `py -m atebeagle.validator --config <caminho>\validator.json`. Se a
   placa não alcançar a porta 8700, libere-a no firewall só para a rede da placa.
6. Espere `TRUSTED` em `http://localhost:8700` e repita a tabela 10.1, além do reboot com
   validador ativo.
7. Depois de `delete`, a cópia do `attacks.sh` na placa não restaura sozinha:
   `sudo mv /root/workload.py /opt/atebeagle/`.

### 10.3 Bancada no desktop (06/11/2026, intervalo de 60 s)

Validador no desktop com o `validator.json` original; chave e baseline conferem com a placa
por hash. Placa alimentada pelo USB do desktop. Sequência em segundo plano e depois repetida
pelo console de ataque (`scripts/attack_console.py`), cujos ataques são inofensivos e diferentes
do `attacks.sh`: o trojan é um comentário e o backdoor se chama `atb-backdoor`.

| Teste | `attacks.sh` | Console | Observação |
|---|---|---|---|
| 20 min sem ataques | Sem eventos | | Aquecimento da detecção de anomalias |
| Carga de CPU / minerador | SUSPECT em 44 s | SUSPECT em 59 s | `cycle_ms` (z=18,8); sem revogar; volta a TRUSTED |
| `tamper` / trojan | REVOKED em 58 s | 58 s | L2 ALTERED; USR3 aceso, workload parado |
| `drop` / backdoor | REVOKED em 53 s | 59 s | L2 UNAUTHORIZED |
| `delete` / apagar programa | REVOKED em 51 s | 59 s | L2 MISSING |
| `module` / rootkit | REVOKED em 52 s | 57 s | L3 MODULE_NEW `dummy` |
| `silence` (SIGKILL) | Não revogou em 210 s | Não revogou em 200 s | SUSPECT passageiro por `arrival_jitter_s` (z=52) |
| `systemctl stop` do agente | REVOKED em 125 s | 106 s | Dead man's switch; USR3 apagado, workload ativo |
| `netcut` | REVOKED em 142 s (200 s fora) | 150 s e 126 s (130 s fora) | Sem reinício espontâneo neste PC |
| Replay | **Inválido** | 403, evento REPLAY | Veredito real capturado em `usb0` |
| Veredito forjado | **Inválido** | 403, evento REJECT | Sem revogar |
| Leitura falsa sem token | | 403 | |
| Leitura falsa com token roubado | | **Aceita** (200) em TRUSTED; 403 depois da revogação | Token ao portador |
| Implante em `/usr/bin` | | **Sem reação** em 135 s | Fora dos caminhos do coletor `fs` |
| Backdoor de 9 s, entre duas medições | | **Sem reação** | Limite de medição periódica |
| Reboot com validador ativo | Sem revogar; 1º veredito em 137 s | | Caso mais favorável; SUSPECT passageiro, `arrival_jitter_s` (z=83) |

Os tempos dependem do ponto do ciclo em que o ataque cai. Replay e forja da coluna
`attacks.sh` são inválidos por erro do roteiro de teste: a captura usava um socket só de IP,
que não vê os pacotes que a própria placa envia, então nenhum veredito real foi reenviado.
A coluna do console usa a captura corrigida.

- [ ] **Reboot deve revogar na maioria dos casos.** Foram 137 s de silêncio começando logo
  depois de um veredito, contra um limite de 150 s. Em outro ponto do ciclo, o total
  passa do limite. Conclusão por cálculo; repita o teste em vários pontos do ciclo e decida
  entre aceitar a revogação ou ajustar a espera.
- [ ] **SUSPECT falso depois de reinício.** A pausa nos vereditos conta como atraso de chegada.
  Avaliar se `arrival_jitter_s` deve ser ignorado no ciclo frio, como `cycle_ms`.
- [ ] **Token ao portador.** Com o token copiado da placa, leituras falsas são aceitas enquanto
  o dispositivo está TRUSTED. Decidir se isso entra como limitação ou se o token deve ser
  vinculado a uma assinatura da placa.
- [ ] **Cobertura e janela.** O coletor `fs` só mede `/opt/atebeagle` e `/usr/local/bin`, e
  alterações desfeitas entre dois ciclos não são vistas. Descrever os dois limites na
  apresentação.
- [ ] O reinício espontâneo do notebook não se repetiu com o desktop, o que sugere alimentação
  pelo USB, mas foi uma única repetição. Não trate como causa confirmada.
- [ ] O journal da placa continua não persistente: um novo reinício espontâneo não deixará
  registro do boot anterior.
- [ ] **Sem `scikit-learn`, o modelo em uso é o z-score robusto**, estatística e não aprendizado
  de máquina, e mesmo com ele o Isolation Forest só conta a partir de 50 vereditos. Os textos
  que dizem "IA" precisam refletir o que estiver rodando.
- [ ] A detecção de anomalias perde o histórico quando o validador reinicia. Suba o sistema
  cerca de 20 min antes da demonstração para o minerador gerar SUSPECT.

### 10.4 Console de ataque, planta e menu

`atebeagle.bat` abre o menu: inicia o sistema, verifica a placa, acerta o relógio, recupera a
placa e abre as três telas. Monitoramento em `http://localhost:8700`; pasteurizador em
`http://localhost:8701/planta`; ataques em `http://localhost:8701/`.

| Mudança | Arquivo | O que revisar |
|---|---|---|
| Console com 13 ataques reversíveis | `scripts/attack_console.py` | Ações são de root na placa: só escuta em 127.0.0.1 e recusa outras origens |
| Tela de ataques | `scripts/attack_console.html` | O personagem muda só por resultado real |
| Planta simulada | `scripts/plant_console.html` | Estado, leitura e token são reais; a planta e a contagem de garrafas, não. A leitura é a temperatura do SoC |
| Menu | `atebeagle.bat`, `scripts/launcher.py` | Encerra só processos que confere serem do projeto |
| Mascote no painel | `atebeagle/dashboard.html` | Embutido no HTML, sem rota nova no validador |

- [ ] A correção de boot não está na imagem de `D:\ATEBEAGLE-build`. O menu acusa esse caso.
- [ ] O console usa a senha padrão `temppwd`. Ao trocá-la, defina `ATEBEAGLE_BOARD_PASSWORD`.
- [ ] `dashboard.html` também fica em `/opt/atebeagle/src` na placa. Sincronizar exige nova
  baseline assinada.
- [ ] Ilustrações em `docs/assets`; as versões `_limpa` não têm a escrita. O mascote e o nome
  são da BeagleBoard: confira as regras de uso da marca antes de publicar a apresentação.
