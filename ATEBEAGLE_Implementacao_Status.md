# ATEBEAGLE: estado da implementação (04/11/2026)

Instruções de revisão e pontos de atenção: [docs/REVISAO.md](docs/REVISAO.md).

Código nesta pasta (Python stdlib + cryptography, 22 testes passando no Windows). O Atebeagle.zip é anterior às correções para Windows e fica fora do repositório.

## Pronto e testado em simulação
- L2: parser do IMA (ima, ima-ng, ima-sig), coletor de hash direto (plano B), coletor híbrido (padrão).
- Baseline dourada assinada (Ed25519) pela autoridade offline; o agente rejeita baseline adulterada.
- L3.1: sys_call_table (módulo atebeagle_kint.ko ou kallsyms), módulos novos, taint, referência por boot.
- Publicador: época monotônica com fsync, cadeia prev_hash, assinatura Ed25519, boot_id, timestamp.
- Validador: anti-replay, cadeia, janela de tempo, reavaliação remota da evidência L2, dead man's switch (2,5 x intervalo), revogação de chave, re-provisionamento pelo administrador.
- State-Gated I/O: token HMAC curto ligado à geração da chave; o gate local apaga o token, acende o LED USR3 e para o workload.
- IA: Isolation Forest + z-score robusto sobre a telemetria; leva a SUSPECT e nunca revoga sozinha.
- Painel web da demo, workload sensor, ataques controlados, demo simulada sem placa (plano B).
- Diagrama draw.io gerado por script; docs ENT8_REQUISITOS, MATRIZ_DECISAO, PLANO_BANCADA e esqueleto da ANALISE_L1.

## Painel redesenhado (04/11/2026)
Arquivo: `atebeagle/dashboard.html`, reescrito como cena de bancada: BeagleBone Black em SVG (vista superior, em escala, conforme o manual de referência) ligada por cabo ao notebook validador, com o estado na tela do notebook.

Conferido em navegador:
- TRUSTED, REVOKED (`tamper`, `drop`, `module`) e SUSPECT (`miner`), com destaque no componente correspondente.
- Animação do veredito e do token no cabo, e largura de 390 px sem rolagem horizontal.

Para rodar: `py scripts\sim_demo.py --interval 5` e abrir `http://localhost:8700`. O painel é lido a cada requisição, então não é preciso reiniciar a demo para ver mudanças no HTML.

O painel agora cobre o que foi definido na Ideação (ENT#7), no pôster e na apresentação: ciclo de 5 etapas, camadas L3/L2/L1 e IA, análise de adversários, 4 proteções do protocolo, áreas do CyBOK, base MITRE e integrantes. A demo ganhou `delete`, `replay`, `forge` e `chain`.

Decidido em 04/11/2026:
- Alerta: o veredito assinado continua PASS ou FAIL. Alerta é PASS com achado de aviso ou SUSPECT da IA; o painel mostra a ameaça e o validador registra o evento ALERT.
- SUSPECT falso: no primeiro ciclo depois de iniciar o agente, a IA não compara a duração do ciclo. Os demais sinais seguem avaliados.
- Chaves: `provision.sh` recusa pasta sincronizada; usar `ATEBEAGLE_KEYS=/c/atebeagle/keys`.

Divergências entre documentos e código, a resolver:
- Rootkit: pôster e slides dizem "contido"; `docs/ANALISE_L1.md` diz que ring 0 pode falsificar o agente. O painel separa os dois casos.
- Detecção "até 60 s": vale para a adulteração; o silêncio só revoga após 2,5 intervalos (150 s).

## Pendente
- Repetir os testes no Linux ou na placa depois das correções para Windows.
- Rodar check_board.sh na placa (portão do IMA) e escolher o coletor hybrid ou fs.
- Compilar atebeagle_kint.ko (precisa dos headers do kernel; kernel/build.sh).
- Gerar a baseline real, ajustar falsos positivos e ensaiar os ataques.
- Apresentação, relatório ABNT e análise do L1.
