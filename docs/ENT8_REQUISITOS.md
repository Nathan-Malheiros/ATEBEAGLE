# ENT#8: Projeto de Ciberproteção, versão final

Onde cada requisito da atividade é atendido.

## 1. Arcabouço e domínio (1 ponto)

**CyBOK v1.1.0**, categoria Infrastructure Security.

- Área central: **Cyber-Physical Systems Security**. O objeto protegido é um
  dispositivo embarcado que atua sobre o mundo físico; a atestação contínua é a
  forma de garantir que ele continua executando o que deveria.
- Áreas de apoio: Hardware Security (raiz de confiança e análise do L1), Applied
  Cryptography (Ed25519, HMAC, cadeia de hashes), Network Security (transporte e
  validação remota), Physical Layer and Telecommunications (canal USB/Ethernet).

## 2. Tecnologias de segurança (1 ponto)

| Tecnologia | Uso no projeto |
|---|---|
| Linux IMA | medição de integridade de executáveis e scripts pelo próprio kernel |
| Módulo de kernel próprio (atebeagle_kint) | leitura da sys_call_table para detectar hooking |
| Ed25519 | assinatura dos vereditos e da baseline |
| HMAC-SHA256 | tokens de capacidade curtos (State-Gated I/O) |
| Contador monotônico + cadeia de hashes | anti-replay e anti-supressão |
| Dead man's switch | silêncio equivale a falha (fail-safe) |
| systemd hardening | menor privilégio para agente e workload |
| **IA: Isolation Forest + z-score robusto** | detecção de comportamento atípico sobre a telemetria de cada ciclo |

**Até onde a IA ajuda.** A atestação responde "o software é o esperado?". Ela não
vê um abuso feito com software legítimo (um minerador rodando por um binário já
autorizado, um atacante atrasando vereditos de propósito). O detector aprende o
perfil normal do dispositivo (carga, processos, memória, duração do ciclo, jitter
de chegada) e marca desvios como SUSPECT. Limites assumidos no projeto: a IA não
revoga sozinha (falso positivo em sistema físico é caro e precisa ser explicável),
é treinada no validador e não na placa (512 MB de RAM), e pode ser envenenada se o
dispositivo já começar comprometido, por isso depende da baseline e da atestação
determinística. Atestação dá a garantia; IA amplia a visibilidade.

## 3. Infográfico de arquitetura (3 pontos)

`docs/arquitetura.drawio` (abrir em app.diagrams.net, exportar PNG ou PDF).
Regenerável com `python3 scripts/gen_drawio.py`.

## 4. Boas práticas do CyBOK (2 pontos)

Princípios de projeto seguro (Saltzer e Schroeder e princípios NIST, apresentados
na introdução do CyBOK) e como aparecem no código:

| Princípio | Aplicação |
|---|---|
| Fail-safe defaults | silêncio = FAIL; sem token não há I/O; dispositivo começa UNKNOWN |
| Complete mediation | todo envio de dado do workload passa pela verificação do token e do estado |
| Separation of privilege | a chave que assina a baseline nunca está na placa |
| Least privilege | units systemd com ProtectSystem/NoNewPrivileges; /proc/atebeagle_kint em 0400 |
| Open design | algoritmos públicos (Ed25519, SHA-256, HMAC); segurança vem das chaves |
| Economy of mechanism | só biblioteca padrão do Python + cryptography; módulo de kernel só lê |
| Compromise recording | cadeia de vereditos, log de eventos, estado persistido do validador |
| Defesa em profundidade | gate local + gate remoto + reavaliação remota + IA |
| Zero Trust | confiança reavaliada a cada ciclo, não só no boot |

Práticas da área CPS: atestação remota como mecanismo de detecção, resposta
automática que leva o sistema a estado seguro (workload inerte) e análise
explícita do que fica fora de alcance (L1, ver ANALISE_L1.md).

## 5. Apresentação com demonstração (3 pontos)

Roteiro da demo (cerca de 4 minutos):
1. Painel em TRUSTED, workload enviando temperatura.
2. `attacks.sh tamper`: em um ciclo o painel vai a REVOKED, o LED USR3 acende, o
   workload é bloqueado.
3. Re-provisionamento; `attacks.sh module`: L3 detecta módulo novo.
4. Replay de um veredito capturado: rejeitado. Na placa ainda falta ferramenta que
   capture o veredito; na demo simulada, use `replay`.
5. `attacks.sh silence`: a barra do dead man's switch enche e revoga.
6. (Opcional) carga atípica: IA gera o alerta e marca SUSPECT sem revogar.

Plano B sem placa: `scripts/sim_demo.py`. Pontos a revisar antes da entrega em
[REVISAO.md](REVISAO.md).
