# Matriz de decisão

| Camada | Evento | Como é detectado | Severidade | Efeito no validador |
|---|---|---|---|---|
| L2 | ALTERED: hash difere da baseline | IMA (remedição após mudança) ou hash direto | crítica | REVOKED |
| L2 | UNAUTHORIZED: arquivo fora da baseline em diretório monitorado | IMA ou hash direto | crítica | REVOKED |
| L2 | MISSING: arquivo da baseline sumiu | verificação de existência | alta | REVOKED |
| L2 | BASELINE_INVALID: assinatura da baseline não confere | Ed25519 da autoridade | crítica | REVOKED |
| L2 | Agente reporta PASS mas evidência não bate | reavaliação remota no validador | crítica | REVOKED |
| L3.1 | SYSCALL_TABLE: ponteiros mudaram desde o boot | atebeagle_kint.ko (ou kallsyms) | crítica | REVOKED |
| L3.1 | MODULE_NEW: módulo carregado após o boot | /proc/modules | alta | REVOKED |
| L3.1 | MODULE_GONE / TAINT | /proc/modules, flag de taint | aviso | ALERTA: veredito PASS, evento ALERT no registro, sem revogar |
| Transporte | assinatura inválida | Ed25519 do dispositivo | rejeita | não revoga (evita DoS por terceiros) |
| Transporte | replay: época repetida ou antiga | contador monotônico | rejeita | registra REPLAY |
| Transporte | cadeia quebrada (prev_hash) | hash do veredito anterior | crítica | REVOKED |
| Transporte | lacuna > 3 épocas | contador | alta | REVOKED |
| Transporte | silêncio > 2,5 × intervalo | dead man's switch | crítica | REVOKED |
| IA | telemetria atípica sem violar regra | Isolation Forest / z-score | suspeita | ALERTA: SUSPECT (revisão humana) |

Princípio: a IA nunca revoga sozinha. A decisão de revogar é sempre de uma regra
determinística e explicável; a IA só levanta suspeita.

O veredito assinado tem dois valores, PASS e FAIL. O "Alerta" dos documentos do
projeto é a situação intermediária: PASS com achado de aviso, ou SUSPECT da IA. O
painel mostra a ameaça e o evento fica registrado, sem revogar.

No primeiro ciclo depois de iniciar o agente, a duração do ciclo não é comparada,
porque todos os hashes são refeitos. Os demais sinais seguem avaliados.

Saída do estado REVOKED: somente por re-provisionamento (POST /admin/reset com
token de administrador), de preferência com chave nova e baseline refeita.
