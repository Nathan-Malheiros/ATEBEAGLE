# Análise do L1 (Plataforma): esqueleto para a Ana Julia

## O que falta no AM335x GP
- Sem TPM e sem boot seguro ativável na variante GP (o ROM não verifica a
  assinatura do MLO/U-Boot).
- Sem armazenamento selado de chaves: `device.key` fica no eMMC, legível por root.
- Sem contador monotônico em hardware: o contador de épocas é software.

## O que o sistema consegue garantir mesmo assim
- Detecção de alteração de binários e módulos feita por atacante sem ring 0
  persistente, enquanto o kernel não estiver comprometido.
- Detecção de silêncio, replay e supressão seletiva de vereditos.
- Agente que mente PASS mas envia evidência real é pego na reavaliação remota.

## O que fica fora de alcance
- Atacante com ring 0 pode falsificar o log do IMA, a saída do kint e o próprio
  agente, assinando vereditos falsos com a chave roubada.
- Bootkit (MLO/U-Boot adulterado) antes do kernel: a referência de boot já nasce
  comprometida.
- Ataques físicos (JTAG, leitura do eMMC, glitching).

## Como seria fechado
TPM/fTPM ou SoC HS com boot seguro, chave do dispositivo selada e medições
estendidas em PCR, quote assinado pelo hardware em cada veredito.

(Desenvolver com referência à área Hardware Security do CyBOK.)
