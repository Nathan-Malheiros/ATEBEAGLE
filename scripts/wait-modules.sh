#!/bin/bash
# Segura o agente ate os modulos do kernel carregados no boot estabilizarem, para
# que a referencia L3 nao gere MODULE_NEW falso. Na BBB os modulos da PRU carregam
# ~60 s apos o boot, depois de ~40 s sem mudancas: so estabilidade nao basta.
# Reinicios depois de MAX_UPTIME nao esperam. Limitacao: modulo carregado nessa
# janela entra na referencia (ver docs/ANALISE_L1.md).
MIN_UPTIME=120; STABLE_S=30; MAX_UPTIME=240
last=""; stable=0
while :; do
    up=$(cut -d. -f1 /proc/uptime)
    cur=$(cut -d' ' -f1 /proc/modules | sort | md5sum)
    if [ "$cur" = "$last" ]; then stable=$((stable + 2)); else stable=0; last=$cur; fi
    if [ "$up" -ge "$MIN_UPTIME" ] && [ "$stable" -ge "$STABLE_S" ]; then
        echo "[wait-modules] estavel: uptime=${up}s modulos=$(wc -l </proc/modules)"; exit 0
    fi
    if [ "$up" -ge "$MAX_UPTIME" ]; then
        echo "[wait-modules] limite: uptime=${up}s estavel=${stable}s modulos=$(wc -l </proc/modules)"; exit 0
    fi
    sleep 2
done
