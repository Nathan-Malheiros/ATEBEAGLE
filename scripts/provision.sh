#!/bin/bash
# ATEBEAGLE - provisionamento feito no NOTEBOOK (o lado confiável).
#   bash scripts/provision.sh keys                 -> gera chaves (dispositivo + autoridade)
#   bash scripts/provision.sh baseline <user@bbb>  -> mede a placa limpa e assina a baseline
#   bash scripts/provision.sh push <user@bbb>      -> envia chave do dispositivo + baseline à placa
# A chave da autoridade de baseline NUNCA vai para a placa.
set -euo pipefail
cd "$(dirname "$0")/.."
# A chave da autoridade não deve ir para a nuvem: em pasta sincronizada, aponte ATEBEAGLE_KEYS para fora dela.
K="${ATEBEAGLE_KEYS:-keys}"; mkdir -p "$K"; chmod 700 "$K"
case "$(cd "$K" && pwd)" in
  *OneDrive*|*Dropbox*|*"Google Drive"*)
    echo "ERRO: $K está em pasta sincronizada com a nuvem." >&2
    echo "Use, por exemplo: export ATEBEAGLE_KEYS=/c/atebeagle/keys" >&2
    exit 1 ;;
esac
PATHS="/usr/bin /usr/sbin /usr/local/bin /opt/atebeagle"

case "${1:-}" in
  keys)
    [ -f "$K/device.key" ] || python3 -m atebeagle.crypto --out "$K/device"
    [ -f "$K/baseline_authority.key" ] || python3 -m atebeagle.crypto --out "$K/baseline_authority"
    echo "pubkey do dispositivo (vai no validator.json):"; cat "$K/device.pub" ;;
  baseline)
    H="${2:?user@ip da placa}"
    # Copia os binários monitorados da placa (que deve estar LIMPA: recém-gravada, offline)
    rm -rf .bbb_root && mkdir .bbb_root
    for p in $PATHS; do
      ssh "$H" "sudo tar -C / -cf - ${p#/} 2>/dev/null" | tar -C .bbb_root -xf - || true
    done
    python3 -m atebeagle.baseline build --root .bbb_root --paths $PATHS \
      --sign-key "$K/baseline_authority.key" --out baseline.json ;;
  push)
    H="${2:?user@ip da placa}"
    scp "$K/device.key" "$K/baseline_authority.pub" baseline.json "$H":/tmp/
    ssh "$H" "sudo install -d /etc/atebeagle && sudo install -m 600 /tmp/device.key /etc/atebeagle/ && \
              sudo install -m 644 /tmp/baseline_authority.pub /tmp/baseline.json /etc/atebeagle/ && \
              rm /tmp/device.key /tmp/baseline_authority.pub /tmp/baseline.json"
    echo "enviado." ;;
  *) echo "uso: $0 keys | baseline <user@bbb> | push <user@bbb>"; exit 1 ;;
esac
