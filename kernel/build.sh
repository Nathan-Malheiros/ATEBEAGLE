#!/bin/bash
# Compila o atebeagle_kint.ko na placa (precisa de linux-headers-$(uname -r)).
#   bash kernel/build.sh          compila
#   bash kernel/build.sh clean    limpa
set -e
cd "$(dirname "$0")"
make -C "/lib/modules/$(uname -r)/build" M="$PWD" "${1:-modules}"
