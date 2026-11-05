#!/bin/bash
# ATEBEAGLE - instala o agente na BeagleBone.
# Pré-requisito: repo copiado para a placa (ex.: /opt/atebeagle/src) e chaves
# geradas no notebook com scripts/provision.sh.
# Uso: sudo bash scripts/setup_board.sh <ip_do_validador> [hybrid|ima|fs]
#   hybrid (padrão): log IMA + hash direto de /opt/atebeagle e /usr/local/bin
#   fs: plano B se o kernel não tiver IMA
set -euo pipefail
VALIDATOR_IP="${1:?informe o IP do validador (ex.: 192.168.7.1)}"
COLLECTOR="${2:-hybrid}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"

apt-get install -y python3-cryptography >/dev/null || echo "aviso: instale python3-cryptography manualmente"

install -d -m 755 /opt/atebeagle /etc/atebeagle
install -d -m 700 /var/lib/atebeagle
rsync -a --delete --exclude tests --exclude .git "$SRC/" /opt/atebeagle/src/ 2>/dev/null || cp -r "$SRC/." /opt/atebeagle/src/
install -m 755 "$SRC/workload/sensor.py" /opt/atebeagle/workload.py
# O agente roda como root a partir daqui: copia vinda de NTFS/WSL pode chegar com 777.
find /opt/atebeagle ! -type l -perm /022 -exec chmod go-w {} +
install -m 755 "$SRC/scripts/wait-modules.sh" /etc/atebeagle/wait-modules.sh

for f in device.key baseline_authority.pub; do
  [ -f "/etc/atebeagle/$f" ] || { echo "falta /etc/atebeagle/$f (copie do notebook)"; exit 1; }
done
chmod 600 /etc/atebeagle/device.key

cat > /etc/atebeagle/agent.json <<EOF
{
  "device_id": "bbb-01",
  "interval_s": 60,
  "validator_url": "http://${VALIDATOR_IP}:8700",
  "l2": { "collector": "${COLLECTOR}", "fs_paths": ["/opt/atebeagle", "/usr/local/bin"] }
}
EOF

install -m 644 "$SRC/systemd/atebeagle-agent.service" /etc/systemd/system/
sed "s#__VALIDATOR__#http://${VALIDATOR_IP}:8700#" "$SRC/systemd/atebeagle-workload.service" \
  > /etc/systemd/system/atebeagle-workload.service
systemctl daemon-reload
echo "Instalado. Próximo: gerar baseline (scripts/provision.sh baseline) e então:"
echo "  sudo systemctl enable --now atebeagle-agent atebeagle-workload"
