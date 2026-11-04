#!/bin/bash
# ATEBEAGLE - Portão de decisão: o que a BeagleBone oferece?
# Uso: sudo bash scripts/check_board.sh | tee board_report.txt
# Cole o board_report.txt de volta no chat: ele decide o caminho de L2 e L3.

ok()   { printf "  [OK]   %s\n" "$*"; }
no()   { printf "  [FALTA] %s\n" "$*"; }
info() { printf "  [i]    %s\n" "$*"; }
sec()  { printf "\n== %s ==\n" "$*"; }

[ "$(id -u)" = 0 ] || echo "AVISO: rode com sudo para ver IMA, kallsyms e config."

sec "Sistema"
info "kernel: $(uname -r)  arch: $(uname -m)"
[ -f /etc/os-release ] && info "distro: $(. /etc/os-release; echo "$PRETTY_NAME")"
[ -f /ID.txt ] && info "imagem bb.org: $(head -1 /ID.txt)"
info "modelo: $(tr -d '\0' < /proc/device-tree/model 2>/dev/null)"
info "RAM: $(awk '/MemTotal/{print $2/1024 " MB"}' /proc/meminfo)  livre: $(awk '/MemAvailable/{print $2/1024 " MB"}' /proc/meminfo)"
info "disco /: $(df -h / | awk 'NR==2{print $4 " livres de " $2}')"
info "data: $(date -Is)  (relógio importa para o validador; sem RTC a placa volta a 2000 após reboot)"

sec "Configuração do kernel"
CFG=""
if [ -r /proc/config.gz ]; then CFG="zcat /proc/config.gz"
elif [ -r "/boot/config-$(uname -r)" ]; then CFG="cat /boot/config-$(uname -r)"
fi
if [ -n "$CFG" ]; then
  for k in CONFIG_INTEGRITY CONFIG_IMA CONFIG_IMA_MEASURE_PCR_IDX CONFIG_IMA_NG_TEMPLATE \
           CONFIG_IMA_DEFAULT_HASH CONFIG_IMA_WRITE_POLICY CONFIG_IMA_READ_POLICY CONFIG_IMA_APPRAISE \
           CONFIG_SECURITYFS CONFIG_KALLSYMS CONFIG_KALLSYMS_ALL CONFIG_MODULES CONFIG_KPROBES \
           CONFIG_DEBUG_INFO_BTF CONFIG_BPF_SYSCALL CONFIG_AUDIT CONFIG_STRICT_KERNEL_RWX; do
    v=$($CFG | grep -E "^$k=|^# $k is not set" | head -1)
    [ -z "$v" ] && v="(ausente)"
    printf "  %-28s %s\n" "$k" "$v"
  done
else
  no "config do kernel não encontrada (/proc/config.gz nem /boot/config-*)"
fi

sec "IMA em execução"
mount | grep -q securityfs && ok "securityfs montado" || no "securityfs não montado (sudo mount -t securityfs none /sys/kernel/security)"
L=/sys/kernel/security/ima/ascii_runtime_measurements
if [ -r "$L" ]; then
  n=$(wc -l < "$L"); ok "log IMA presente: $n medições"
  info "template/hash: $(sed -n 2p "$L" | awk '{print $3, substr($4,1,index($4,":"))}')"
  [ "$n" -le 1 ] && info "só boot_aggregate: falta política. Adicione ima_policy=tcb na cmdline (uEnv.txt)"
else
  no "log IMA ausente -> plano B: coletor 'fs' (hash direto) e recompilar kernel se der tempo"
fi
info "cmdline: $(cat /proc/cmdline)"

sec "L3 (kernel em execução)"
info "kptr_restrict=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)  tainted=$(cat /proc/sys/kernel/tainted)"
grep -m1 ' sys_call_table$' /proc/kallsyms >/dev/null 2>&1 && info "sys_call_table: $(grep -m1 ' sys_call_table$' /proc/kallsyms)" || no "sys_call_table não visível em kallsyms"
info "módulos carregados: $(wc -l < /proc/modules)"
if [ -d "/lib/modules/$(uname -r)/build" ]; then ok "headers do kernel instalados (dá para compilar o módulo kint)"
else no "headers ausentes: sudo apt install linux-headers-$(uname -r)  (ou módulo kint fica de fora)"; fi
[ -f /sys/kernel/btf/vmlinux ] && ok "BTF presente (eBPF CO-RE possível)" || info "sem BTF (eBPF comportamental fica de fora, como previsto)"

sec "Userspace"
command -v python3 >/dev/null && ok "$(python3 --version)" || no "python3"
python3 -c "import cryptography; print(cryptography.__version__)" >/dev/null 2>&1 \
  && ok "python3-cryptography $(python3 -c 'import cryptography;print(cryptography.__version__)')" \
  || no "python3-cryptography (sudo apt install python3-cryptography)"
command -v gcc >/dev/null && ok "gcc $(gcc -dumpversion)" || no "gcc"
command -v git >/dev/null && ok "git" || no "git"
systemctl is-active cloud9.service >/dev/null 2>&1 && info "Cloud9 ativo (porta 3000)"

sec "LEDs e rede"
ls -d /sys/class/leds/*usr* 2>/dev/null | sed 's/^/  [i]    /'
ip -4 -o addr | awk '{print "  [i]    " $2 " " $4}'
echo
echo "Fim. Cole este relatório no chat."
