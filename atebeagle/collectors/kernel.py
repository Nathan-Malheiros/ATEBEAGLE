"""Coletor L3.1: integridade do kernel em tempo de execução.

Fontes, em ordem de preferência:
  1. /proc/atebeagle_kint  (módulo kernel/atebeagle_kint.c): lista os ponteiros
     reais da sys_call_table. Detecta hooking por sobrescrita da tabela.
  2. /proc/kallsyms        : endereços de sys_call_table e dos símbolos sys_*.
     Mais fraco (não vê sobrescrita de ponteiro), mas não exige módulo.
Também enumera /proc/modules e lê o flag de taint do kernel.
"""
from __future__ import annotations

import os

from ..common import sha256_hex


def _read(path: str):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return None


class KernelCollector:
    def __init__(self, proc_root: str = "/proc", kint_path: str = "/proc/atebeagle_kint"):
        self.proc_root = proc_root
        self.kint_path = kint_path

    def _modules(self):
        txt = _read(os.path.join(self.proc_root, "modules")) or ""
        mods = []
        for line in txt.splitlines():
            f = line.split()
            if len(f) >= 2:
                mods.append(f"{f[0]}:{f[1]}")
        return sorted(mods)

    def _syscall_table(self):
        txt = _read(self.kint_path)
        if txt:
            return "lkm", sha256_hex(txt.strip().encode())
        ks = _read(os.path.join(self.proc_root, "kallsyms"))
        if ks:
            sel = []
            for line in ks.splitlines():
                f = line.split()
                if len(f) >= 3 and (f[2] == "sys_call_table" or f[2].startswith("sys_")):
                    sel.append(f"{f[2]}={f[0]}")
            if sel:
                sel.sort()
                restricted = all(s.endswith("=" + "0" * len(s.split("=")[1])) for s in sel)
                return ("kallsyms-restricted" if restricted else "kallsyms"), sha256_hex("\n".join(sel).encode())
        return "unavailable", None

    def collect(self) -> dict:
        mods = self._modules()
        src, digest = self._syscall_table()
        tainted = _read(os.path.join(self.proc_root, "sys/kernel/tainted"))
        return {
            "modules": mods,
            "modules_digest": sha256_hex("\n".join(mods).encode()),
            "syscall_source": src,
            "syscall_digest": digest,
            "tainted": int(tainted.strip()) if tainted and tainted.strip().isdigit() else None,
        }


def collect_telemetry(proc_root: str = "/proc") -> dict:
    """Sinais leves para o detector de anomalias do validador."""
    t = {}
    la = _read(os.path.join(proc_root, "loadavg"))
    if la:
        parts = la.split()
        t["load1"] = float(parts[0])
        if "/" in parts[3]:
            t["procs_total"] = int(parts[3].split("/")[1])
    mi = _read(os.path.join(proc_root, "meminfo"))
    if mi:
        for line in mi.splitlines():
            if line.startswith("MemAvailable:"):
                t["mem_avail_kb"] = int(line.split()[1])
    return t
