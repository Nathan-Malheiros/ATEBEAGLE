"""Placa simulada: um "root" falso e um /proc falso.

Fica fora do conftest.py porque scripts/sim_demo.py também usa, e a demo não deve
depender do pytest.
"""


def make_fake_board(tmp):
    root = tmp / "root"
    for rel, content in {
        "usr/bin/bash": b"#!bash v1\n",
        "usr/bin/ls": b"ls binary\n",
        "opt/atebeagle/workload": b"#!/bin/sh\necho sensor\n",
    }.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
        p.chmod(0o755)
    proc = tmp / "proc"
    (proc / "sys/kernel/random").mkdir(parents=True)
    (proc / "sys/kernel/random/boot_id").write_text("boot-1234\n")
    (proc / "sys/kernel/tainted").write_text("0\n")
    (proc / "modules").write_text("pru_rproc 32768 0 - Live 0x0\nuio_pdrv_genirq 16384 0 - Live 0x0\n")
    (proc / "kallsyms").write_text("c0100000 R sys_call_table\nc0200000 T sys_read\nc0200100 T sys_write\n")
    (proc / "loadavg").write_text("0.10 0.08 0.05 1/95 1234\n")
    (proc / "meminfo").write_text("MemTotal: 506000 kB\nMemAvailable: 300000 kB\n")
    return root, proc
