"""State-Gated I/O do lado da placa.

O workload só consegue falar com o mundo usando o token de capacidade que o
validador emite a cada veredito PASS aceito (curta duração). Na falha local o
agente apaga o token, acende o LED USR3 e para o serviço do workload. Do lado
do validador, a revogação invalida todos os tokens já emitidos (ver validator.py).
"""
from __future__ import annotations

import os
import subprocess

from .common import atomic_write, retry_if_locked


class LocalGate:
    def __init__(self, token_file: str, led: str | None = None, on_fail_cmd=None, log=print):
        self.token_file = token_file
        self.led = led
        self.on_fail_cmd = on_fail_cmd
        self.log = log

    def _led(self, on: bool):
        if self.led and os.path.exists(self.led):
            try:
                with open(self.led, "w") as f:
                    f.write("1" if on else "0")
            except OSError:
                pass

    def grant(self, token: str):
        atomic_write(self.token_file, token.encode(), 0o640)
        self._led(False)

    def revoke(self, reason: str):
        try:
            retry_if_locked(os.unlink, self.token_file)
        except FileNotFoundError:
            pass
        self._led(True)
        self.log(f"[gate] workload bloqueado: {reason}")
        if self.on_fail_cmd:
            try:
                subprocess.run(self.on_fail_cmd, timeout=10, check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except (OSError, subprocess.SubprocessError):
                pass
