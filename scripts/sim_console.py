"""Modo simulado do console: as mesmas três telas, sem tocar na BeagleBone.

O validador, o agente e o workload são os de verdade; só a placa é falsa, com arquivos e um
/proc numa pasta temporária. O ciclo é de 10 s para as reações aparecerem depressa.

  py scripts\\sim_console.py     (normalmente pelo atebeagle.bat)
"""
from __future__ import annotations

import argparse
import base64
import json
import secrets
import shutil
import socket
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT, ROOT / "scripts", ROOT / "tests", ROOT / "workload"):
    sys.path.insert(0, str(extra))

import attack_console as ac  # noqa: E402
from atebeagle import baseline as bmod, config, crypto  # noqa: E402
from atebeagle.agent import Agent  # noqa: E402
from atebeagle.common import retry_if_locked, write_json  # noqa: E402
from atebeagle.validator import Validator, serve  # noqa: E402
from fakeboard import make_fake_board  # noqa: E402
import sensor  # noqa: E402

VALIDATOR_PORT = 8710
CONSOLE_PORT = 8711
WORKDIR = ROOT / "runs" / "launcher" / "sim"
INTERVAL_S = 10
WARMUP = 8
KILL_PAUSE_S = 5
WORKLOAD = "opt/atebeagle/workload"
BACKDOOR = "usr/local/bin/atb-backdoor"
IMPLANT = "usr/bin/atb-implante"
ROOTKIT_LINE = "dummy 16384 0 - Live 0x0\n"
BUSY_LOAD = "3.95 3.10 1.20 5/240 999\n"


class SimValidator(Validator):
    def snapshot(self):
        return dict(super().snapshot(), simulated=True)


class SimBoard:
    """Recebe os mesmos scripts que a placa real e aplica o efeito na placa falsa."""

    def __init__(self, root, proc, token_file, netcut_s):
        self.root, self.proc, self.token_file, self.netcut_s = Path(root), Path(proc), Path(token_file), netcut_s
        self.lock = threading.Lock()  # nada muda no meio de uma medição
        self.agent_on = True
        self.link_up = True
        self.last_env = None
        self.workload = (self.root / WORKLOAD).read_bytes()
        self.modules = (self.proc / "modules").read_text()
        self.loadavg = (self.proc / "loadavg").read_text()
        (self.root / "usr/local/bin").mkdir(parents=True, exist_ok=True)
        self.scripts = {
            ac.BY_ID["trojan"]["run"]: self._trojan,
            ac.BY_ID["backdoor"]["run"]: lambda: self._write(BACKDOOR),
            ac.BY_ID["sabotage"]["run"]: lambda: (self.root / WORKLOAD).unlink(missing_ok=True),
            ac.BY_ID["rootkit"]["run"]: lambda: (self.proc / "modules").write_text(self.modules + ROOTKIT_LINE),
            ac.BY_ID["miner"]["run"]: lambda: (self.proc / "loadavg").write_text(BUSY_LOAD),
            ac.BY_ID["stop_agent"]["run"]: lambda: setattr(self, "agent_on", False),
            ac.BY_ID["kill_agent"]["run"]: self._kill_agent,
            ac.BY_ID["netcut"]["run"]: self._netcut,
            ac.BY_ID["blind_spot"]["run"]: lambda: self._write(IMPLANT),
            ac.RESTORE_WORKLOAD: self._restore_workload,
            ac.BY_ID["backdoor"]["undo"]: lambda: (self.root / BACKDOOR).unlink(missing_ok=True),
            ac.BY_ID["rootkit"]["undo"]: lambda: (self.proc / "modules").write_text(self.modules),
            ac.BY_ID["miner"]["undo"]: lambda: (self.proc / "loadavg").write_text(self.loadavg),
            ac.BY_ID["stop_agent"]["undo"]: lambda: setattr(self, "agent_on", True),
            ac.BY_ID["blind_spot"]["undo"]: lambda: (self.root / IMPLANT).unlink(missing_ok=True),
            ac.RESTORE_ALL: self._restore_all,
        }

    def _write(self, rel):
        path = self.root / rel
        path.write_bytes(b"\x7fELF implante simulado")
        path.chmod(0o755)

    def _trojan(self):
        (self.root / WORKLOAD).write_bytes(self.workload + b"# trojan simulado\n")

    def _restore_workload(self):
        (self.root / WORKLOAD).write_bytes(self.workload)

    def _kill_agent(self):  # como o Restart=always do systemd: o agente volta sozinho
        self.agent_on = False
        threading.Timer(KILL_PAUSE_S, setattr, (self, "agent_on", True)).start()

    def _netcut(self):
        self.link_up = False
        timer = threading.Timer(self.netcut_s, setattr, (self, "link_up", True))
        timer.daemon = True
        timer.start()

    def _restore_all(self):
        self._restore_workload()
        for rel in (BACKDOOR, IMPLANT):
            (self.root / rel).unlink(missing_ok=True)
        (self.proc / "modules").write_text(self.modules)
        (self.proc / "loadavg").write_text(self.loadavg)
        self.agent_on = True

    def run(self, script, timeout=120):
        if not self.link_up:
            raise ac.BoardError("sem resposta da placa: rede cortada")
        if "workload.token" in script:
            return 0, self.token_file.read_text().strip() if self.token_file.exists() else ""
        if "base64 -d" in script:  # o grampo: entrega o último veredito que saiu da placa falsa
            env = self.last_env
            if not env:
                return 1, ""
            return 0, base64.b64encode(json.dumps(env).encode()).decode()
        action = self.scripts.get(script)
        if action:
            with self.lock:
                retry_if_locked(action)
            return 0, "(simulado) comando executado"
        return 0, ""  # relógio, ligar o workload: nada a fazer na placa falsa


def localize_catalog(interval_s, netcut_s):
    """Os textos do catálogo citam os tempos da placa real (ciclo de 60 s)."""
    dead_man = int(interval_s * 2.5)
    ac.NETCUT_S = netcut_s
    for attack in ac.ATTACKS:
        for key in ("story", "expect"):
            attack[key] = (attack[key].replace("130 s", f"{netcut_s} s").replace("150 s", f"{dead_man} s")
                           .replace("20 ciclos", f"{WARMUP} ciclos").replace(" Para sozinho em 2,5 min.", " Cancele para parar."))


def build(workdir, interval_s, validator_port, netcut_s):
    """Monta placa falsa, validador, agente e workload reais. Não inicia nenhuma thread."""
    workdir = Path(workdir)
    shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True)
    root, proc = make_fake_board(workdir)
    (root / "usr/local/bin").mkdir(parents=True, exist_ok=True)
    (root / "usr/local/bin/atebeagle-helper").write_bytes(b"#!/bin/sh\n")
    keys = workdir / "keys"
    pub = crypto.generate_keypair(str(keys / "device.key"), str(keys / "device.pub"))
    crypto.generate_keypair(str(keys / "authority.key"), str(keys / "authority.pub"))
    measured = ["/usr/local/bin", "/opt/atebeagle"]  # como na placa real: /usr/bin fica de fora
    baseline = workdir / "baseline.json"
    write_json(str(baseline), bmod.sign(bmod.build(str(root), measured),
                                        crypto.load_private(str(keys / "authority.key"))))
    token = secrets.token_hex(16)
    validator = SimValidator(config._merge(config.VALIDATOR_DEFAULTS, {
        "port": validator_port, "state_file": None, "admin_token": token,
        "devices": {"bbb-01": {"pubkey": pub, "baseline": str(baseline)}},
        "anomaly": {"enabled": True, "warmup": WARMUP, "threshold": 6.0},
    }))
    url = f"http://127.0.0.1:{validator_port}"
    agent_cfg = config._merge(config.AGENT_DEFAULTS, {
        "interval_s": interval_s, "state_dir": str(workdir / "state"), "device_key": str(keys / "device.key"),
        "baseline_pubkey": str(keys / "authority.pub"), "validator_url": url,
        "l2": {"collector": "fs", "root": str(root), "fs_paths": measured, "baseline": str(baseline)},
        "l3": {"proc_root": str(proc), "kint_path": str(workdir / "no_kint")},
        "gate": {"token_file": str(workdir / "run/workload.token"), "led": None, "on_fail_cmd": None},
    })
    board = SimBoard(root, proc, agent_cfg["gate"]["token_file"], netcut_s)
    return dict(validator=validator, agent=Agent(agent_cfg), board=board, url=url, token=token,
                token_file=agent_cfg["gate"]["token_file"], interval_s=interval_s, stop=threading.Event())


def agent_loop(sim):
    board, agent = sim["board"], sim["agent"]
    while not sim["stop"].is_set():
        with board.lock:  # confere dentro da trava: nenhum veredito sai depois de um corte
            if board.agent_on and board.link_up:
                try:
                    board.last_env = agent.cycle()["envelope"]
                except Exception as e:  # um arquivo travado não pode derrubar a demonstração
                    print("[agente] erro:", repr(e), flush=True)
        sim["stop"].wait(sim["interval_s"])


def sensor_loop(sim):
    while not sim["stop"].is_set():
        if sim["board"].link_up:
            sensor.send(sim["url"], sim["token_file"], "bbb-01")
        sim["stop"].wait(min(5, sim["interval_s"] / 2))


def start_threads(sim):
    for target in (agent_loop, sensor_loop):
        threading.Thread(target=target, args=(sim,), daemon=True).start()


def port_free(port):
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def main():
    ap = argparse.ArgumentParser(description="Modo simulado do console de ataque")
    ap.add_argument("--validator-port", type=int, default=VALIDATOR_PORT)
    ap.add_argument("--port", type=int, default=CONSOLE_PORT)
    a = ap.parse_args()
    for port in (a.validator_port, a.port):
        if not port_free(port):
            sys.exit(f"A porta {port} já está em uso: a simulação já deve estar aberta.")
    netcut_s = 30  # cobre a tentativa de envio aos 20 s, antes do limite de 25 s
    localize_catalog(INTERVAL_S, netcut_s)
    sim = build(WORKDIR, INTERVAL_S, a.validator_port, netcut_s)
    srv = serve(sim["validator"], "127.0.0.1", a.validator_port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    start_threads(sim)
    console = ac.Console(sim["board"], ac.Validator(sim["url"], sim["token"]), recover_timeout=90,
                         monitor_url=f"http://127.0.0.1:{a.validator_port}", simulated=True)
    console.start()
    server = ThreadingHTTPServer(("127.0.0.1", a.port), ac.make_handler(console, a.port))
    print(f"simulação: http://127.0.0.1:{a.validator_port} e http://127.0.0.1:{a.port}/ataques", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
