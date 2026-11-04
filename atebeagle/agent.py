"""Agente de atestação que roda na BeagleBone Black.

  sudo python3 -m atebeagle.agent --config /etc/atebeagle/agent.json         # ciclo contínuo
  sudo python3 -m atebeagle.agent --config /etc/atebeagle/agent.json --once  # um ciclo
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import time

from . import appraiser, config as cfgmod
from .baseline import BaselineError, load_verified
from .collectors.fs import FsCollector
from .collectors.ima import ImaCollector
from .collectors.kernel import KernelCollector, collect_telemetry
from .common import read_boot_id, read_json, write_json
from .gate import LocalGate
from .publisher import Publisher


class HybridCollector:
    """IMA para tudo que o kernel mediu + hash direto dos caminhos críticos.

    O IMA só remede um arquivo quando ele é aberto de novo; o hash direto pega a
    adulteração de um arquivo crítico já no ciclo seguinte, mesmo sem reexecução,
    e também detecta exclusão. Para o mesmo caminho, o hash direto prevalece.
    """

    def __init__(self, ima, fs):
        self.ima, self.fs = ima, fs

    def collect(self):
        a, b = self.ima.collect(), self.fs.collect()
        return {"source": "ima+fs", "entries": a["entries"] + b["entries"], "files": {**a["files"], **b["files"]}}


class Agent:
    def __init__(self, cfg: dict, log=print):
        self.cfg = cfg
        self.log = log
        os.makedirs(cfg["state_dir"], exist_ok=True)
        l2 = cfg["l2"]
        if l2["collector"] == "ima":
            self.l2 = ImaCollector(l2["ima_log"])
        elif l2["collector"] == "hybrid":
            self.l2 = HybridCollector(ImaCollector(l2["ima_log"]), FsCollector(l2["root"], l2["fs_paths"]))
        else:
            self.l2 = FsCollector(l2["root"], l2["fs_paths"])
        self.l3 = KernelCollector(cfg["l3"]["proc_root"], cfg["l3"]["kint_path"]) if cfg["l3"]["enabled"] else None
        self.pub = Publisher(cfg["validator_url"], cfg["device_key"], cfg["state_dir"], cfg["timeout_s"])
        g = cfg["gate"]
        self.gate = LocalGate(g["token_file"], g.get("led"), g.get("on_fail_cmd"), log)
        self.boot_id = read_boot_id(cfg["l3"]["proc_root"])
        self._stop = False
        self._cold = True  # o primeiro ciclo faz todos os hashes: duração não comparável

    # Referência L3 é capturada no primeiro ciclo de cada boot ("medição no boot").
    # Sem raiz de confiança em hardware (L1), essa captura é confiável apenas se o
    # boot foi limpo: limitação documentada na análise do L1.
    def _l3_reference(self, observed: dict) -> dict:
        path = os.path.join(self.cfg["state_dir"], "l3_reference.json")
        ref = read_json(path)
        if not ref or ref.get("boot_id") != self.boot_id:
            ref = {"boot_id": self.boot_id, **observed}
            write_json(path, ref)
            self.log(f"[l3] referência de boot registrada ({observed['syscall_source']})")
        return ref

    def cycle(self) -> dict:
        t0 = time.monotonic()
        findings = []
        l2cfg = self.cfg["l2"]
        evidence = {}
        try:
            bl = load_verified(l2cfg["baseline"], self.cfg.get("baseline_pubkey"))
            prefixes = l2cfg["monitored_prefixes"]
            if prefixes == "auto":
                prefixes = appraiser.prefixes_from_baseline(bl)
            obs = self.l2.collect()
            evidence = {p: d for p, d in obs["files"].items() if any(p.startswith(x) for x in prefixes)}
            findings += appraiser.appraise_l2(obs["files"], bl, prefixes,
                                              l2cfg["root"], l2cfg["check_missing"])
            l2_summary = {"source": obs["source"], "entries": obs["entries"]}
        except BaselineError as e:
            findings.append(appraiser.Finding("L2", "BASELINE_INVALID", str(e), "critical"))
            l2_summary = {"source": "error"}
        except OSError as e:
            findings.append(appraiser.Finding("L2", "COLLECTOR_ERROR", str(e), "high"))
            l2_summary = {"source": "error"}

        l3_summary = None
        if self.l3:
            k = self.l3.collect()
            findings += appraiser.appraise_l3(k, self._l3_reference(k))
            l3_summary = {"syscall_source": k["syscall_source"], "modules": len(k["modules"]),
                          "modules_digest": k["modules_digest"], "tainted": k["tainted"]}

        status = appraiser.decide(findings)
        tel = collect_telemetry(self.cfg["l3"]["proc_root"])
        tel["cycle_ms"] = round((time.monotonic() - t0) * 1000, 1)
        if self._cold:
            tel["cold_start"] = True
            self._cold = False
        tel["l2_entries"] = l2_summary.get("entries", 0)
        if l3_summary:
            tel["modules"] = l3_summary["modules"]

        body = {
            "device_id": self.cfg["device_id"],
            "boot_id": self.boot_id,
            "ts": time.time(),
            "interval_s": self.cfg["interval_s"],
            "status": status,
            "findings": [f.to_dict() for f in findings],
            "l2": l2_summary,
            "l3": l3_summary,
            "telemetry": tel,
        }
        if self.cfg.get("send_evidence"):
            body["evidence"] = evidence
        env = self.pub.seal(body)
        resp = self.pub.send(env)

        if status == "FAIL":
            self.gate.revoke("falha local: " + ", ".join(f"{f.kind} {f.subject}" for f in findings[:3]))
        elif resp.get("accepted") and resp.get("token"):
            self.gate.grant(resp["token"])
        elif not resp.get("offline"):
            self.gate.revoke("validador recusou: " + str(resp.get("reason")))
        self.log(f"[ciclo] época={env['body']['epoch']} status={status} achados={len(findings)} "
                 f"validador={'ok' if resp.get('accepted') else resp.get('reason')}")
        return {"envelope": env, "response": resp}

    def run(self):
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, "_stop", True))
        while not self._stop:
            start = time.monotonic()
            try:
                self.cycle()
            except Exception as e:  # o agente não pode morrer silenciosamente
                self.log(f"[erro] {e!r}")
            dt = self.cfg["interval_s"] - (time.monotonic() - start)
            while dt > 0 and not self._stop:
                time.sleep(min(1, dt))
                dt -= 1


def main():
    ap = argparse.ArgumentParser(description="Agente ATEBEAGLE")
    ap.add_argument("--config")
    ap.add_argument("--once", action="store_true")
    a = ap.parse_args()
    ag = Agent(cfgmod.load_agent(a.config))
    if a.once:
        print(json.dumps(ag.cycle()["response"], indent=2, ensure_ascii=False))
    else:
        ag.run()


if __name__ == "__main__":
    main()
