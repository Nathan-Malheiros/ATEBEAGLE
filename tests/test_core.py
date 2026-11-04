import copy
import os
import threading

from atebeagle import appraiser, baseline as bmod, crypto
from atebeagle.agent import Agent
from atebeagle.collectors.ima import parse_log, latest_by_path
from atebeagle.collectors.kernel import KernelCollector
from atebeagle.common import read_json, write_json
from atebeagle.validator import Validator, serve

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def wire(board):
    """Agente falando direto com o validador (sem rede)."""
    v = Validator(board["validator"], log=lambda *_: None)
    ag = Agent(board["agent"], log=lambda *_: None)
    ag.pub.send = lambda env: v.handle_verdict(copy.deepcopy(env))
    return ag, v


# ------------------------------------------------------------------ IMA
def test_ima_parser_formats_and_latest():
    ms = parse_log(open(os.path.join(FIX, "ima_ng.log")).read())
    assert all(m.path != "boot_aggregate" for m in ms)
    latest = latest_by_path(ms)
    assert latest["/usr/bin/bash"].digest.startswith("ffff")  # última medição vence
    assert latest["/usr/bin/legacy"].algo == "sha1"
    assert "/opt/atebeagle/app with space" in latest  # ima-sig com espaço no caminho


# ------------------------------------------------------------------ baseline
def test_baseline_signature_detects_tampering(board):
    path = str(board["tmp"] / "baseline.json")
    pub = str(board["tmp"] / "keys/authority.pub")
    assert bmod.load_verified(path, pub)
    bl = read_json(path)
    bl["files"]["/usr/bin/evil"] = {"sha256": "00", "sha1": "00"}
    write_json(path, bl)
    try:
        bmod.load_verified(path, pub)
        assert False, "deveria falhar"
    except bmod.BaselineError:
        pass


# ------------------------------------------------------------------ appraiser
def test_appraiser_l2_cases(board):
    bl = read_json(str(board["tmp"] / "baseline.json"))
    obs = {p: "sha256:" + h["sha256"] for p, h in bl["files"].items()}
    pref = appraiser.prefixes_from_baseline(bl)
    assert appraiser.appraise_l2(obs, bl, pref, str(board["root"])) == []
    obs["/usr/bin/ls"] = "sha256:" + "0" * 64
    obs["/usr/bin/nc"] = "sha256:" + "1" * 64
    obs["/tmp/ignorado"] = "sha256:" + "2" * 64
    (board["root"] / "opt/atebeagle/workload").unlink()
    kinds = {(f.kind, f.subject) for f in appraiser.appraise_l2(obs, bl, pref, str(board["root"]))}
    assert ("ALTERED", "/usr/bin/ls") in kinds
    assert ("UNAUTHORIZED", "/usr/bin/nc") in kinds
    assert ("MISSING", "/opt/atebeagle/workload") in kinds
    assert not any(s == "/tmp/ignorado" for _, s in kinds)


def test_kernel_new_module_and_syscall_change(board):
    kc = KernelCollector(str(board["proc"]), "/nao/existe")
    ref = kc.collect()
    assert ref["syscall_source"] == "kallsyms"
    with open(board["proc"] / "modules", "a") as f:
        f.write("rootkit 4096 0 - Live 0x0\n")
    (board["proc"] / "kallsyms").write_text("c0100000 R sys_call_table\nbf000000 T sys_read\nc0200100 T sys_write\n")
    kinds = {f.kind for f in appraiser.appraise_l3(kc.collect(), ref)}
    assert {"MODULE_NEW", "SYSCALL_TABLE"} <= kinds


# ------------------------------------------------------------------ ponta a ponta
def test_e2e_pass_then_tamper_revokes(board):
    ag, v = wire(board)
    r = ag.cycle()["response"]
    assert r["accepted"] and v.devices["bbb-01"]["state"] == "TRUSTED"
    token = open(board["agent"]["gate"]["token_file"]).read()
    assert v.check_token(token)[0]

    (board["root"] / "usr/bin/ls").write_bytes(b"trojan\n")  # adulteração
    r = ag.cycle()["response"]
    assert not r["accepted"]
    d = v.devices["bbb-01"]
    assert d["state"] == "REVOKED" and "ALTERED" in d["reason"]
    assert not os.path.exists(board["agent"]["gate"]["token_file"])  # gate local
    assert v.check_token(token) == (False, "token revogado")          # gate remoto
    assert not ag.cycle()["response"]["accepted"]                     # chave continua revogada


def test_new_module_after_boot_revokes(board):
    ag, v = wire(board)
    ag.cycle()
    with open(board["proc"] / "modules", "a") as f:
        f.write("diamorphine 16384 0 - Live 0x0\n")
    ag.cycle()
    assert v.devices["bbb-01"]["state"] == "REVOKED"
    assert "MODULE_NEW diamorphine" in v.devices["bbb-01"]["reason"]


def test_replay_rejected(board):
    ag, v = wire(board)
    env = ag.pub.seal({"device_id": "bbb-01", "boot_id": "b", "ts": __import__("time").time(),
                       "interval_s": 60, "status": "PASS", "findings": []})
    assert v.handle_verdict(copy.deepcopy(env))["accepted"]
    r = v.handle_verdict(copy.deepcopy(env))
    assert not r["accepted"] and "replay" in r["reason"]


def test_forged_signature_rejected_without_revoking(board):
    ag, v = wire(board)
    env = ag.pub.seal({"device_id": "bbb-01", "boot_id": "b", "ts": __import__("time").time(),
                       "interval_s": 60, "status": "PASS", "findings": []})
    env["body"]["status"] = "PASS"
    env["body"]["findings"] = [{"x": 1}]  # altera conteúdo depois da assinatura
    r = v.handle_verdict(env)
    assert r["reason"] == "assinatura inválida"
    assert v.devices["bbb-01"]["state"] == "UNKNOWN"


def test_lying_device_caught_by_remote_appraisal(board):
    """Agente comprometido diz PASS, mas a evidência não bate com a baseline do validador."""
    ag, v = wire(board)
    ag.cycle()
    (board["root"] / "usr/bin/ls").write_bytes(b"trojan\n")
    import types
    from atebeagle import agent as agent_mod
    liar = types.SimpleNamespace(**{k: getattr(appraiser, k) for k in dir(appraiser) if not k.startswith("__")})
    liar.decide = lambda f: "PASS"           # agente adulterado mente o status
    liar.appraise_l2 = lambda *a, **k: []    # e esconde os achados
    real = agent_mod.appraiser
    try:
        agent_mod.appraiser = liar
        ag.cycle()
    finally:
        agent_mod.appraiser = real
    d = v.devices["bbb-01"]
    assert d["state"] == "REVOKED" and "reavaliação remota" in d["reason"]


def test_deadman_switch(board):
    ag, v = wire(board)
    ag.cycle()
    t = v.devices["bbb-01"]["last_seen"]
    v.check_deadman(t + 60 * 2.4)
    assert v.devices["bbb-01"]["state"] == "TRUSTED"
    v.check_deadman(t + 60 * 2.6)
    assert v.devices["bbb-01"]["state"] == "REVOKED"
    assert "dead man" in v.devices["bbb-01"]["reason"]


def test_broken_chain_revokes(board):
    ag, v = wire(board)
    ag.cycle()
    write_json(os.path.join(board["agent"]["state_dir"], "chain.json"), {"last": "f" * 64})
    ag.cycle()
    assert "cadeia" in v.devices["bbb-01"]["reason"]


def test_epoch_persists_across_restart(board):
    ag, v = wire(board)
    ag.cycle(); ag.cycle()
    ag2 = Agent(board["agent"], log=lambda *_: None)
    ag2.pub.send = lambda env: v.handle_verdict(copy.deepcopy(env))
    assert ag2.cycle()["envelope"]["body"]["epoch"] == 3
    assert v.devices["bbb-01"]["state"] == "TRUSTED"


def test_admin_reset_with_new_key(board):
    ag, v = wire(board)
    ag.cycle()
    (board["root"] / "usr/bin/ls").write_bytes(b"trojan\n")
    ag.cycle()
    assert v.devices["bbb-01"]["state"] == "REVOKED"
    (board["root"] / "usr/bin/ls").write_bytes(b"ls binary\n")
    newpub = crypto.generate_keypair(str(board["tmp"] / "keys/device.key"), str(board["tmp"] / "keys/device.pub"))
    v.reset("bbb-01", newpub)
    for f in ("epoch.json", "chain.json"):
        os.unlink(os.path.join(board["agent"]["state_dir"], f))
    ag2 = Agent(board["agent"], log=lambda *_: None)
    ag2.pub.send = lambda env: v.handle_verdict(copy.deepcopy(env))
    assert ag2.cycle()["response"]["accepted"]


def test_anomaly_flags_suspect(board):
    ag, v = wire(board)
    for i in range(15):
        (board["proc"] / "loadavg").write_text(f"0.{10 + i % 3} 0.08 0.05 1/{95 + i % 3} 1234\n")
        ag.cycle()
    assert v.devices["bbb-01"]["state"] == "TRUSTED"
    (board["proc"] / "loadavg").write_text("3.90 2.0 1.0 4/260 1234\n")  # minerador escondido
    ag.cycle()
    assert v.devices["bbb-01"]["state"] == "SUSPECT"


def test_warning_is_recorded_as_alert_without_revoking(board):
    ag, v = wire(board)
    ag.cycle()
    (board["proc"] / "sys/kernel/tainted").write_text("4096\n")
    ag.cycle(); ag.cycle()
    assert v.devices["bbb-01"]["state"] == "TRUSTED"
    alerts = [e for e in v.events if e["kind"] == "ALERT"]
    assert len(alerts) == 1 and "L3 TAINT" in alerts[0]["msg"]  # registra uma vez, não a cada ciclo


def test_cold_start_ignores_only_cycle_duration():
    from atebeagle.anomaly import AnomalyDetector
    det = AnomalyDetector(warmup=10, use_sklearn=False)
    normal = {"load1": 0.1, "procs_total": 95, "cycle_ms": 3000}
    for _ in range(12):
        det.score(normal)
    size = len(det.hist)
    assert det.score({**normal, "cycle_ms": 90000})["anomaly"]
    assert not det.score({**normal, "cycle_ms": 90000}, ignore=("cycle_ms",))["anomaly"]
    assert len(det.hist) == size  # o ciclo frio não entra no treino
    assert det.score({**normal, "cycle_ms": 90000, "load1": 3.9}, ignore=("cycle_ms",))["anomaly"]  # minerador segue visível


def test_http_roundtrip(board):
    v = Validator(board["validator"], log=lambda *_: None)
    srv = serve(v, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    board["agent"]["validator_url"] = f"http://127.0.0.1:{srv.server_address[1]}"
    ag = Agent(board["agent"], log=lambda *_: None)
    assert ag.cycle()["response"]["accepted"]
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(FIX), "..", "workload"))
    import sensor
    assert sensor.send(board["agent"]["validator_url"], board["agent"]["gate"]["token_file"], "bbb-01")["accepted"]
    (board["root"] / "usr/bin/bash").write_bytes(b"trojan\n")
    ag.cycle()
    r = sensor.send(board["agent"]["validator_url"], board["agent"]["gate"]["token_file"], "bbb-01")
    assert not r["accepted"]
    srv.shutdown()


def test_anomaly_fallback_without_sklearn():
    from atebeagle.anomaly import AnomalyDetector
    det = AnomalyDetector(warmup=10, use_sklearn=False)
    for i in range(12):
        assert not det.score({"load1": 0.1 + 0.01 * (i % 3), "procs_total": 95, "cycle_ms": 3000 + i})["anomaly"]
    r = det.score({"load1": 3.9, "procs_total": 260, "cycle_ms": 3000})
    assert r["anomaly"] and r["model"] == "robust_z"
