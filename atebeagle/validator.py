"""Validador externo (roda no notebook/servidor, fora da placa).

Estados do dispositivo:
  UNKNOWN  -> ainda sem veredito válido
  TRUSTED  -> último veredito PASS, assinado, fresco e encadeado
  SUSPECT  -> PASS, mas a IA apontou comportamento atípico (revisão humana)
  REVOKED  -> FAIL, assinatura inválida, replay, cadeia quebrada ou silêncio
              (dead man's switch). Chave do dispositivo revogada; tokens de
              workload invalidados. Só sai daqui por re-provisionamento manual.

Endpoints:
  POST /verdict       envelope assinado do agente
  POST /data          dados do workload (exige token válido = State-Gated I/O)
  GET  /api/state     estado de todos os dispositivos (JSON)
  GET  /              painel para a demonstração
  POST /admin/reset   re-provisiona dispositivo (header X-Admin-Token)

  python3 -m atebeagle.validator --config validator.json
"""
from __future__ import annotations

import argparse
import hmac
import hashlib
import json
import os
import secrets
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import appraiser, config as cfgmod, crypto
from .anomaly import AnomalyDetector
from .common import b64d, b64e, canonical, read_json, sha256_hex, write_json

MAX_EVENTS = 200


class Validator:
    def __init__(self, cfg: dict, log=print):
        self.cfg = cfg
        self.log = log
        self.lock = threading.RLock()
        self.secret = secrets.token_bytes(32)
        self.devices = {}
        self.events = []
        self.anomaly = {}
        self.baselines = {}
        self.data_log = []
        saved = read_json(cfg["state_file"], {}) if cfg.get("state_file") else {}
        for did, dcfg in cfg["devices"].items():
            st = saved.get(did, {})
            self.devices[did] = {
                "device_id": did,
                "pubkey": st.get("pubkey", dcfg["pubkey"]),
                "state": st.get("state", "UNKNOWN"),
                "key_gen": st.get("key_gen", 0),
                "last_epoch": st.get("last_epoch", 0),
                "last_hash": st.get("last_hash", "genesis"),
                "last_seen": None,  # reinicia o relógio do dead man's switch ao subir
                "interval_s": st.get("interval_s", 60),
                "last_body": None,
                "reason": st.get("reason"),
                "anomaly": None,
            }
            if dcfg.get("baseline"):
                self.baselines[did] = read_json(dcfg["baseline"])
            a = cfg["anomaly"]
            self.anomaly[did] = AnomalyDetector(a["warmup"], a["threshold"]) if a["enabled"] else None

    # ---------------------------------------------------------------- persistência
    def _persist(self):
        if not self.cfg.get("state_file"):
            return
        keep = ("pubkey", "state", "key_gen", "last_epoch", "last_hash", "interval_s", "reason")
        write_json(self.cfg["state_file"], {d: {k: v[k] for k in keep} for d, v in self.devices.items()})

    def _event(self, did, kind, msg):
        ev = {"t": time.time(), "device": did, "kind": kind, "msg": msg}
        self.events.append(ev)
        del self.events[:-MAX_EVENTS]
        self.log(f"[{kind}] {did}: {msg}")

    # ---------------------------------------------------------------- revogação
    def revoke(self, did, reason):
        d = self.devices[did]
        if d["state"] != "REVOKED":
            d["state"] = "REVOKED"
            d["reason"] = reason
            d["key_gen"] += 1  # invalida todos os tokens emitidos
            self._event(did, "REVOKED", reason)
            self._persist()

    def reset(self, did, new_pubkey=None):
        with self.lock:
            d = self.devices[did]
            if new_pubkey:
                d["pubkey"] = new_pubkey
            d.update(state="UNKNOWN", reason=None, last_epoch=0, last_hash="genesis", last_seen=None, alerts=[])
            d["key_gen"] += 1
            self._event(did, "RESET", "re-provisionado pelo administrador")
            self._persist()

    # ---------------------------------------------------------------- tokens
    def _issue_token(self, d, now):
        ttl = d["interval_s"] * self.cfg["token_ttl_factor"]
        payload = canonical({"d": d["device_id"], "g": d["key_gen"], "exp": now + ttl})
        mac = hmac.new(self.secret, payload, hashlib.sha256).digest()
        return b64e(payload) + "." + b64e(mac)

    def check_token(self, token, now=None):
        now = now or time.time()
        if not token:
            return False, "sem token (dispositivo não atestado)"
        try:
            p64, m64 = token.split(".")
            payload = b64d(p64)
            if not hmac.compare_digest(hmac.new(self.secret, payload, hashlib.sha256).digest(), b64d(m64)):
                return False, "token com MAC inválido"
            p = json.loads(payload)
        except Exception:
            return False, "token malformado"
        d = self.devices.get(p["d"])
        if not d:
            return False, "dispositivo desconhecido"
        if p["g"] != d["key_gen"]:
            return False, "token revogado"
        if p["exp"] < now:
            return False, "token expirado"
        if d["state"] == "REVOKED" or d["state"] == "UNKNOWN":
            return False, f"dispositivo {d['state']}"
        if d["state"] == "SUSPECT" and self.cfg["suspect_blocks_io"]:
            return False, "dispositivo SUSPECT"
        return True, p["d"]

    # ---------------------------------------------------------------- vereditos
    def handle_verdict(self, env: dict, now=None) -> dict:
        now = now or time.time()
        with self.lock:
            body = env.get("body") or {}
            did = body.get("device_id")
            d = self.devices.get(did)
            if not d:
                return {"accepted": False, "reason": "dispositivo não registrado"}
            if d["state"] == "REVOKED":
                return {"accepted": False, "reason": f"chave revogada: {d['reason']}"}
            raw = canonical(body)
            if env.get("alg") != "Ed25519" or not crypto.verify(crypto.load_public_b64(d["pubkey"]), raw,
                                                                 env.get("sig", "")):
                # assinatura inválida não revoga: senão qualquer um na rede derrubaria o dispositivo
                self._event(did, "REJECT", "assinatura inválida")
                return {"accepted": False, "reason": "assinatura inválida"}
            epoch = int(body.get("epoch", 0))
            if epoch <= d["last_epoch"]:
                self._event(did, "REPLAY", f"época {epoch} <= {d['last_epoch']}")
                return {"accepted": False, "reason": "replay: época repetida ou antiga"}
            if abs(now - float(body.get("ts", 0))) > self.cfg["max_clock_skew_s"]:
                self._event(did, "REJECT", "veredito fora da janela de tempo")
                return {"accepted": False, "reason": "veredito velho ou relógio dessincronizado"}
            gap = epoch - d["last_epoch"]
            if d["last_epoch"] and gap == 1 and body.get("prev_hash") != d["last_hash"]:
                self.revoke(did, "cadeia de vereditos quebrada (prev_hash não confere)")
                return {"accepted": False, "reason": "cadeia quebrada"}
            if d["last_epoch"] and gap > self.cfg["max_epoch_gap"] + 1:
                self.revoke(did, f"{gap - 1} vereditos perdidos")
                return {"accepted": False, "reason": "lacuna de épocas"}
            if gap > 1 and d["last_epoch"]:
                self._event(did, "GAP", f"{gap - 1} veredito(s) não recebido(s)")

            prev_seen = d["last_seen"]
            d.update(last_epoch=epoch, last_hash=sha256_hex(raw), last_seen=now,
                     interval_s=float(body.get("interval_s", 60)), last_body=body)

            # Reavaliação remota: o validador refaz o appraisal L2 com SUA cópia da baseline.
            remote = []
            if did in self.baselines and isinstance(body.get("evidence"), dict):
                remote = appraiser.appraise_l2(body["evidence"], self.baselines[did],
                                               appraiser.prefixes_from_baseline(self.baselines[did]),
                                               root=None, check_missing=False)
            if body.get("status") != "PASS" or appraiser.decide(remote) == "FAIL":
                fs, seen = [], set()
                for f in body.get("findings", []) + [f.to_dict() for f in remote]:
                    k = (f.get("layer"), f.get("kind"), f.get("subject"))
                    if k not in seen:
                        seen.add(k)
                        fs.append(f)
                why = "; ".join(f"{f['layer']} {f['kind']} {f['subject']}" for f in fs[:3]) or "status FAIL"
                if body.get("status") == "PASS":
                    why = "dispositivo reportou PASS mas a reavaliação remota falhou: " + why
                self.revoke(did, why)
                return {"accepted": False, "reason": "FAIL", "detail": why}

            # Achado de aviso não revoga, mas precisa ficar registrado: é um alerta de ameaça.
            warns = sorted(f"{f.get('layer')} {f.get('kind')} {f.get('subject')}" for f in body.get("findings", []))
            if warns != d.get("alerts", []):
                if warns:
                    self._event(did, "ALERT", "; ".join(warns[:3]))
                d["alerts"] = warns

            tel = dict(body.get("telemetry") or {})
            tel["arrival_jitter_s"] = abs((now - prev_seen) - d["interval_s"]) if prev_seen else 0.0
            det = self.anomaly.get(did)
            # Só a duração é desconsiderada no ciclo frio; carga, processos e o resto seguem avaliados.
            res = det.score(tel, ignore=("cycle_ms",) if tel.get("cold_start") else ()) if det else None
            d["anomaly"] = res
            if res and res["anomaly"]:
                if d["state"] != "SUSPECT":
                    self._event(did, "SUSPECT", f"IA: {res['feature']} atípico (z={res.get('z', res['score'])}, {res['model']})")
                d["state"] = "SUSPECT"
            else:
                if d["state"] != "TRUSTED":
                    self._event(did, "TRUSTED", f"época {epoch} PASS")
                d["state"] = "TRUSTED"
            self._persist()
            return {"accepted": True, "state": d["state"], "token": self._issue_token(d, now)}

    def check_deadman(self, now=None):
        now = now or time.time()
        with self.lock:
            for did, d in self.devices.items():
                if d["state"] in ("TRUSTED", "SUSPECT") and d["last_seen"]:
                    limit = d["interval_s"] * self.cfg["deadman_factor"]
                    if now - d["last_seen"] > limit:
                        self.revoke(did, f"dead man's switch: {now - d['last_seen']:.0f}s sem veredito")

    def handle_data(self, req: dict) -> dict:
        ok, who = self.check_token(req.get("token", ""))
        with self.lock:
            if not ok:
                self._event(req.get("device_id", "?"), "IO_BLOCKED", who)
                return {"accepted": False, "reason": who}
            self.data_log.append({"t": time.time(), "device": who, "value": req.get("value")})
            del self.data_log[:-50]
            return {"accepted": True}

    def snapshot(self):
        with self.lock:
            devs = []
            for d in self.devices.values():
                b = d["last_body"] or {}
                devs.append({k: d[k] for k in ("device_id", "state", "last_epoch", "last_seen", "interval_s",
                                                 "reason", "anomaly")} |
                            {"findings": b.get("findings", []), "l2": b.get("l2"), "l3": b.get("l3"),
                             "telemetry": b.get("telemetry")})
            return {"now": time.time(), "devices": devs, "events": self.events[-40:][::-1],
                    "data": self.data_log[-10:][::-1]}


# ------------------------------------------------------------------- HTTP
DASHBOARD = os.path.join(os.path.dirname(__file__), "dashboard.html")


def make_handler(v: Validator):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code, obj):
            data = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self):
            n = int(self.headers.get("Content-Length", 0))
            if n > 4 * 1024 * 1024:
                raise ValueError("payload grande demais")
            return json.loads(self.rfile.read(n).decode() or "{}")

        def do_GET(self):
            if self.path.startswith("/api/state"):
                return self._json(200, v.snapshot())
            if self.path in ("/", "/index.html"):
                with open(DASHBOARD, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                return self.wfile.write(data)
            self._json(404, {"error": "não encontrado"})

        def do_POST(self):
            try:
                body = self._body()
            except Exception as e:
                return self._json(400, {"accepted": False, "reason": str(e)})
            if self.path == "/verdict":
                r = v.handle_verdict(body)
                return self._json(200 if r["accepted"] else 403, r)
            if self.path == "/data":
                r = v.handle_data(body)
                return self._json(200 if r["accepted"] else 403, r)
            if self.path == "/admin/reset":
                if not hmac.compare_digest(self.headers.get("X-Admin-Token", ""), v.cfg["admin_token"]):
                    return self._json(401, {"error": "não autorizado"})
                if body.get("device_id") not in v.devices:
                    return self._json(404, {"error": "dispositivo desconhecido"})
                v.reset(body["device_id"], body.get("pubkey"))
                return self._json(200, {"ok": True})
            self._json(404, {"error": "não encontrado"})

    return H


class _Server(ThreadingHTTPServer):
    """No Windows, SO_REUSEADDR deixa outro processo ouvir na mesma porta sem erro: uma
    segunda instância ficaria muda e um processo local poderia sequestrar a porta do
    validador. Lá a porta passa a ser exclusiva; no Linux nada muda."""
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        if os.name == "nt":
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def serve(v: Validator, host, port, tls=None):
    srv = _Server((host, port), make_handler(v))
    if tls and tls.get("cert"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(tls["cert"], tls["key"])
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)

    def watchdog():
        while True:
            time.sleep(1)
            v.check_deadman()

    threading.Thread(target=watchdog, daemon=True).start()
    return srv


def main():
    ap = argparse.ArgumentParser(description="Validador ATEBEAGLE")
    ap.add_argument("--config", required=True)
    a = ap.parse_args()
    cfg = cfgmod.load_validator(a.config)
    v = Validator(cfg)
    srv = serve(v, cfg["listen"], cfg["port"], cfg["tls"])
    print(f"validador em http://{cfg['listen']}:{cfg['port']}  (painel em /)")
    srv.serve_forever()


if __name__ == "__main__":
    main()
