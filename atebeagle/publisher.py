"""Publicador: época monotônica, cadeia de hashes, assinatura e transporte.

Anti-replay em três camadas:
  * epoch     : contador persistido com fsync, nunca repete nem volta (sobrevive a reboot);
  * prev_hash : cada veredito aponta para o hash do anterior (apagar/reordenar quebra a cadeia);
  * ts+boot_id: frescor e identificação do boot.
Silêncio é tratado como falha pelo validador (dead man's switch).
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from . import crypto
from .common import canonical, read_json, sha256_hex, write_json


class EpochCounter:
    def __init__(self, path: str):
        self.path = path

    def current(self) -> int:
        st = read_json(self.path, {"epoch": 0})
        return int(st["epoch"])

    def next(self) -> int:
        e = self.current() + 1
        write_json(self.path, {"epoch": e})  # gravado ANTES de usar: nunca reaproveita época
        return e


class Publisher:
    def __init__(self, url: str, key_path: str, state_dir: str, timeout_s: float = 5):
        self.url = url.rstrip("/")
        self.sk = crypto.load_private(key_path)
        self.pubkey = crypto.public_b64(self.sk)
        self.epochs = EpochCounter(os.path.join(state_dir, "epoch.json"))
        self.chain_path = os.path.join(state_dir, "chain.json")
        self.timeout_s = timeout_s

    def seal(self, body: dict) -> dict:
        body = dict(body)
        body["epoch"] = self.epochs.next()
        body["prev_hash"] = read_json(self.chain_path, {"last": "genesis"})["last"]
        raw = canonical(body)
        env = {"alg": "Ed25519", "body": body, "sig": crypto.sign(self.sk, raw)}
        write_json(self.chain_path, {"last": sha256_hex(raw), "epoch": body["epoch"]})
        return env

    def send(self, envelope: dict):
        req = urllib.request.Request(self.url + "/verdict", data=json.dumps(envelope).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read().decode())
            except Exception:
                return {"accepted": False, "reason": f"HTTP {e.code}"}
        except (urllib.error.URLError, OSError) as e:
            return {"accepted": False, "reason": f"sem conexão: {e}", "offline": True}
