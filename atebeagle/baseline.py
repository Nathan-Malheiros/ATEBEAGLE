"""Golden baseline assinada.

A baseline é gerada numa imagem confiável (placa recém-gravada, offline) e
assinada pela chave da *autoridade de baseline*, que NÃO fica na placa. O
agente só aceita a baseline se a assinatura conferir: um atacante com root
que edite /etc/atebeagle/baseline.json para "aprovar" seu binário é detectado.

Uso:
  python3 -m atebeagle.baseline build --root / --paths /usr/bin /opt/atebeagle \
      --sign-key keys/baseline_authority.key --out baseline.json
"""
from __future__ import annotations

import argparse
import os
import time

from . import crypto
from .common import HASH_ALGOS, canonical, hash_file, read_json, write_json
from .collectors.fs import _is_candidate


class BaselineError(Exception):
    pass


def build(root: str, paths, algos=HASH_ALGOS) -> dict:
    root = os.path.abspath(root)
    files = {}
    for p in paths:
        real = os.path.join(root, p.lstrip("/"))
        walk = [(os.path.dirname(real), [], [os.path.basename(real)])] if os.path.isfile(real) else os.walk(real)
        for dirpath, dirs, names in walk:
            dirs[:] = [x for x in dirs if x != "__pycache__"]
            for n in names:
                full = os.path.join(dirpath, n)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if not _is_candidate(st, n):
                    continue
                target = "/" + os.path.relpath(full, root).replace(os.sep, "/")
                files[target] = hash_file(full, algos)
    return {
        "version": 1,
        "created": int(time.time()),
        "algos": list(algos),
        "roots": list(paths),
        "files": files,
    }


def sign(baseline: dict, sk) -> dict:
    body = {k: v for k, v in baseline.items() if k != "signature"}
    return {**body, "signature": crypto.sign(sk, canonical(body))}


def verify(baseline: dict, pk) -> bool:
    sig = baseline.get("signature")
    if not sig:
        return False
    body = {k: v for k, v in baseline.items() if k != "signature"}
    return crypto.verify(pk, canonical(body), sig)


def load_verified(path: str, pubkey_path: str | None, require_signature: bool = True) -> dict:
    bl = read_json(path)
    if bl is None:
        raise BaselineError(f"baseline ausente: {path}")
    if require_signature:
        if not pubkey_path or not os.path.exists(pubkey_path):
            raise BaselineError("chave pública da autoridade de baseline ausente")
        if not verify(bl, crypto.load_public(pubkey_path)):
            raise BaselineError("ASSINATURA DA BASELINE INVÁLIDA")
    return bl


def main():
    ap = argparse.ArgumentParser(description="Golden baseline do ATEBEAGLE")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--root", default="/")
    b.add_argument("--paths", nargs="+", required=True)
    b.add_argument("--sign-key", required=True)
    b.add_argument("--out", required=True)
    v = sub.add_parser("verify")
    v.add_argument("baseline")
    v.add_argument("--pubkey", required=True)
    a = ap.parse_args()
    if a.cmd == "build":
        bl = sign(build(a.root, a.paths), crypto.load_private(a.sign_key))
        write_json(a.out, bl, 0o644)
        print(f"baseline com {len(bl['files'])} arquivos assinada em {a.out}")
    else:
        ok = verify(read_json(a.baseline), crypto.load_public(a.pubkey))
        print("OK" if ok else "INVÁLIDA")
        raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
