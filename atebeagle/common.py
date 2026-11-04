"""Utilitários compartilhados: JSON canônico, hashes, escrita atômica."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import time

HASH_ALGOS = ("sha256", "sha1")


def canonical(obj) -> bytes:
    """Serialização determinística usada para assinar e encadear vereditos."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file(path: str, algos=HASH_ALGOS, bufsize: int = 1 << 16) -> dict:
    hs = {a: hashlib.new(a) for a in algos}
    with open(path, "rb") as f:
        while True:
            chunk = f.read(bufsize)
            if not chunk:
                break
            for h in hs.values():
                h.update(chunk)
    return {a: h.hexdigest() for a, h in hs.items()}


def retry_if_locked(op, *args, attempts: int = 40, delay_s: float = 0.05):
    """Executa uma operação de arquivo, tolerando travas passageiras do Windows.

    No Windows, replace, unlink e rmtree falham com PermissionError enquanto outro
    leitor mantém o arquivo aberto (o workload lendo o token, o antivírus, o
    OneDrive). No Linux essa restrição não existe e a operação roda direto. Se a
    trava persistir, o erro é propagado: nunca se finge que a operação aconteceu.
    """
    if os.name == "nt":
        for _ in range(attempts - 1):
            try:
                return op(*args)
            except PermissionError:
                time.sleep(delay_s)
    return op(*args)


def atomic_write(path: str, data: bytes, mode: int = 0o600) -> None:
    """Escreve com fsync + rename, para sobreviver a queda de energia (contador de época).

    O modo só tem efeito real no Linux: no Windows, chmod controla apenas o atributo
    somente leitura, e a proteção de um arquivo depende da ACL da pasta onde ele está.
    """
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        retry_if_locked(os.replace, tmp, path)
        try:  # o Windows não abre diretório assim; o OSError abaixo cobre esse caso
            dfd = os.open(d, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def read_json(path: str, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def write_json(path: str, obj, mode: int = 0o600) -> None:
    atomic_write(path, json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8"), mode)


def read_boot_id(proc_root: str = "/proc") -> str:
    try:
        with open(os.path.join(proc_root, "sys/kernel/random/boot_id")) as f:
            return f.read().strip()
    except OSError:
        return "sim-boot"


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def now() -> float:
    return time.time()
