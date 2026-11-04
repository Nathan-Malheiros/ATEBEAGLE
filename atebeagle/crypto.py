"""Assinatura Ed25519 dos vereditos e da baseline (biblioteca `cryptography`).

Na BeagleBone (Debian): `sudo apt install python3-cryptography`.
"""
from __future__ import annotations

import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .common import b64d, b64e, atomic_write


def generate_keypair(priv_path: str, pub_path: str) -> str:
    sk = Ed25519PrivateKey.generate()
    raw = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                           serialization.NoEncryption())
    atomic_write(priv_path, b64e(raw).encode() + b"\n", 0o600)
    pub = public_b64(sk)
    atomic_write(pub_path, pub.encode() + b"\n", 0o644)
    return pub


def load_private(path: str) -> Ed25519PrivateKey:
    with open(path) as f:
        return Ed25519PrivateKey.from_private_bytes(b64d(f.read().strip()))


def load_public_b64(s: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(b64d(s.strip()))


def load_public(path: str) -> Ed25519PublicKey:
    with open(path) as f:
        return load_public_b64(f.read())


def public_b64(sk: Ed25519PrivateKey) -> str:
    return b64e(sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def sign(sk: Ed25519PrivateKey, data: bytes) -> str:
    return b64e(sk.sign(data))


def verify(pk: Ed25519PublicKey, data: bytes, sig_b64: str) -> bool:
    try:
        pk.verify(b64d(sig_b64), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def main():
    import argparse
    p = argparse.ArgumentParser(description="Gera par de chaves Ed25519 (dispositivo ou autoridade de baseline)")
    p.add_argument("--out", required=True, help="prefixo do arquivo, ex: keys/device")
    a = p.parse_args()
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    pub = generate_keypair(a.out + ".key", a.out + ".pub")
    print(f"privada: {a.out}.key\npública: {a.out}.pub\n{pub}")


if __name__ == "__main__":
    main()
