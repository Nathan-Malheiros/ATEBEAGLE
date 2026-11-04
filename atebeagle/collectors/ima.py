"""Coletor L2 baseado no IMA (Integrity Measurement Architecture).

Lê /sys/kernel/security/ima/ascii_runtime_measurements. Formatos aceitos:
  ima     : PCR template-hash ima     <sha1hex>          <path>
  ima-ng  : PCR template-hash ima-ng  <algo>:<hex>       <path>
  ima-sig : PCR template-hash ima-sig <algo>:<hex>       <path> [<assinatura>]

O IMA acrescenta uma nova entrada quando um arquivo medido muda, então vale a
medição mais recente de cada caminho.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_HEX = re.compile(r"^[0-9a-fA-F]+$")


@dataclass(frozen=True)
class Measurement:
    pcr: int
    template: str
    algo: str
    digest: str
    path: str

    @property
    def tagged(self) -> str:
        return f"{self.algo}:{self.digest}"


def parse_line(line: str):
    f = line.strip().split()
    if len(f) < 5:
        return None
    try:
        pcr = int(f[0])
    except ValueError:
        return None
    template, data = f[2], f[3]
    rest = f[4:]
    if template == "ima-sig" and len(rest) > 1 and _HEX.match(rest[-1]):
        rest = rest[:-1]
    path = " ".join(rest)
    if ":" in data:
        algo, digest = data.split(":", 1)
    else:  # template "ima" legado
        algo, digest = "sha1", data
    algo = algo.lower()
    if not _HEX.match(digest):
        return None
    return Measurement(pcr, template, algo, digest.lower(), path)


def parse_log(text: str) -> list:
    out = []
    for line in text.splitlines():
        m = parse_line(line)
        if m and m.path != "boot_aggregate":
            out.append(m)
    return out


def latest_by_path(measurements) -> dict:
    latest = {}
    for m in measurements:
        latest[m.path] = m
    return latest


class ImaCollector:
    def __init__(self, log_path: str):
        self.log_path = log_path

    def collect(self) -> dict:
        with open(self.log_path, "r", errors="replace") as f:
            ms = parse_log(f.read())
        latest = latest_by_path(ms)
        return {
            "source": "ima",
            "entries": len(ms),
            "files": {p: m.tagged for p, m in latest.items()},
        }
