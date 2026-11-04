"""Appraiser: compara evidências com as referências e produz achados.

Matriz de decisão (resumo; ver docs/MATRIZ_DECISAO.md):
  L2 ALTERED       hash difere da baseline             -> FAIL (crítico)
  L2 UNAUTHORIZED  executável fora da baseline         -> FAIL (crítico)
  L2 MISSING       arquivo da baseline sumiu do disco  -> FAIL (alto)
  L3 SYSCALL       tabela de syscalls mudou desde boot -> FAIL (crítico)
  L3 MODULE_NEW    módulo carregado após o boot        -> FAIL (alto)
  L3 MODULE_GONE   módulo do boot descarregado         -> WARN
  L3 TAINT         kernel passou a ficar "tainted"     -> WARN
  BASELINE_INVALID assinatura da baseline não confere  -> FAIL (crítico)
Qualquer achado de severidade >= alto torna o veredito FAIL.
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass

from .collectors.fs import is_ignored

SEVERITY_RANK = {"info": 0, "warn": 1, "high": 2, "critical": 3}


@dataclass
class Finding:
    layer: str
    kind: str
    subject: str
    severity: str
    expected: str | None = None
    observed: str | None = None

    def to_dict(self):
        return asdict(self)


def prefixes_from_baseline(baseline: dict) -> list:
    """Prefixos monitorados = diretórios cobertos pela baseline (mantém os dois sempre coerentes)."""
    out = []
    for r in baseline.get("roots", []):
        r = "/" + r.strip("/")
        out.append(r if r in baseline.get("files", {}) else r.rstrip("/") + "/")
    return out


def _monitored(path: str, prefixes) -> bool:
    return any(path.startswith(p) for p in prefixes)


def appraise_l2(observed_files: dict, baseline: dict, prefixes, root: str | None = "/",
                check_missing: bool = True) -> list:
    findings = []
    ref = baseline.get("files", {})
    for path, tagged in sorted(observed_files.items()):
        if not _monitored(path, prefixes) or is_ignored(path):
            continue
        algo, _, digest = tagged.partition(":")
        if path not in ref:
            findings.append(Finding("L2", "UNAUTHORIZED", path, "critical", None, tagged))
            continue
        exp = ref[path].get(algo)
        if exp is None:
            findings.append(Finding("L2", "ALGO_MISMATCH", path, "warn", ",".join(ref[path]), algo))
        elif exp != digest:
            findings.append(Finding("L2", "ALTERED", path, "critical", f"{algo}:{exp}", tagged))
    if check_missing and root is not None:
        for path in sorted(ref):
            if not os.path.lexists(os.path.join(root, path.lstrip("/"))):
                findings.append(Finding("L2", "MISSING", path, "high", "presente", "ausente"))
    return findings


def appraise_l3(observed: dict, reference: dict) -> list:
    findings = []
    if reference.get("syscall_digest") and observed.get("syscall_digest") != reference["syscall_digest"]:
        findings.append(Finding("L3", "SYSCALL_TABLE", "sys_call_table", "critical",
                                reference["syscall_digest"], observed.get("syscall_digest")))
    ref_m = {m.split(":")[0] for m in reference.get("modules", [])}
    obs_m = {m.split(":")[0] for m in observed.get("modules", [])}
    for m in sorted(obs_m - ref_m):
        findings.append(Finding("L3", "MODULE_NEW", m, "high"))
    for m in sorted(ref_m - obs_m):
        findings.append(Finding("L3", "MODULE_GONE", m, "warn"))
    rt, ot = reference.get("tainted"), observed.get("tainted")
    if rt is not None and ot is not None and ot != rt:
        findings.append(Finding("L3", "TAINT", "kernel", "warn", str(rt), str(ot)))
    return findings


def decide(findings) -> str:
    worst = max((SEVERITY_RANK[f.severity] for f in findings), default=0)
    return "FAIL" if worst >= SEVERITY_RANK["high"] else "PASS"
