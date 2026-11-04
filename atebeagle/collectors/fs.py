"""Coletor L2 alternativo: hashing direto do sistema de arquivos.

Usado (a) se o kernel da placa não tiver IMA (portão de decisão da semana 1)
e (b) na simulação. Mantém cache por (inode, tamanho, mtime, ctime): o ctime não
pode ser forjado por um usuário comum sem alterar o relógio do sistema, o que
reduz o custo de reprocessar /usr/bin a cada ciclo no Cortex-A8.
"""
from __future__ import annotations

import os
import stat

from ..common import hash_file


IGNORED_PARTS = ("/__pycache__/",)


def is_ignored(path: str) -> bool:
    return path.endswith(".pyc") or any(x in path for x in IGNORED_PARTS)


def _is_candidate(st, name: str) -> bool:
    """Todo arquivo regular sob os diretórios monitorados (o IMA mede scripts lidos
    por root, não só executáveis), exceto bytecode gerado em tempo de execução."""
    return stat.S_ISREG(st.st_mode) and not name.endswith(".pyc")


class FsCollector:
    def __init__(self, root: str, paths, algo: str = "sha256"):
        self.root = os.path.abspath(root)
        self.paths = list(paths)
        self.algo = algo
        self._cache = {}

    def _target_path(self, real: str) -> str:
        rel = os.path.relpath(real, self.root)
        return "/" + rel.replace(os.sep, "/")

    def _iter_files(self):
        for p in self.paths:
            real = os.path.join(self.root, p.lstrip("/"))
            if os.path.isfile(real):
                yield real
                continue
            for dirpath, dirs, files in os.walk(real):
                dirs[:] = [d for d in dirs if d != "__pycache__"]
                for n in files:
                    yield os.path.join(dirpath, n)

    def collect(self) -> dict:
        files = {}
        hashed = 0
        for real in self._iter_files():
            try:
                st = os.lstat(real)
            except OSError:
                continue
            if not _is_candidate(st, os.path.basename(real)):
                continue
            key = (st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
            cached = self._cache.get(real)
            if cached and cached[0] == key:
                digest = cached[1]
            else:
                try:
                    digest = hash_file(real, (self.algo,))[self.algo]
                except OSError:
                    continue
                self._cache[real] = (key, digest)
                hashed += 1
            files[self._target_path(real)] = f"{self.algo}:{digest}"
        return {"source": "fs", "entries": len(files), "hashed_this_cycle": hashed, "files": files}
