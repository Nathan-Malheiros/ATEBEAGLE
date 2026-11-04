"""Regressões encontradas ao rodar no Windows. Valem nas duas plataformas."""
import os
import subprocess
import sys
import threading

import pytest

from atebeagle.common import atomic_write
from atebeagle.gate import LocalGate
from atebeagle.validator import Validator, serve

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _segura_aberto(path, segundos=0.3):
    """Mantém o arquivo aberto por um tempo, como o workload lendo o token."""
    f = open(path)
    threading.Timer(segundos, f.close).start()


def test_demo_nao_depende_de_pytest():
    codigo = "import sys; sys.modules['pytest'] = None; sys.path.insert(0, 'scripts'); import sim_demo"
    r = subprocess.run([sys.executable, "-c", codigo], cwd=RAIZ, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_atomic_write_espera_leitor_soltar_o_arquivo(tmp_path):
    p = tmp_path / "token"
    p.write_text("antigo")
    _segura_aberto(p)
    atomic_write(str(p), b"novo")
    assert p.read_text() == "novo"
    assert [x.name for x in tmp_path.iterdir()] == ["token"]


def test_gate_apaga_token_mesmo_com_leitor_aberto(tmp_path):
    p = tmp_path / "token"
    p.write_text("t")
    _segura_aberto(p)
    LocalGate(str(p), log=lambda *_: None).revoke("teste")
    assert not p.exists()


def test_segunda_instancia_na_mesma_porta_e_recusada(board):
    v = Validator(board["validator"], log=lambda *_: None)
    srv = serve(v, "127.0.0.1", 0)
    try:
        with pytest.raises(OSError):
            serve(v, "127.0.0.1", srv.server_address[1])
    finally:
        srv.server_close()
