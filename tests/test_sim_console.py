"""Modo simulado de ponta a ponta: validador, agente e console reais contra a placa falsa."""
import os
import socket
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import attack_console as ac  # noqa: E402
import sim_console as sc  # noqa: E402
from atebeagle.validator import serve  # noqa: E402

INTERVAL = .6


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait(cond, timeout=12):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(.03)
    return False


@pytest.fixture
def sim(tmp_path):
    port = free_port()
    s = sc.build(tmp_path / "sim", INTERVAL, port, netcut_s=2)
    srv = serve(s["validator"], "127.0.0.1", port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    sc.start_threads(s)
    con = ac.Console(s["board"], ac.Validator(s["url"], s["token"]), recover_timeout=10, simulated=True)
    con.start()
    assert wait(lambda: con._state() == "TRUSTED")
    assert wait(lambda: not con.busy)
    yield s, con
    s["stop"].set()
    srv.shutdown()


def attack(con, aid):
    assert con.launch(aid)[0] == 202
    assert wait(lambda: not con.busy)


def recover(con):
    assert con.recover()[0] == 202
    assert wait(lambda: not con.busy, 25)
    assert con._state() == "TRUSTED"
    assert con.current is None


@pytest.mark.parametrize("aid, finding", [("trojan", "L2 ALTERED"), ("backdoor", "L2 UNAUTHORIZED"),
                                          ("sabotage", "L2 MISSING"), ("rootkit", "L3 MODULE_NEW")])
def test_ataque_e_detectado_pelo_codigo_real_e_recupera(sim, aid, finding):
    _, con = sim
    attack(con, aid)
    assert wait(lambda: con.current["status"] == "detected")
    assert con.current["reaction"] == "REVOKED" and finding in con.current["reason"]
    recover(con)


def test_desligar_o_monitor_cai_no_dead_man_switch(sim):
    _, con = sim
    attack(con, "stop_agent")
    assert wait(lambda: con.current["status"] == "detected")
    assert "dead man" in con.current["reason"]
    recover(con)


def test_ponto_cego_nao_e_visto(sim):
    s, con = sim
    attack(con, "blind_spot")
    time.sleep(INTERVAL * 4)
    assert con.current["status"] == "running" and con._state() == "TRUSTED"
    assert con.cancel()[0] == 202
    assert wait(lambda: not con.busy)
    assert not (s["board"].root / sc.IMPLANT).exists()


def test_replay_e_forja_com_veredito_real_sao_recusados(sim):
    _, con = sim
    assert wait(lambda: con.snap and con.snap["devices"][0]["last_epoch"] > 0)
    for aid, word in (("replay", "replay"), ("forge", "assinatura")):
        attack(con, aid)
        assert con.current["blocked"] is True and word in con.current["result"]
        assert con._state() == "TRUSTED"


def test_token_roubado_vale_ate_a_revogacao(sim):
    _, con = sim
    assert wait(lambda: os.path.exists(sim[0]["token_file"]))
    attack(con, "stolen_token")
    assert con.current["blocked"] is False
    attack(con, "rootkit")
    assert wait(lambda: con.current["status"] == "detected")
    attack(con, "stolen_token")
    assert con.current["blocked"] is True and "revogado" in con.current["result"]


def test_corte_de_rede_derruba_o_ssh_e_a_placa_volta_sozinha(sim):
    s, con = sim
    attack(con, "netcut")
    assert not s["board"].link_up
    with pytest.raises(ac.BoardError):
        s["board"].run("true")
    assert wait(lambda: s["board"].link_up, 5)
    s["board"].run("true")


def test_status_avisa_que_e_simulacao_e_nao_expoe_o_token(sim):
    s, con = sim
    status = con.status()
    assert status["simulated"] is True
    assert s["token"] not in str(status)
    assert s["validator"].snapshot()["simulated"] is True


def test_textos_citam_os_tempos_da_simulacao(monkeypatch):
    attacks = [dict(a) for a in ac.ATTACKS]
    monkeypatch.setattr(ac, "ATTACKS", attacks)
    monkeypatch.setattr(ac, "NETCUT_S", ac.NETCUT_S)
    sc.localize_catalog(10, 30)
    joined = " ".join(a["story"] + a["expect"] for a in attacks)
    assert "25 s" in joined and "30 s" in joined and "150 s" not in joined
