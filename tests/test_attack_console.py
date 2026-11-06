"""Console de ataque com placa e validador falsos: nada aqui toca a placa real."""
import http.client
import json
import os
import sys
import threading
import time
from http.server import ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import attack_console as ac  # noqa: E402

TOKEN = "segredo-admin"


class FakeBoard:
    def __init__(self):
        self.calls = []
        self.fail = False

    def run(self, script, timeout=120):
        if self.fail:
            raise ac.BoardError("sem resposta da placa")
        self.calls.append(script)
        return 0, ""


class FakeValidator:
    admin_token = TOKEN

    def __init__(self):
        self.st = "TRUSTED"
        self.resets = 0
        self.posts = []

    def state(self):
        return {"now": time.time(), "devices": [{"state": self.st, "reason": "motivo", "last_epoch": 5}],
                "data": [], "events": []}

    def post(self, path, obj, headers=None):
        self.posts.append((path, obj))
        return 403, {"accepted": False, "reason": "sem token"}

    def reset(self):
        self.resets += 1
        self.st = "TRUSTED"
        return True


@pytest.fixture
def con():
    c = ac.Console(FakeBoard(), FakeValidator(), recover_timeout=2)
    c.poll_once()
    return c


def settle(c):
    for _ in range(200):
        if not c.busy:
            return
        time.sleep(.01)
    raise AssertionError("ação não terminou")


def test_todo_ataque_na_placa_sabe_se_desfazer():
    for a in ac.ATTACKS:
        if not a.get("net"):
            assert a["run"] and a["undo"], a["id"]


def test_recuperacao_cobre_o_que_os_ataques_deixam():
    for trace in (ac.BACKUP, ac.BACKDOOR, ac.IMPLANT, "atb-miner", "atb-netcut", "dummy", "usb0 up", "start atebeagle-agent"):
        assert trace in ac.RESTORE_ALL


def test_ataque_detectado_registra_tempo_e_motivo(con):
    assert con.launch("trojan")[0] == 202
    settle(con)
    assert con.current["status"] == "running"
    con.validator.st = "REVOKED"
    con.poll_once()
    assert con.current["status"] == "detected"
    assert con.current["reaction"] == "REVOKED"
    assert con.history[0]["result"].startswith("REVOKED em")


def test_nao_aceita_segundo_ataque_com_um_ativo(con):
    con.launch("trojan")
    settle(con)
    code, body = con.launch("backdoor")
    assert code == 409 and "ataque ativo" in body["error"]


def test_ataque_na_placa_exige_trusted_mas_o_de_rede_nao(con):
    con.validator.st = "REVOKED"
    con.poll_once()
    assert con.launch("trojan")[0] == 409
    assert con.launch("fake_sensor")[0] == 202
    settle(con)
    assert con.current["status"] == "finished"
    assert con.validator.posts[0][0] == "/data"


def test_cancelar_desfaz_e_registra_que_nao_houve_reacao(con):
    con.launch("backdoor")
    settle(con)
    assert con.cancel()[0] == 202
    settle(con)
    assert con.board.calls[-1] == ac.BY_ID["backdoor"]["undo"]
    assert con.current["status"] == "canceled"
    assert "sem reação" in con.history[0]["result"]


def test_corte_de_rede_nao_pode_ser_cancelado(con):
    con.launch("netcut")
    settle(con)
    code, body = con.cancel()
    assert code == 409 and "volta sozinha" in body["error"]


def test_corte_de_rede_que_derruba_a_sessao_nao_conta_como_falha(con):
    con.board.fail = True
    con.launch("netcut")
    settle(con)
    assert con.current["status"] == "running"


def test_falha_de_ssh_em_outro_ataque_e_informada(con):
    con.board.fail = True
    con.launch("trojan")
    settle(con)
    assert con.current["status"] == "failed"
    assert "não foi executado" in con.history[0]["result"]


def test_recuperar_restaura_reprovisiona_e_religa_o_workload(con):
    con.launch("trojan")
    settle(con)
    con.validator.st = "REVOKED"
    con.poll_once()
    assert con.recover()[0] == 202
    settle(con)
    assert con.validator.resets == 1
    assert ac.RESTORE_ALL in con.board.calls
    assert con.board.calls[-1] == "systemctl start atebeagle-workload"
    assert con.current is None


def test_token_de_admin_nao_vai_para_a_tela(con):
    con.launch("fake_sensor")
    settle(con)
    assert TOKEN not in json.dumps(con.status())


@pytest.fixture
def http_port(con):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), None)
    port = srv.server_address[1]
    srv.RequestHandlerClass = ac.make_handler(con, port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield port
    srv.shutdown()


def post(port, path, headers):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.putrequest("POST", path, skip_host=True)
    for k, v in headers.items():
        c.putheader(k, v)
    c.putheader("Content-Length", "0")
    c.endheaders()
    return c.getresponse().status


def test_outro_site_nao_aciona_o_console(con, http_port):
    host = f"127.0.0.1:{http_port}"
    assert post(http_port, "/api/recover", {"Host": host, "Origin": "http://malicioso.example"}) == 403
    assert post(http_port, "/api/recover", {"Host": f"malicioso.example:{http_port}"}) == 403
    assert not con.busy
    assert post(http_port, "/api/recover", {"Host": host, "Origin": f"http://{host}"}) == 202
    settle(con)


def get(port, path):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", path)
    r = c.getresponse()
    return r.status, r.getheader("Content-Type"), r.read()


def test_as_duas_telas_do_console_abrem(con, http_port):
    for path, marca in (("/ataques", "Mesa do invasor"), ("/", "Mesa do invasor"), ("/planta", "Pasteurizador")):
        code, ctype, body = get(http_port, path)
        assert code == 200 and "text/html" in ctype and marca in body.decode()


def test_as_tres_ilustracoes_abrem_e_o_resto_nao(con, http_port):
    for state in ac.DOGS:
        code, ctype, body = get(http_port, f"/assets/dog/{state}")
        assert code == 200 and ctype == "image/jpeg" and body
    assert get(http_port, "/assets/dog/..%2f..%2fbaseline.json")[0] == 404
    assert get(http_port, "/assets/dog/outra")[0] == 404


def test_ataque_de_rede_recusado_conta_como_contido(con):
    con.launch("fake_sensor")
    settle(con)
    assert con.current["blocked"] is True


def test_ataque_de_rede_continua_possivel_com_a_placa_revogada(con):
    con.launch("trojan")
    settle(con)
    con.validator.st = "REVOKED"
    con.poll_once()
    assert con.launch("backdoor")[0] == 409
    assert con.launch("fake_sensor")[0] == 202
    settle(con)
    assert con.current["status"] == "finished"
