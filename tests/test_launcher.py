"""Partes puras do menu `atebeagle.bat`. Nada aqui toca a placa nem sobe serviços."""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import launcher  # noqa: E402


def sha(data):
    return hashlib.sha256(data).hexdigest()


def make_build(tmp_path):
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / "device.key").write_bytes(b"chave")
    baseline = json.dumps({"files": {"/opt/atebeagle/workload.py": {"sha256": "abc"}}}).encode()
    (tmp_path / "baseline.json").write_bytes(baseline)
    (tmp_path / "validator.json").write_text("{}")
    return {"agent": "active", "workload": "active", "kint": "1", "waitmod": "sim", "restos": "",
            "device_sha": sha(b"chave"), "baseline_sha": sha(baseline), "workload_sha": "abc"}


def tones(rows):
    return {text: tone for tone, text in rows}


def test_placa_saudavel_nao_tem_problema(tmp_path):
    keys = make_build(tmp_path)
    assert all(tone == "ok" for tone, _ in launcher.assess_report(keys, tmp_path))


def test_imagem_original_e_chave_trocada_sao_apontadas(tmp_path):
    keys = make_build(tmp_path)
    keys.update(waitmod="nao", device_sha="outra")
    rows = launcher.assess_report(keys, tmp_path)
    bad = [text for tone, text in rows if tone == "bad"]
    assert any("imagem original" in t for t in bad)
    assert any("chave da placa" in t for t in bad)


def test_programa_adulterado_e_restos_de_ataque_sao_apontados(tmp_path):
    keys = make_build(tmp_path)
    keys.update(workload_sha="adulterado", restos=" /usr/bin/atb-implante")
    rows = launcher.assess_report(keys, tmp_path)
    assert any(tone == "bad" and "difere da baseline" in text for tone, text in rows)
    assert any(tone == "warn" and "atb-implante" in text for tone, text in rows)


def test_le_o_relatorio_mesmo_com_o_banner_da_placa():
    keys = launcher.parse_keys("Debian GNU/Linux\nagent=active\nrestos= /a /b\nsem igual\n")
    assert keys == {"agent": "active", "restos": " /a /b"}


def test_acha_a_pasta_com_os_dados(tmp_path, monkeypatch):
    monkeypatch.delenv("ATEBEAGLE_BUILD", raising=False)
    (tmp_path / "validator.json").write_text("{}")
    assert launcher.find_build_dir([str(tmp_path / "nada"), str(tmp_path)], {}) == tmp_path
    assert launcher.find_build_dir([str(tmp_path / "nada")], {}) is None


def test_status_descreve_cada_situacao():
    assert launcher.describe(False, None, None)[0][2] == "bad"
    assert launcher.describe(False, None, None, True)[-1][:2] == ("Simulação", "no ar, sem tocar na placa")
    dev = {"state": "REVOKED", "last_epoch": 9, "reason": "L2 ALTERED x", "anomaly": {"ready": False}}
    con = {"attack": {"status": "detected", "title": "Trojan"}}
    rows = {name: (text, tone) for name, text, tone in launcher.describe(True, dev, con)}
    assert rows["Validador"] == ("REVOKED, época 9: L2 ALTERED x", "bad")
    assert rows["Anomalias"][0].startswith("aprendendo")
    assert rows["Console"] == ("ataque ativo: Trojan", "warn")


def test_menu_desenha_sem_console_e_marca_a_selecao():
    items = [it[:4] for it in launcher.ITEMS]
    text = launcher.render(items, 1, [("Placa", "ok", "ok")], 100)
    assert "ATEBEAGLE" in text and "Pasteurizador" in text and "►" in text
    selected = [line for line in text.splitlines() if "►" in line][0]
    assert "Iniciar simulado" in selected


def test_cada_tela_tem_identidade_propria_no_chrome():
    # O Chrome ignora a porta ao identificar uma janela de aplicativo.
    from urllib.parse import urlsplit
    urls = [*launcher.SCREENS.values(), *launcher.SIM_SCREENS.values()]
    ids = [(urlsplit(u).hostname, urlsplit(u).path) for u in urls]
    assert len(ids) == len(set(ids))


def test_menu_separa_ataque_real_de_simulado():
    by_key = {it[0]: it for it in launcher.ITEMS}
    assert by_key["1"][4] is launcher.action_start and "real" in by_key["1"][1]
    assert by_key["2"][4] is launcher.action_start_sim and "simulado" in by_key["2"][1]


def test_simulacao_nao_mexe_na_placa_e_usa_outras_portas(monkeypatch):
    def forbidden(*_, **__):
        raise AssertionError("a simulação não pode falar com a placa")
    started = []
    monkeypatch.setattr(launcher, "board", forbidden)
    monkeypatch.setattr(launcher, "start_service", lambda *a: started.append(a))
    monkeypatch.setattr(launcher, "open_url", lambda url: started.append(url))
    launcher.action_start_sim()
    assert started[0][3] == launcher.SIM_CONSOLE_PORT
    assert started[1:] == list(launcher.SIM_SCREENS.values())
    assert launcher.SIM_CONSOLE_PORT not in (launcher.VALIDATOR_PORT, launcher.CONSOLE_PORT)


def test_titulos_procurados_sao_os_das_telas():
    root = launcher.ROOT
    pages = (root / "atebeagle/dashboard.html", root / "scripts/plant_console.html", root / "scripts/attack_console.html")
    for title, page in zip(launcher.SCREEN_TITLES, pages):
        assert f"<title>{title}</title>" in page.read_text(encoding="utf-8")


class FakeSsh:
    def __init__(self, order):
        self.order = order

    def run(self, script, timeout=120):
        self.order.append(script)
        return 0, ""


def shutdown_env(monkeypatch, order, board_up=True, answer=True):
    state = {"up": board_up}

    def up(host, port, timeout=.6):
        return state["up"] if host == launcher.BOARD_HOST else False

    class Ssh(FakeSsh):
        def run(self, script, timeout=120):
            state["up"] = False
            return super().run(script, timeout)

    monkeypatch.setattr(launcher, "port_open", up)
    monkeypatch.setattr(launcher, "console_status", lambda: None)
    monkeypatch.setattr(launcher, "missing_dependencies", lambda: [])
    monkeypatch.setattr(launcher, "board", lambda: (Ssh(order), RuntimeError))
    monkeypatch.setattr(launcher, "stop_everything", lambda: order.append("fechou"))
    monkeypatch.setattr(launcher, "confirm", lambda *_a, **_k: answer)


def test_desligar_para_o_validador_antes_da_placa(monkeypatch):
    order = []
    shutdown_env(monkeypatch, order)
    launcher.action_shutdown()
    assert order == ["fechou", launcher.POWEROFF]


def test_desligar_pede_confirmacao_e_recusar_nao_fecha_nada(monkeypatch):
    order = []
    shutdown_env(monkeypatch, order, answer=False)
    launcher.action_shutdown()
    assert order == []


def test_desligar_pela_linha_de_comando_nao_pergunta(monkeypatch):
    order = []
    shutdown_env(monkeypatch, order, answer=False)
    launcher.action_shutdown(ask=False)
    assert order == ["fechou", launcher.POWEROFF]


def test_placa_sem_resposta_fecha_o_pc_e_avisa(monkeypatch):
    order = []
    shutdown_env(monkeypatch, order, board_up=False)
    try:
        launcher.action_shutdown()
    except launcher.Fail as f:
        assert "não responde" in f.what and "POWER" in f.todo
    else:
        raise AssertionError("deveria avisar que a placa não respondeu")
    assert order == ["fechou"]


def test_atalhos_do_menu_nao_se_repetem():
    keys = [it[0] for it in launcher.ITEMS]
    assert len(keys) == len(set(keys))
    assert "q" not in keys


def test_laco_do_menu_com_teclas_simuladas(monkeypatch, capsys):
    keys = iter(["down", "up", "l", "x", "q"])
    monkeypatch.setattr(launcher, "msvcrt", type("K", (), {"kbhit": staticmethod(lambda: True)}))
    monkeypatch.setattr(launcher, "read_key", lambda: next(keys))
    monkeypatch.setattr(launcher, "watch_status", lambda status, stop: None)
    monkeypatch.setattr("builtins.input", lambda *_: "")
    called = []
    items = [(*it[:4], (lambda: called.append("logs")) if it[0] == "l" else it[4]) for it in launcher.ITEMS]
    monkeypatch.setattr(launcher, "ITEMS", items)
    launcher.interactive_menu()
    assert called == ["logs"]
    assert "Ver os logs" in capsys.readouterr().out


def test_falha_mostra_o_que_fazer_e_nao_derruba_o_menu(capsys):
    def boom():
        raise launcher.Fail("placa sem resposta", "confira o cabo")
    launcher.run_action(boom)
    out = capsys.readouterr().out
    assert "placa sem resposta" in out and "confira o cabo" in out
