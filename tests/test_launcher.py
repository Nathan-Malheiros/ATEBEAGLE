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
    assert "Verificar a placa" in selected


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
