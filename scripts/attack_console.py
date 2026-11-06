"""Console de ataque da demonstração: roda no PC, ao lado do validador.

Executa ataques reais e reversíveis contra a placa, por SSH e pela rede, e mostra a
reação do sistema. Só escuta em 127.0.0.1. A planta na tela é simulada; estado,
leituras e autorização vêm do validador real.

  py scripts\\attack_console.py --validator-config D:\\ATEBEAGLE-build\\validator.json

Precisa de paramiko (py -m pip install paramiko). A senha SSH vem de
ATEBEAGLE_BOARD_PASSWORD; sem ela, usa a senha padrão da imagem.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import shlex
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
# Caminhos próprios: o Chrome ignora a porta ao identificar uma janela de aplicativo, e "/" aqui
# seria o mesmo aplicativo que o painel do validador.
PAGES = {"/": "attack_console.html", "/ataques": "attack_console.html", "/planta": "plant_console.html"}
DOGS = {"calm": "BBBDogAtack_limpa.jpg", "hack": "BBBDogHacker_limpa.jpg", "caught": "BBBDogAtackConfuse_limpa.jpg"}
ASSETS = os.path.join(os.path.dirname(HERE), "docs", "assets")
DEVICE = "bbb-01"
WORKLOAD = "/opt/atebeagle/workload.py"
BACKUP = "/var/tmp/atb-workload.bak"
BACKDOOR = "/usr/local/bin/atb-backdoor"
IMPLANT = "/usr/bin/atb-implante"
# Precisa cobrir a tentativa de envio que ocorre 120 s depois do último veredito e dura até
# 5 s (timeout_s). Com menos que isso, um corte logo após um veredito pode não revogar.
NETCUT_S = 130
FAKE_TEMP = 12.0

RESTORE_WORKLOAD = f"if [ -e {BACKUP} ]; then mv -f {BACKUP} {WORKLOAD}; fi"

# Ordem importa: a rede volta antes de tudo, o agente sobe por último porque a unit
# dele espera os módulos estabilizarem.
RESTORE_ALL = "\n".join([
    "systemctl stop atb-miner atb-netcut 2>/dev/null",
    "ip link set usb0 up",
    RESTORE_WORKLOAD,
    f"rm -f {BACKDOOR} {IMPLANT}",
    "modprobe -r dummy 2>/dev/null",
    "systemctl start atebeagle-agent",
    "true",
])

# Lê o veredito direto da interface da placa, como faria um grampo na rede. Precisa de
# ETH_P_ALL: um socket só de IP (0x0800) não recebe os pacotes que a própria placa envia.
SNIFF = r'''
import base64, socket, struct, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3))
s.bind(("usb0", 3)); s.settimeout(5)
flows, end = {}, time.time() + 130
while time.time() < end:
    try:
        p = s.recv(65535)
    except socket.timeout:
        continue
    if len(p) < 40 or p[0] >> 4 != 4 or p[9] != 6:
        continue
    ihl = (p[0] & 15) * 4
    total = struct.unpack("!H", p[2:4])[0]
    sport, dport, seq = struct.unpack("!HHI", p[ihl:ihl + 8])
    if dport != 8700:
        continue
    data = p[ihl + (p[ihl + 12] >> 4) * 4:total]
    if not data:
        continue
    f = flows.setdefault(sport, {})
    f[seq] = data
    blob = b"".join(f[k] for k in sorted(f))
    if not blob.startswith(b"POST /verdict"):
        continue
    head, sep, body = blob.partition(b"\r\n\r\n")
    if not sep:
        continue
    n = [int(l.split(b":")[1]) for l in head.split(b"\r\n") if l.lower().startswith(b"content-length")][0]
    if len(body) >= n:
        print(base64.b64encode(body[:n]).decode())
        break
'''

INSIDE = "Dentro da placa, como root"
NETWORK = "De fora, só com acesso à rede"
BLIND = "Onde a atestação não enxerga"

ATTACKS = [
    {"id": "trojan", "layer": "L2", "group": INSIDE, "title": "Trocar a lógica do controlador",
     "story": "Altera o programa que comanda a planta, como um trojan.",
     "expect": "Revogação por arquivo alterado (L2 ALTERED).", "watch": "REVOKED",
     "run": f"[ -e {BACKUP} ] || cp -p {WORKLOAD} {BACKUP}\n"
            f"echo '# ATEBEAGLE: trojan de demonstracao, sem efeito' >> {WORKLOAD}\ntail -1 {WORKLOAD}",
     "undo": RESTORE_WORKLOAD},
    {"id": "backdoor", "layer": "L2", "group": INSIDE, "title": "Instalar um backdoor",
     "story": "Coloca um programa novo na área monitorada e o executa.",
     "expect": "Revogação por arquivo fora da baseline (L2 UNAUTHORIZED).", "watch": "REVOKED",
     "run": f"cp /bin/true {BACKDOOR} && {BACKDOOR} && ls -l {BACKDOOR}",
     "undo": f"rm -f {BACKDOOR}"},
    {"id": "sabotage", "layer": "L2", "group": INSIDE, "title": "Apagar o programa de controle",
     "story": "Remove o programa da planta. O processo em memória continua rodando.",
     "expect": "Revogação por arquivo ausente (L2 MISSING).", "watch": "REVOKED",
     "run": f"if [ -e {BACKUP} ]; then rm -f {WORKLOAD}; else mv {WORKLOAD} {BACKUP}; fi\n"
            f"ls -l /opt/atebeagle",
     "undo": RESTORE_WORKLOAD},
    {"id": "rootkit", "layer": "L3", "group": INSIDE, "title": "Carregar um módulo no kernel",
     "story": "Insere código no kernel depois do boot, como um rootkit faria. O módulo é inofensivo.",
     "expect": "Revogação por módulo novo (L3 MODULE_NEW).", "watch": "REVOKED",
     "run": "modprobe -v dummy", "undo": "modprobe -r dummy"},
    {"id": "miner", "layer": "Anomalia", "group": INSIDE, "title": "Rodar um minerador escondido",
     "story": "Ocupa a CPU sem alterar nenhum arquivo. Para sozinho em 2,5 min.",
     "expect": "Alerta SUSPECT pela detecção de anomalias, sem revogar. Precisa de 20 ciclos de histórico.",
     "watch": "SUSPECT",
     "run": "systemd-run --unit=atb-miner --collect --quiet bash -c "
            "'for i in 1 2; do timeout 150 sh -c \"while :; do :; done\" & done; wait'\n"
            "echo minerador iniciado",
     "undo": "systemctl stop atb-miner"},
    {"id": "stop_agent", "layer": "Silêncio", "group": INSIDE, "title": "Desligar o monitor",
     "story": "Para o agente de atestação para operar sem ser observado.",
     "expect": "Revogação por silêncio em até 150 s. O bloqueio vem do validador.", "watch": "REVOKED",
     "run": "systemctl stop atebeagle-agent\necho agente: $(systemctl is-active atebeagle-agent)",
     "undo": "systemctl start atebeagle-agent"},
    {"id": "kill_agent", "layer": "Silêncio", "group": INSIDE, "title": "Matar o processo do monitor",
     "story": "Envia SIGKILL ao agente. O systemd o religa em 5 s.",
     "expect": "Tende a não revogar: o agente volta antes do limite de silêncio.", "watch": "REVOKED",
     "run": "systemctl kill -s SIGKILL atebeagle-agent\necho SIGKILL enviado",
     "undo": "systemctl start atebeagle-agent"},
    {"id": "netcut", "layer": "Silêncio", "group": INSIDE, "title": "Cortar a rede do controlador",
     "story": f"Derruba a interface da placa. Ela volta sozinha em {NETCUT_S} s, sem precisar de você.",
     "expect": "Revogação por silêncio em até 150 s.", "watch": "REVOKED", "cancellable": False,
     "run": "systemd-run --unit=atb-netcut --collect --quiet bash -c "
            f"'sleep 1; ip link set usb0 down; sleep {NETCUT_S}; ip link set usb0 up'\necho corte agendado",
     "undo": "ip link set usb0 up"},
    {"id": "fake_sensor", "layer": "I/O", "group": NETWORK, "title": "Injetar leitura falsa sem token",
     "story": f"Envia ao validador uma temperatura de {FAKE_TEMP:.0f} °C fingindo ser a placa.",
     "expect": "Recusada: sem token não há I/O.", "net": True},
    {"id": "stolen_token", "layer": "I/O", "group": NETWORK, "title": "Injetar leitura falsa com token roubado",
     "story": "Copia o token do workload e o usa de fora. Repita depois de uma revogação para comparar.",
     "expect": "Aceita enquanto o token vale; recusada depois da revogação.", "net": True},
    {"id": "replay", "layer": "Protocolo", "group": NETWORK, "title": "Reenviar um veredito capturado",
     "story": "Grampeia um veredito legítimo e o reenvia depois. Leva até um ciclo.",
     "expect": "Recusado com 403, sem revogar.", "net": True},
    {"id": "forge", "layer": "Protocolo", "group": NETWORK, "title": "Forjar um veredito de aprovação",
     "story": "Altera um veredito capturado para dizer que está tudo bem, sem ter a chave.",
     "expect": "Recusado com 403 por assinatura inválida, sem revogar.", "net": True},
    {"id": "blind_spot", "layer": "Sem cobertura", "group": BLIND, "title": "Implante fora da área medida",
     "story": "Coloca um programa em /usr/bin. Sem IMA neste kernel, o coletor só vê /opt/atebeagle e /usr/local/bin.",
     "expect": "Nenhuma reação: limite conhecido, que vale mostrar.", "watch": "REVOKED",
     "run": f"cp /bin/true {IMPLANT} && ls -l {IMPLANT}", "undo": f"rm -f {IMPLANT}"},
]
BY_ID = {a["id"]: a for a in ATTACKS}
CATALOG_KEYS = ("id", "layer", "group", "title", "story", "expect")


class BoardError(Exception):
    pass


class SshBoard:
    def __init__(self, target, password):
        self.user, self.host = target.split("@", 1)
        self.password = password
        self.client = None
        self.lock = threading.Lock()

    def _connect(self):
        import paramiko
        c = paramiko.SSHClient()
        c.load_system_host_keys()  # chave diferente da registrada é recusada pelo paramiko
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(self.host, username=self.user, password=self.password, timeout=10,
                  banner_timeout=15, auth_timeout=15, look_for_keys=False, allow_agent=False)
        return c

    def run(self, script, timeout=120):
        cmd = "sudo -S -p '' bash -c " + shlex.quote(script)
        try:
            with self.lock:
                transport = self.client.get_transport() if self.client else None
                if not transport or not transport.is_active():
                    self.client = self._connect()
                client = self.client
            stdin, stdout, _ = client.exec_command(cmd, timeout=timeout)
            stdout.channel.set_combine_stderr(True)
            stdin.write(self.password + "\n")
            stdin.flush()
            stdin.channel.shutdown_write()
            out = stdout.read().decode("utf-8", "replace").strip()
            return stdout.channel.recv_exit_status(), out
        except Exception as e:
            with self.lock:
                if self.client:
                    self.client.close()
                self.client = None
            raise BoardError(f"sem resposta da placa: {e}") from e


class Validator:
    def __init__(self, url, admin_token):
        self.url = url.rstrip("/")
        self.admin_token = admin_token

    def state(self):
        with urllib.request.urlopen(self.url + "/api/state", timeout=3) as r:
            return json.loads(r.read().decode())

    def post(self, path, obj, headers=None):
        req = urllib.request.Request(self.url + path, data=json.dumps(obj).encode(), method="POST",
                                     headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or "{}")

    def reset(self):
        code, _ = self.post("/admin/reset", {"device_id": DEVICE}, {"X-Admin-Token": self.admin_token})
        return code == 200


class Console:
    def __init__(self, board, validator, recover_timeout=300, monitor_url=None, simulated=False):
        self.board = board
        self.validator = validator
        self.recover_timeout = recover_timeout
        self.monitor_url = monitor_url
        self.simulated = simulated
        self.lock = threading.RLock()
        self.current = None
        self.busy = None  # "attack", "cancel" ou "recover": bloqueia ações concorrentes
        self.history = []
        self.log_lines = []
        self.snap = None
        self.stolen_token = None

    # ---------------------------------------------------------------- registro
    def log(self, kind, text):
        with self.lock:
            self.log_lines.append({"t": time.time(), "kind": kind, "text": text})
            del self.log_lines[:-300]

    def _sh(self, script, shown=None, timeout=120):
        self.log("cmd", shown or script)
        rc, out = self.board.run(script, timeout=timeout)
        if out:
            self.log("out", out)
        if rc:
            self.log("err", f"saída {rc}")
        return rc, out

    def _state(self):
        devs = (self.snap or {}).get("devices") or []
        return devs[0]["state"] if devs else None

    def _record(self, cur, result):
        cur["result"] = result
        self.history.insert(0, {"t": time.time(), "title": cur["title"], "result": result})

    # ---------------------------------------------------------------- observação
    def poll_once(self):
        try:
            snap = self.validator.state()
        except (OSError, ValueError):
            snap = None
        with self.lock:
            self.snap = snap
            cur = self.current
            state = self._state()
            if not (cur and cur["status"] == "running" and cur.get("watch")):
                return
            if state in ("REVOKED", "SUSPECT"):
                secs = time.time() - cur["started"]
                reason = snap["devices"][0].get("reason") or "desvio apontado pela detecção de anomalias"
                cur.update(status="detected", detected_after=secs, reaction=state, reason=reason)
                self._record(cur, f"{state} em {secs:.0f} s: {reason}")
                self.log("info", f"Reação do sistema: {state} em {secs:.0f} s. {reason}")

    def _watch(self):
        while True:
            self.poll_once()
            time.sleep(1)

    def start(self):
        threading.Thread(target=self._watch, daemon=True).start()

    # ---------------------------------------------------------------- ações
    def launch(self, attack_id):
        attack = BY_ID.get(attack_id)
        if not attack:
            return 404, {"error": "Ataque desconhecido."}
        with self.lock:
            if self.busy:
                return 409, {"error": "Espere a ação em andamento terminar."}
            cur = self.current
            # Com a placa já revogada, a rede ainda pode tentar: é assim que se mostra o token roubado sendo recusado.
            revoked_net = attack.get("net") and cur and cur["reaction"] == "REVOKED"
            if cur and cur["status"] in ("running", "detected") and not revoked_net:
                return 409, {"error": "Há um ataque ativo. Cancele o ataque ou recupere a placa antes."}
            if self.snap is None:
                return 409, {"error": "O validador não responde. Suba o validador e tente de novo."}
            if not attack.get("net") and self._state() != "TRUSTED":
                return 409, {"error": "A placa precisa estar TRUSTED para medir a reação. Recupere a placa antes."}
            self.busy = "attack"
            self.current = {"id": attack["id"], "title": attack["title"], "started": time.time(),
                            "status": "running", "watch": attack.get("watch"), "reaction": None,
                            "detected_after": None, "reason": None, "result": None,
                            "cancellable": attack.get("cancellable", True) and not attack.get("net"),
                            "self_heal_s": NETCUT_S if attack["id"] == "netcut" else None,
                            "blocked": None, "finished_at": None}
        threading.Thread(target=self._run_attack, args=(attack,), daemon=True).start()
        return 202, {"ok": True}

    def _run_attack(self, attack):
        cur = self.current
        self.log("info", f"Ataque iniciado: {attack['title']}.")
        try:
            if attack.get("net"):
                blocked, result = getattr(self, "_net_" + attack["id"])()
                with self.lock:
                    cur.update(status="finished", blocked=blocked, finished_at=time.time())
                    self._record(cur, result)
                self.log("info", result)
            else:
                try:
                    rc, _ = self._sh(attack["run"])
                    failed = rc != 0
                except BoardError:
                    # O corte de rede derruba a própria sessão: isso é o ataque funcionando.
                    failed = attack["id"] != "netcut"
                    if failed:
                        raise
                if failed:
                    with self.lock:
                        cur["status"] = "failed"
                        self._record(cur, "O ataque não foi executado.")
        except (BoardError, OSError, ValueError) as e:
            self.log("err", str(e))
            with self.lock:
                cur["status"] = "failed"
                self._record(cur, f"O ataque não foi executado: {e}")
        finally:
            with self.lock:
                self.busy = None

    def cancel(self):
        with self.lock:
            cur = self.current
            if self.busy:
                return 409, {"error": "Espere a ação em andamento terminar."}
            if not cur or cur["status"] not in ("running", "detected"):
                return 409, {"error": "Não há ataque ativo para cancelar."}
            if not cur["cancellable"]:
                return 409, {"error": "Este ataque não pode ser cancelado: a placa está sem rede e volta sozinha."}
            self.busy = "cancel"
        threading.Thread(target=self._run_cancel, args=(cur,), daemon=True).start()
        return 202, {"ok": True}

    def _run_cancel(self, cur):
        try:
            self.log("info", f"Cancelando: {cur['title']}.")
            self._sh(BY_ID[cur["id"]]["undo"])
            with self.lock:
                if cur["status"] == "running":
                    secs = time.time() - cur["started"]
                    self._record(cur, f"Cancelado após {secs:.0f} s, sem reação do sistema.")
                was_revoked = cur.get("reaction") == "REVOKED"
                cur["status"] = "canceled"
            if was_revoked:
                self.log("info", "Ataque desfeito. A revogação continua: use Recuperar a placa.")
            else:
                self.log("info", "Ataque desfeito.")
        except BoardError as e:
            self.log("err", str(e))
        finally:
            with self.lock:
                self.busy = None

    def recover(self):
        with self.lock:
            if self.busy:
                return 409, {"error": "Espere a ação em andamento terminar."}
            self.busy = "recover"
        threading.Thread(target=self._run_recover, daemon=True).start()
        return 202, {"ok": True}

    def _wait_board(self):
        end = time.time() + self.recover_timeout
        while True:
            try:
                self.board.run("true", timeout=15)
                return
            except BoardError:
                if time.time() > end:
                    raise
                self.log("info", "Esperando a placa responder.")
                time.sleep(5)

    def _run_recover(self):
        try:
            self.log("info", "Recuperando a placa.")
            self._wait_board()
            self._sh(RESTORE_ALL, shown="# desfaz todos os ataques e religa o agente", timeout=300)
            now = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
            self._sh(f"date -u -s '{now}' >/dev/null", shown=f"date -u -s '{now}'")
            if not self.validator.reset():
                raise BoardError("o validador recusou o re-provisionamento: confira o admin_token")
            self.log("info", "Validador re-provisionado. Esperando um veredito aprovado.")
            end = time.time() + self.recover_timeout
            while time.time() < end:
                self.poll_once()
                if self._state() == "TRUSTED":
                    break
                time.sleep(2)
            else:
                raise BoardError("a placa não voltou a TRUSTED: veja o agente com journalctl -u atebeagle-agent")
            self._sh("systemctl start atebeagle-workload")
            with self.lock:
                self.current = None
            self.log("info", "Placa recuperada: TRUSTED, com o workload ligado.")
        except (BoardError, OSError, ValueError) as e:
            self.log("err", f"Recuperação incompleta: {e}")
        finally:
            with self.lock:
                self.busy = None

    # ---------------------------------------------------------------- ataques de rede
    def _net_fake_sensor(self):
        self.log("cmd", f"POST /data temp_c={FAKE_TEMP} sem token")
        code, r = self.validator.post("/data", {"device_id": DEVICE, "token": "",
                                                "value": {"temp_c": FAKE_TEMP}})
        return self._data_result(code, r)

    def _net_stolen_token(self):
        rc, token = self.board_read_token()
        if token:
            self.stolen_token = token
        elif not self.stolen_token:
            return None, "Não há token para roubar: a placa está sem autorização. Rode este ataque com ela TRUSTED."
        self.log("cmd", f"POST /data temp_c={FAKE_TEMP} com token {self.stolen_token[:10]}...")
        code, r = self.validator.post("/data", {"device_id": DEVICE, "token": self.stolen_token,
                                                "value": {"temp_c": FAKE_TEMP}})
        return self._data_result(code, r)

    def board_read_token(self):
        try:
            rc, out = self.board.run("cat /run/atebeagle/workload.token 2>/dev/null", timeout=20)
        except BoardError:
            return 1, ""
        self.log("cmd", "cat /run/atebeagle/workload.token")
        self.log("out", f"{out[:10]}... (oculto)" if out else "sem token na placa")
        return rc, out if rc == 0 else ""

    @staticmethod
    def _data_result(code, r):
        if code == 200:
            return False, f"Leitura falsa ACEITA pelo validador (HTTP {code})."
        return True, f"Leitura falsa recusada (HTTP {code}): {r.get('reason')}."

    def _capture_verdict(self):
        self.log("cmd", "# grampeia usb0 até passar um veredito")
        b64 = base64.b64encode(SNIFF.encode()).decode()
        rc, out = self.board.run(f"python3 -c \"$(echo {b64} | base64 -d)\"", timeout=150)
        if rc or not out:
            raise BoardError(f"nenhum veredito capturado: {out or 'tempo esgotado'}")
        env = json.loads(base64.b64decode(out.splitlines()[-1]).decode())
        self.log("out", f"veredito capturado: época {env['body']['epoch']}")
        return env

    def _net_replay(self):
        env = self._capture_verdict()
        epoch = env["body"]["epoch"]
        self.log("info", "Esperando o próximo ciclo para o veredito ficar antigo.")
        end = time.time() + 150
        while time.time() < end:
            devs = (self.snap or {}).get("devices") or [{}]
            if devs[0].get("last_epoch", 0) > epoch:
                break
            time.sleep(2)
        self.log("cmd", f"POST /verdict época {epoch}")
        code, r = self.validator.post("/verdict", env)
        return code != 200, f"Replay da época {epoch}: HTTP {code}, {r.get('reason') or r.get('state')}."

    def _net_forge(self):
        env = self._capture_verdict()
        env["body"].update(epoch=env["body"]["epoch"] + 1, ts=time.time(), status="PASS", findings=[])
        self.log("cmd", f"POST /verdict época {env['body']['epoch']}, conteúdo alterado")
        code, r = self.validator.post("/verdict", env)
        return code != 200, f"Veredito forjado: HTTP {code}, {r.get('reason') or r.get('state')}."

    # ---------------------------------------------------------------- estado para a tela
    def status(self):
        with self.lock:
            return {"now": time.time(), "validator": self.snap, "attack": self.current, "busy": self.busy,
                    "history": self.history[:12], "log": self.log_lines[-120:],
                    "monitor_url": self.monitor_url, "fake_temp": FAKE_TEMP, "simulated": self.simulated,
                    "catalog": [dict({k: a[k] for k in CATALOG_KEYS}, net=bool(a.get("net"))) for a in ATTACKS]}


def make_handler(console, port):
    allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code, obj):
            data = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _trusted(self):
            # Este servidor age como root na placa: nenhuma outra página do navegador pode acioná-lo.
            if self.headers.get("Host") not in allowed:
                return False
            origin = self.headers.get("Origin")
            return origin is None or origin.split("//")[-1] in allowed

        def do_GET(self):
            if not self._trusted():
                return self._json(403, {"error": "origem não permitida"})
            if self.path == "/api/status":
                return self._json(200, console.status())
            if self.path in PAGES:
                return self._file(os.path.join(HERE, PAGES[self.path]), "text/html; charset=utf-8")
            if self.path.startswith("/assets/dog/"):
                name = DOGS.get(self.path.rsplit("/", 1)[-1])
                if name and os.path.exists(os.path.join(ASSETS, name)):
                    return self._file(os.path.join(ASSETS, name), "image/jpeg")
            self._json(404, {"error": "não encontrado"})

        def _file(self, path, content_type):
            with open(path, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if not self._trusted():
                return self._json(403, {"error": "origem não permitida"})
            if self.path.startswith("/api/attack/"):
                return self._json(*console.launch(self.path.rsplit("/", 1)[-1]))
            if self.path == "/api/cancel":
                return self._json(*console.cancel())
            if self.path == "/api/recover":
                return self._json(*console.recover())
            self._json(404, {"error": "não encontrado"})

    return Handler


def main():
    ap = argparse.ArgumentParser(description="Console de ataque do ATEBEAGLE")
    ap.add_argument("--validator-config", required=True)
    ap.add_argument("--board", default="debian@192.168.7.2")
    ap.add_argument("--port", type=int, default=8701)
    ap.add_argument("--abrir", action="store_true", help="abre as três telas no navegador")
    a = ap.parse_args()
    try:
        import paramiko  # noqa: F401
    except ImportError:
        sys.exit(f"Falta a dependência paramiko. Instale com:\n  \"{sys.executable}\" -m pip install paramiko")
    with open(a.validator_config, encoding="utf-8") as f:
        cfg = json.load(f)
    vport = cfg.get("port", 8700)
    validator = Validator(f"http://127.0.0.1:{vport}", cfg["admin_token"])
    password = os.environ.get("ATEBEAGLE_BOARD_PASSWORD", "temppwd")
    console = Console(SshBoard(a.board, password), validator, monitor_url=f"http://localhost:{vport}")
    console.start()
    server = ThreadingHTTPServer(("127.0.0.1", a.port), make_handler(console, a.port))
    urls = [f"http://localhost:{vport}", f"http://localhost:{a.port}/planta", f"http://localhost:{a.port}/ataques"]
    print("monitoramento, pasteurizador e ataques:", *urls, sep="\n  ", flush=True)
    if a.abrir:
        for url in urls:
            webbrowser.open_new(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
