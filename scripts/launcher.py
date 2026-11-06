"""Menu do ATEBEAGLE (`atebeagle.bat`): sobe o sistema, verifica a placa e abre as telas.

Só biblioteca padrão para o menu. O validador e o console ficam em segundo plano e continuam
depois de fechar o menu; os logs ficam em runs/launcher/.

  atebeagle.bat               menu interativo
  atebeagle.bat --iniciar     sobe tudo, com ataques reais na placa, e abre as três telas
  atebeagle.bat --simulado    sobe a simulação, sem tocar na placa, e abre as três telas
  atebeagle.bat --verificar   só confere a placa
  atebeagle.bat --parar       fecha as telas, o validador, o console e a simulação
  atebeagle.bat --desligar    fecha tudo e desliga a BeagleBone
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from datetime import datetime
from pathlib import Path

try:
    import msvcrt
except ImportError:  # fora do Windows só o menu numerado funciona
    msvcrt = None

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "runs" / "launcher"
SETTINGS = RUNS / "config.json"
BOARD_HOST = "192.168.7.2"
BOARD_TARGET = "debian@" + BOARD_HOST
VALIDATOR_PORT = 8700
CONSOLE_PORT = 8701
VALIDATOR_URL = f"http://127.0.0.1:{VALIDATOR_PORT}"
CONSOLE_URL = f"http://127.0.0.1:{CONSOLE_PORT}"
SIM_VALIDATOR_PORT = 8710
SIM_CONSOLE_PORT = 8711
SIM_SCREENS = {"monitor": f"http://127.0.0.1:{SIM_VALIDATOR_PORT}", "planta": f"http://127.0.0.1:{SIM_CONSOLE_PORT}/planta",
               "ataques": f"http://127.0.0.1:{SIM_CONSOLE_PORT}/ataques"}
SCREENS = {"monitor": f"http://localhost:{VALIDATOR_PORT}", "planta": f"http://localhost:{CONSOLE_PORT}/planta",
           "ataques": f"http://localhost:{CONSOLE_PORT}/ataques"}
BUILD_CANDIDATES = (r"D:\ATEBEAGLE-build", r"C:\ATEBEAGLE-build", r"C:\atebeagle")
BROWSERS = (
    Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Google/Chrome/Application/chrome.exe",
    Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")) / "Google/Chrome/Application/chrome.exe",
    Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/Application/chrome.exe",
    Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")) / "Microsoft/Edge/Application/msedge.exe",
)
DEPENDENCIES = {"cryptography": "cryptography", "paramiko": "paramiko"}
# Título exato: janela de aplicativo não tem " - Google Chrome", então uma aba comum nunca é fechada.
SCREEN_TITLES = ("ATEBEAGLE Validador", "Pasteurizador P-101", "Mesa do invasor ATEBEAGLE")
POWEROFF = "systemd-run --on-active=2 --quiet systemctl poweroff"

RESET, BOLD = "\033[0m", "\033[1m"
DIM, FAINT = "\033[38;5;245m", "\033[38;5;240m"
ACCENT, WARM, OK, BAD = "\033[38;5;179m", "\033[38;5;215m", "\033[38;5;114m", "\033[38;5;203m"
SEL = "\033[48;5;94m\033[38;5;231m"
CLEAR, HIDE, SHOW = "\033[2J\033[3J\033[H", "\033[?25l", "\033[?25h"
TONES = {"ok": OK, "warn": WARM, "bad": BAD, "dim": DIM, "info": ACCENT}
SAY_PREFIX = {"ok": "[ok] ", "warn": "[!] ", "bad": "[ERRO] ", "info": "", "dim": ""}


class Fail(Exception):
    """Falha com o que fazer: o menu mostra as duas partes e volta."""

    def __init__(self, what, todo):
        super().__init__(what)
        self.what, self.todo = what, todo


def say(text, kind="info"):
    print(f"{TONES[kind]}{SAY_PREFIX[kind]}{text}{RESET}", flush=True)


def confirm(prompt, default=True):
    if not sys.stdin.isatty():
        return default
    hint = "S/n" if default else "s/N"
    answer = input(f"{ACCENT}{prompt} ({hint}): {RESET}").strip().lower()
    return default if not answer else answer in ("s", "sim", "y", "yes")


# ------------------------------------------------------------------- configuração
def load_settings():
    try:
        return json.loads(SETTINGS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def find_build_dir(candidates=BUILD_CANDIDATES, settings=None):
    """Pasta com validator.json e baseline.json, que fica fora do Git por ter segredos."""
    settings = load_settings() if settings is None else settings
    for folder in (os.environ.get("ATEBEAGLE_BUILD"), settings.get("build_dir"), *candidates):
        if folder and (Path(folder) / "validator.json").is_file():
            return Path(folder)
    return None


def build_dir():
    folder = find_build_dir()
    if folder:
        return folder
    if sys.stdin.isatty():
        typed = input(f"{ACCENT}Pasta com o validator.json: {RESET}").strip().strip('"')
        if typed and (Path(typed) / "validator.json").is_file():
            RUNS.mkdir(parents=True, exist_ok=True)
            SETTINGS.write_text(json.dumps({"build_dir": typed}), encoding="utf-8")
            return Path(typed)
    raise Fail("não encontrei o validator.json",
               r"copie as chaves e o validator.json para D:\ATEBEAGLE-build, ou defina ATEBEAGLE_BUILD")


def missing_dependencies():
    found = {name: False for name in DEPENDENCIES}
    for name in DEPENDENCIES:
        try:
            __import__(name)
            found[name] = True
        except ImportError:
            pass
    return [DEPENDENCIES[n] for n, ok in found.items() if not ok]


def install(packages):
    say("Instalando: " + ", ".join(packages))
    if subprocess.call([sys.executable, "-m", "pip", "install", "--quiet", *packages]):
        raise Fail("o pip não conseguiu instalar as dependências", "confira a internet e tente de novo")
    say("Dependências instaladas", "ok")


def ensure_dependencies():
    missing = missing_dependencies()
    if not missing:
        return
    if not confirm("Faltam " + ", ".join(missing) + ". Instalar agora"):
        raise Fail("faltam dependências: " + ", ".join(missing), "use a opção Instalar dependências")
    install(missing)


# ------------------------------------------------------------------- rede e serviços
def port_open(host, port, timeout=.6):
    with socket.socket() as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def get_json(url, timeout=3):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)


def post_json(url, timeout=10):
    req = urllib.request.Request(url, method="POST", data=b"")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def device():
    try:
        devices = get_json(VALIDATOR_URL + "/api/state", 2)["devices"]
    except (OSError, ValueError):
        return None
    return devices[0] if devices else None


def console_status():
    try:
        return get_json(CONSOLE_URL + "/api/status", 2)
    except (OSError, ValueError):
        return None


def board():
    sys.path.insert(0, str(ROOT / "scripts"))
    import attack_console
    password = os.environ.get("ATEBEAGLE_BOARD_PASSWORD", "temppwd")
    return attack_console.SshBoard(BOARD_TARGET, password), attack_console.BoardError


def start_service(name, args, cwd, port):
    """Sobe em segundo plano, sem janela, e confere que a porta abriu."""
    if port_open("127.0.0.1", port):
        say(f"{name} já estava no ar", "ok")
        return
    RUNS.mkdir(parents=True, exist_ok=True)
    log_path = RUNS / f"{name}.log"
    env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
    flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    log = open(log_path, "a", encoding="utf-8")
    log.write(f"\n--- {datetime.now():%d/%m %H:%M:%S} início\n")
    log.flush()
    proc = subprocess.Popen([sys.executable, *args], cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=log,
                            stderr=subprocess.STDOUT, creationflags=flags)
    log.close()
    end = time.time() + 20
    while time.time() < end:
        if port_open("127.0.0.1", port):
            say(f"{name} no ar", "ok")
            return
        if proc.poll() is not None:
            break
        time.sleep(.3)
    tail = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-4:]
    raise Fail(f"o {name} não subiu: " + " | ".join(tail), f"veja {log_path}")


def start_validator(folder):
    start_service("validador", ["-m", "atebeagle.validator", "--config", "validator.json"], folder, VALIDATOR_PORT)


def start_console(folder):
    start_service("console", [str(ROOT / "scripts" / "attack_console.py"), "--validator-config",
                              str(folder / "validator.json")], ROOT, CONSOLE_PORT)


def port_owner(port):
    out = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True, text=True, errors="replace").stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[1].endswith(f":{port}") and parts[3] == "LISTENING":
            return int(parts[4])
    return None


def command_line(pid):
    script = f"(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').CommandLine"
    return subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True, text=True,
                          errors="replace").stdout


def stop_service(name, port, marker):
    pid = port_owner(port)
    if pid is None:
        say(f"{name} já estava parado", "dim")
        return
    # Só encerra o processo se ele for mesmo nosso: outra coisa pode estar nessa porta.
    if marker not in command_line(pid):
        raise Fail(f"a porta {port} está com outro programa (PID {pid})", "feche esse programa manualmente")
    subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
    say(f"{name} encerrado", "ok")


# ------------------------------------------------------------------- placa
def parse_keys(text):
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


BOARD_REPORT = r"""
echo agent=$(systemctl is-active atebeagle-agent)
echo workload=$(systemctl is-active atebeagle-workload)
echo kint=$(lsmod | grep -c atebeagle_kint)
echo waitmod=$(test -x /etc/atebeagle/wait-modules.sh && echo sim || echo nao)
echo led=$(cat /sys/class/leds/beaglebone:green:usr3/brightness)
echo uptime=$(cut -d' ' -f1 /proc/uptime)
echo workload_sha=$(sha256sum /opt/atebeagle/workload.py 2>/dev/null | cut -d' ' -f1)
echo device_sha=$(sha256sum /etc/atebeagle/device.key | cut -d' ' -f1)
echo baseline_sha=$(sha256sum /etc/atebeagle/baseline.json | cut -d' ' -f1)
left=""
for f in /var/tmp/atb-workload.bak /usr/local/bin/atb-backdoor /usr/bin/atb-implante /usr/local/bin/backdoor /root/workload.py; do
  test -e "$f" && left="$left $f"
done
lsmod | grep -q '^dummy' && left="$left modulo:dummy"
systemctl is-active -q atb-miner && left="$left atb-miner"
systemctl is-active -q atb-netcut && left="$left atb-netcut"
echo restos=$left
"""


def file_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def assess_report(keys, folder):
    """Transforma o relatório da placa em linhas (tom, texto). Função pura, para poder testar."""
    rows = []

    def row(ok, good, bad, tone="bad"):
        rows.append(("ok", good) if ok else (tone, bad))

    row(keys.get("agent") == "active", "Agente de atestação ativo", f"Agente: {keys.get('agent')}")
    row(keys.get("workload") == "active", "Workload ativo", f"Workload: {keys.get('workload')}", "warn")
    row(keys.get("kint", "0") != "0", "Módulo atebeagle_kint carregado", "Módulo atebeagle_kint não carregado")
    row(keys.get("waitmod") == "sim", "Correção de boot presente (espera de módulos)",
        "Sem a correção de boot: esta é a imagem original e vai dar falso positivo")
    if folder:
        row(keys.get("device_sha") == file_sha(folder / "keys" / "device.key"),
            "Chave do dispositivo confere com o PC", "A chave da placa é diferente da que está no PC")
        row(keys.get("baseline_sha") == file_sha(folder / "baseline.json"),
            "Baseline confere com o PC", "A baseline da placa é diferente da que está no PC")
        baseline = json.loads((folder / "baseline.json").read_text(encoding="utf-8"))
        files = baseline.get("body", baseline).get("files", {})
        expected = (files.get("/opt/atebeagle/workload.py") or {}).get("sha256")
        row(keys.get("workload_sha") == expected, "Programa de controle confere com a baseline",
            "O programa de controle difere da baseline: recupere a placa")
    left = keys.get("restos", "").strip()
    row(not left, "Sem restos de ataque", f"Restos de ataque: {left}. Recupere a placa.", "warn")
    return rows


def clock_offset(ssh):
    t0 = time.time()
    _, out = ssh.run("date +%s.%N", timeout=20)
    t1 = time.time()
    return float(out.splitlines()[-1]) - (t0 + t1) / 2


def set_clock(ssh):
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    rc, out = ssh.run(f"date -u -s '{stamp}' >/dev/null", timeout=20)
    if rc:
        raise Fail(f"não consegui acertar o relógio: {out}", "confira a senha da placa")


def require_board(wait_s=0):
    if port_open(BOARD_HOST, 22):
        return
    if wait_s:
        say(f"Esperando a placa responder em {BOARD_HOST} (até {wait_s} s). Ctrl+C cancela.")
        end = time.time() + wait_s
        while time.time() < end:
            if port_open(BOARD_HOST, 22):
                say("A placa respondeu", "ok")
                return
            time.sleep(3)
    raise Fail(f"a placa não responde em {BOARD_HOST}",
               "ligue a placa com um cabo mini-USB de DADOS e espere pouco mais de 2 minutos")


def action_check():
    say("Verificando a placa", "info")
    require_board()
    say(f"Rede USB: a placa responde em {BOARD_HOST}", "ok")
    ensure_dependencies()
    ssh, board_error = board()
    try:
        rc, out = ssh.run(BOARD_REPORT, timeout=40)
        offset = clock_offset(ssh)
    except board_error as e:
        raise Fail(f"SSH falhou: {e}", "confira a senha (ATEBEAGLE_BOARD_PASSWORD) e a chave em known_hosts") from e
    say("SSH e sudo funcionando", "ok")
    keys = parse_keys(out)
    up = float(keys.get("uptime", "0"))
    say(f"Ligada há {up / 60:.0f} min" + (" (ainda no boot: o agente espera até 120 s)" if up < 130 else ""), "dim")
    say(f"Relógio confere: diferença de {offset:+.1f} s" if abs(offset) < 30
        else f"Relógio {offset:+.0f} s fora: use a opção Acertar o relógio",
        "ok" if abs(offset) < 30 else "warn" if abs(offset) < 120 else "bad")
    for tone, text in assess_report(keys, find_build_dir()):
        say(text, tone)
    say("LED USR3 " + ("aceso: a placa detectou falha local" if keys.get("led") == "1" else "apagado"),
        "warn" if keys.get("led") == "1" else "ok")


def action_clock():
    require_board()
    ensure_dependencies()
    ssh, board_error = board()
    try:
        before = clock_offset(ssh)
        set_clock(ssh)
        after = clock_offset(ssh)
    except board_error as e:
        raise Fail(f"SSH falhou: {e}", "confira a placa e a senha") from e
    say(f"Relógio acertado: estava {before:+.1f} s, agora {after:+.1f} s", "ok")


def wait_state(wanted, timeout):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        d = device()
        state = d and d["state"]
        if state != last:
            say(f"Estado: {state or 'sem resposta'}", "dim")
            last = state
        if state in wanted:
            return state
        time.sleep(2)
    return last


def recover():
    code, body = post_json(CONSOLE_URL + "/api/recover")
    if code != 202:
        raise Fail(f"o console recusou: {body.get('error')}", "espere a ação em andamento terminar")
    say("Recuperando: desfaz ataques, acerta o relógio e re-provisiona. Pode levar 2 minutos.")
    end = time.time() + 420
    while time.time() < end:
        s = console_status()
        if s and not s["busy"]:
            for line in s["log"][-5:]:
                if line["kind"] == "err":
                    raise Fail(line["text"], "veja runs/launcher/console.log")
            return
        time.sleep(2)
    raise Fail("a recuperação demorou demais", "confira a placa e tente de novo")


def action_recover():
    folder = build_dir()
    ensure_dependencies()
    start_validator(folder)
    start_console(folder)
    recover()
    d = device()
    say(f"Placa recuperada: {d and d['state']}", "ok")


def open_url(url):
    browser = next((p for p in BROWSERS if p.is_file()), None)
    if browser:  # janela própria, sem abas, para distribuir as telas nos monitores
        subprocess.Popen([str(browser), f"--app={url}", "--new-window"])
    else:
        webbrowser.open(url)


def active_screens():
    """Telas do modo que está no ar. Com os dois no ar, vale o real."""
    if port_open("127.0.0.1", VALIDATOR_PORT) and port_open("127.0.0.1", CONSOLE_PORT):
        return SCREENS
    if port_open("127.0.0.1", SIM_CONSOLE_PORT):
        return SIM_SCREENS
    raise Fail("nenhum modo está no ar", "use Iniciar com ataque real ou Iniciar simulado")


def open_screens(*names, screens=None):
    screens = screens or SCREENS
    for name in names or screens:
        open_url(screens[name])
    say("Telas abertas", "ok")


def action_start_sim():
    """Validador e agente reais contra uma placa falsa: não toca na BeagleBone."""
    try:
        __import__("cryptography")
    except ImportError:
        if not confirm("Falta cryptography. Instalar agora"):
            raise Fail("falta cryptography", "use a opção Instalar dependências") from None
        install(["cryptography"])
    start_service("simulacao", [str(ROOT / "scripts" / "sim_console.py")], ROOT, SIM_CONSOLE_PORT)
    say("Simulação no ar: nada aqui chega à BeagleBone.", "ok")
    open_screens(screens=SIM_SCREENS)
    say("A detecção de anomalias aprende por 8 ciclos (cerca de 80 s). O ciclo é de 10 s.", "dim")


def action_start():
    """Sobe tudo na ordem certa e só diz que está pronto com um veredito aprovado."""
    folder = build_dir()
    say(f"Dados locais: {folder}", "dim")
    ensure_dependencies()
    require_board(wait_s=180)
    ssh, board_error = board()
    try:
        offset = clock_offset(ssh)
        set_clock(ssh)
        _, out = ssh.run(BOARD_REPORT, timeout=40)
    except board_error as e:
        raise Fail(f"SSH falhou: {e}", "confira a senha da placa e tente de novo") from e
    say(f"Relógio acertado (estava {offset:+.0f} s)", "ok")
    bad = [text for tone, text in assess_report(parse_keys(out), folder) if tone == "bad"]
    for text in bad:
        say(text, "warn")
    start_validator(folder)
    start_console(folder)
    d = device()
    left = parse_keys(out).get("restos", "").strip()
    if left or (d and d["state"] == "REVOKED"):
        why = f"revogada: {d['reason']}" if d and d["state"] == "REVOKED" else f"com restos de ataque: {left}"
        if not confirm(f"A placa está {why}. Recuperar agora"):
            raise Fail("o sistema subiu, mas a placa não está liberada", "use a opção Recuperar a placa")
        recover()
    say("Esperando um veredito aprovado (até 3 min; depois de um boot o agente espera 120 s)")
    state = wait_state(("TRUSTED", "SUSPECT"), 180)
    if state not in ("TRUSTED", "SUSPECT"):
        raise Fail(f"a placa não foi aprovada: estado {state}",
                   "use Verificar a placa para ver o motivo, ou Recuperar a placa")
    say(f"Sistema pronto: placa {state}", "ok")
    open_screens()
    say("A detecção de anomalias aprende por 20 ciclos (cerca de 20 min) depois que o validador sobe.", "dim")


def close_windows(titles=SCREEN_TITLES):
    """Pede o fechamento das janelas com esses títulos exatos e devolve quantas achou."""
    if os.name != "nt":
        return 0
    import ctypes
    from ctypes import wintypes
    user32 = ctypes.windll.user32
    found = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def each(hwnd, _):
        if user32.IsWindowVisible(hwnd):
            buf = ctypes.create_unicode_buffer(256)
            user32.GetWindowTextW(hwnd, buf, 256)
            if buf.value in titles:
                found.append(hwnd)
        return True

    user32.EnumWindows(each, 0)
    for hwnd in found:
        user32.PostMessageW(hwnd, 0x0010, 0, 0)  # WM_CLOSE
    return len(found)


def attack_left_active():
    """Ataque real ativo deixa restos na placa. Devolve o título, se houver."""
    s = console_status()
    a = s and s.get("attack")
    return a["title"] if a and a["status"] in ("running", "detected") else None


def stop_everything():
    closed = close_windows()
    say(f"{closed} tela(s) fechada(s)" if closed else "Nenhuma tela aberta", "ok" if closed else "dim")
    stop_service("console", CONSOLE_PORT, "attack_console")
    stop_service("validador", VALIDATOR_PORT, "atebeagle.validator")
    stop_service("simulacao", SIM_CONSOLE_PORT, "sim_console")


def action_stop():
    title = attack_left_active()
    if title:
        say(f"Há um ataque ativo: {title}. Recupere a placa para não deixar restos.", "warn")
        if not confirm("Fechar mesmo assim", default=False):
            return
    stop_everything()
    say("A BeagleBone continua ligada.", "dim")


def action_shutdown(ask=True):
    """Fecha tudo e desliga a placa. O validador para antes: sem isso, o silêncio da placa
    desligada viraria uma revogação que continuaria valendo no próximo início."""
    board_up = port_open(BOARD_HOST, 22)
    title = attack_left_active()
    if title:
        say(f"Há um ataque ativo: {title}. Os restos ficam na placa até uma recuperação.", "warn")
    if ask and not confirm("Fechar tudo e desligar a BeagleBone? Para religar, use o botão POWER ou o cabo",
                           default=False):
        say("Nada foi fechado.", "dim")
        return
    if not board_up:
        stop_everything()
        raise Fail(f"tudo foi fechado, mas a placa não responde em {BOARD_HOST}",
                   "se ela ainda estiver ligada, segure o botão POWER por alguns segundos")
    ensure_dependencies()
    ssh, board_error = board()
    stop_everything()
    try:
        rc, out = ssh.run(POWEROFF, timeout=20)
    except board_error as e:
        raise Fail(f"não consegui mandar a placa desligar: {e}",
                   "segure o botão POWER por alguns segundos") from e
    if rc:
        raise Fail(f"a placa recusou o desligamento: {out}", "segure o botão POWER por alguns segundos")
    say("Desligando a BeagleBone")
    end = time.time() + 40
    while time.time() < end and port_open(BOARD_HOST, 22):
        time.sleep(1)
    if port_open(BOARD_HOST, 22):
        raise Fail("a placa ainda responde depois de 40 s", "espere mais um pouco ou segure o botão POWER")
    say("A BeagleBone saiu da rede. Espere os LEDs apagarem antes de tirar o cabo.", "ok")


def action_screen(name):
    open_screens(name, screens=active_screens())


def action_all_screens():
    open_screens(screens=active_screens())


def action_tests():
    try:
        __import__("pytest")
    except ImportError:
        install(["pytest"])
    subprocess.call([sys.executable, "-m", "pytest", "-q"], cwd=ROOT)


def action_install():
    install([*DEPENDENCIES.values(), "pytest"])


def action_logs():
    for name in ("validador", "console", "simulacao"):
        path = RUNS / f"{name}.log"
        say(f"--- {path}", "info")
        if path.is_file():
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[-12:]:
                print(line)
        else:
            say("sem registros ainda", "dim")


# ------------------------------------------------------------------- menu
class Status:
    def __init__(self):
        self.rows, self.version, self.lock = {}, 0, threading.Lock()

    def set(self, name, text, tone="dim"):
        with self.lock:
            if self.rows.get(name) != (text, tone):
                self.rows[name] = (text, tone)
                self.version += 1

    def snapshot(self):
        with self.lock:
            return [(k, t, tone) for k, (t, tone) in self.rows.items()]


def describe(board_up, dev, con, sim_up=False):
    """Painel de status como (nome, texto, tom). Função pura, para poder testar."""
    rows = [("Placa", f"respondendo em {BOARD_HOST}", "ok") if board_up
            else ("Placa", "sem resposta: confira o cabo mini-USB de dados", "bad")]
    if dev is None:
        rows.append(("Validador", "parado", "dim"))
    else:
        tone = {"TRUSTED": "ok", "SUSPECT": "warn", "REVOKED": "bad"}.get(dev["state"], "dim")
        reason = f": {dev['reason']}" if dev.get("reason") else ""
        rows.append(("Validador", f"{dev['state']}, época {dev['last_epoch']}{reason}", tone))
        anomaly = dev.get("anomaly") or {}
        rows.append(("Anomalias", "detecção ativa" if anomaly.get("ready") else "aprendendo (cerca de 20 min)",
                     "ok" if anomaly.get("ready") else "dim"))
    if con is None:
        rows.append(("Console", "parado", "dim"))
    else:
        attack = con.get("attack")
        active = attack and attack["status"] in ("running", "detected")
        rows.append(("Console", f"ataque ativo: {attack['title']}" if active else "no ar, nenhum ataque ativo",
                     "warn" if active else "ok"))
    rows.append(("Simulação", "no ar, sem tocar na placa" if sim_up else "parada", "info" if sim_up else "dim"))
    return rows


def visible_len(text):
    out, i = 0, 0
    while i < len(text):
        if text[i] == "\033":
            i = text.find("m", i) + 1
            continue
        out += 1
        i += 1
    return out


def clip(text, width):
    if visible_len(text) <= width:
        return text
    out, n, i = [], 0, 0
    while i < len(text) and n < width - 1:
        if text[i] == "\033":
            j = text.find("m", i)
            out.append(text[i:j + 1])
            i = j + 1
            continue
        out.append(text[i])
        n += 1
        i += 1
    return "".join(out) + "…" + RESET


def render(items, sel, status, width):
    w = max(60, min(width, 110))
    inner = w - 4
    stamp = datetime.now().strftime("%d/%m %H:%M")
    head = f"{BOLD}{ACCENT}ATEBEAGLE{RESET}  {DIM}pasteurizador P-101{RESET}"
    lines = [f" {FAINT}╭{'─' * (w - 3)}╮{RESET}",
             f" {FAINT}│{RESET} {head}{' ' * max(1, inner - visible_len(head) - len(stamp))}{DIM}{stamp}{RESET} {FAINT}│{RESET}",
             f" {FAINT}╰{'─' * (w - 3)}╯{RESET}", ""]
    label_w = max(len(it[1]) for it in items) + 2
    for i, (key, label, hint, *rest) in enumerate(items):
        if i == sel:
            body = f" ► {key:>2}  {label:<{label_w}}{hint}"
            lines.append(f"  {SEL}{BOLD}{clip(body + ' ' * max(0, inner + 1 - len(body)), inner + 1)}{RESET}")
        else:
            tone = TONES.get(rest[0], "") if rest else ""
            lines.append(clip(f"     {DIM}{key:>2}{RESET}  {tone}{label:<{label_w}}{RESET}{FAINT}{hint}{RESET}", inner + 2))
    if status:
        lines += ["", f"  {FAINT}── status {'─' * (inner - 9)}{RESET}"]
        name_w = max(len(n) for n, _, _ in status) + 2
        for name, text, tone in status:
            lines.append(clip(f"   {TONES.get(tone, DIM)}●{RESET} {DIM}{name:<{name_w}}{RESET}{text}", inner + 2))
    lines += ["", f"  {FAINT}↑↓ escolher · Enter abrir · tecla = atalho · Q sair (o sistema continua no ar){RESET}"]
    return "\n".join(lines)


def read_key():
    ch = msvcrt.getwch()
    if ch in ("\x00", "\xe0"):
        return {"H": "up", "P": "down"}.get(msvcrt.getwch(), "")
    if ch in ("\r", "\n", " "):
        return "enter"
    if ch == "\x03":
        raise KeyboardInterrupt
    if ch == "\x1b":
        return "quit"
    return ch.lower()


ITEMS = [
    ("1", "Iniciar com ataque real", "ataques de verdade na BeagleBone; confere a placa e abre as telas", "warn", action_start),
    ("2", "Iniciar simulado", "para brincar: placa falsa, nada chega à BeagleBone", "info", action_start_sim),
    ("3", "Verificar a placa", "rede, SSH, relógio, serviços, chave, baseline e restos", "", action_check),
    ("4", "Abrir as três telas", "do modo que estiver no ar", "", action_all_screens),
    ("5", "Abrir o Pasteurizador", "só a planta", "", lambda: action_screen("planta")),
    ("6", "Abrir os Ataques", "só a mesa do invasor", "", lambda: action_screen("ataques")),
    ("7", "Abrir o Monitoramento", "só o painel do validador", "", lambda: action_screen("monitor")),
    ("8", "Acertar o relógio", "a placa não tem bateria e perde a hora", "", action_clock),
    ("9", "Recuperar a placa", "desfaz ataques reais e re-provisiona", "warn", action_recover),
    ("0", "Fechar tudo", "telas, validador, console e simulação; a placa fica ligada", "", action_stop),
    ("x", "Fechar tudo e desligar a BBB", "desliga a placa; para religar, botão POWER ou cabo", "warn", action_shutdown),
    ("t", "Rodar os testes", "testes automatizados, não tocam a placa", "", action_tests),
    ("d", "Instalar dependências", "cryptography, paramiko e pytest", "", action_install),
    ("l", "Ver os logs", "últimas linhas do validador e do console", "", action_logs),
]


def run_action(fn):
    try:
        fn()
    except Fail as f:
        say(f.what, "bad")
        say(f"O que fazer: {f.todo}", "warn")
    except KeyboardInterrupt:
        say("Cancelado.", "warn")


def watch_status(status, stop):
    while not stop.is_set():
        for name, text, tone in describe(port_open(BOARD_HOST, 22), device(), console_status(), port_open("127.0.0.1", SIM_CONSOLE_PORT)):
            status.set(name, text, tone)
        stop.wait(2.5)


def interactive_menu():
    status = Status()
    stop = threading.Event()
    threading.Thread(target=watch_status, args=(status, stop), daemon=True).start()
    sel, drawn, size = 0, -1, None
    keys = [it[0] for it in ITEMS]
    items = [it[:4] for it in ITEMS]
    sys.stdout.write(HIDE)
    try:
        while True:
            now_size = shutil.get_terminal_size((100, 30))
            if status.version != drawn or now_size != size:
                drawn, size = status.version, now_size
                sys.stdout.write(CLEAR + render(items, sel, status.snapshot(), now_size.columns))
                sys.stdout.flush()
            if not msvcrt.kbhit():
                time.sleep(.05)
                continue
            k = read_key()
            if k == "q" or k == "quit":
                return
            if k == "up":
                sel = (sel - 1) % len(ITEMS)
            elif k == "down":
                sel = (sel + 1) % len(ITEMS)
            elif k == "enter" or k in keys:
                if k in keys:
                    sel = keys.index(k)
                sys.stdout.write(SHOW + CLEAR)
                sys.stdout.flush()
                say(ITEMS[sel][1] + "\n", "info")
                run_action(ITEMS[sel][4])
                print()
                input(f"{DIM}Enter para voltar ao menu{RESET}")
                sys.stdout.write(HIDE)
            else:
                continue
            drawn = -1
    finally:
        stop.set()
        sys.stdout.write(SHOW + RESET)
        sys.stdout.flush()


def numbered_menu():
    while True:
        for key, label, hint, *_ in ITEMS:
            print(f"  {key:>2}  {label}  ({hint})")
        choice = input("Opção (Q sai): ").strip().lower()
        if choice == "q":
            return
        match = [it for it in ITEMS if it[0] == choice]
        if match:
            run_action(match[0][4])


def main(argv=None):
    if os.name == "nt":
        os.system("")  # liga as sequências ANSI no console do Windows
    ap = argparse.ArgumentParser(description="Menu do ATEBEAGLE")
    group = ap.add_mutually_exclusive_group()
    for flag, help_text in (("--iniciar", "sobe tudo, com ataques reais, e abre as telas"),
                            ("--simulado", "sobe a simulação e abre as telas"), ("--verificar", "só confere a placa"),
                            ("--parar", "fecha as telas, o validador, o console e a simulação"),
                            ("--desligar", "fecha tudo e desliga a BeagleBone")):
        group.add_argument(flag, action="store_true", help=help_text)
    a = ap.parse_args(argv)
    direct = (action_start if a.iniciar else action_start_sim if a.simulado else action_check if a.verificar
              else action_stop if a.parar else (lambda: action_shutdown(ask=False)) if a.desligar else None)
    if direct:
        try:
            direct()
        except Fail as f:
            say(f.what, "bad")
            say(f"O que fazer: {f.todo}", "warn")
            return 1
        return 0
    try:
        if msvcrt and sys.stdin.isatty() and sys.stdout.isatty():
            interactive_menu()
        else:
            numbered_menu()
    except (KeyboardInterrupt, EOFError):
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
