"""Gera docs/arquitetura.drawio (abrir em app.diagrams.net e exportar PNG/PDF).

Paleta terrosa da BeagleBone. Rodar de novo após mudar a arquitetura:
  python3 scripts/gen_drawio.py
"""
from pathlib import Path
from xml.sax.saxutils import escape

TERRA, MOSTARDA, CARAMELO, GRAFITE, AREIA, CREME, VERDE = (
    "#B5532F", "#C9962B", "#A8743F", "#3B3532", "#E9DCCB", "#FFFAF4", "#4F7A4A")

cells = []
_id = [10]


def nid():
    _id[0] += 1
    return f"n{_id[0]}"


def box(text, x, y, w, h, fill=CREME, stroke=CARAMELO, font=GRAFITE, bold=False, dashed=False, size=12,
        align="center", valign="middle", rounded=1, parent="1"):
    i = nid()
    style = (f"rounded={rounded};whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};"
             f"fontColor={font};fontSize={size};fontStyle={1 if bold else 0};align={align};"
             f"verticalAlign={valign};arcSize=6;spacing=6;" + ("dashed=1;dashPattern=6 4;" if dashed else ""))
    cells.append(f'<mxCell id="{i}" value="{escape(text.replace(chr(10), '<br>'))}" style="{style}" vertex="1" parent="{parent}">'
                 f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')
    return i


def zone(title, x, y, w, h, fill, stroke, font=GRAFITE, dashed=False):
    return box(title, x, y, w, h, fill=fill, stroke=stroke, font=font, bold=True, size=14,
               align="left", valign="top", dashed=dashed)


def arrow(a, b, label="", color=GRAFITE, dashed=False, exit_=None, entry=None):
    i = nid()
    st = (f"edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;strokeColor={color};strokeWidth=2;"
          f"fontColor={GRAFITE};fontSize=11;endArrow=block;endFill=1;labelBackgroundColor={CREME};")
    if dashed:
        st += "dashed=1;"
    if exit_:
        st += f"exitX={exit_[0]};exitY={exit_[1]};exitDx=0;exitDy=0;"
    if entry:
        st += f"entryX={entry[0]};entryY={entry[1]};entryDx=0;entryDy=0;"
    cells.append(f'<mxCell id="{i}" value="{escape(label)}" style="{st}" edge="1" parent="1" source="{a}" '
                 f'target="{b}"><mxGeometry relative="1" as="geometry"/></mxCell>')


# título
box("ATEBEAGLE  |  Atestação Remota Contínua de Integridade na BeagleBone Black\n"
    "CyBOK v1.1: Cyber-Physical Systems Security (central), com Hardware Security, Applied Cryptography, "
    "Network Security e Physical Layer & Telecommunications", 20, 10, 1500, 56,
    fill=GRAFITE, stroke=GRAFITE, font=CREME, bold=True, size=14)

# ---------------- zona da placa
zone("BeagleBone Black (AM335x GP)  |  dispositivo NÃO confiável", 20, 90, 760, 640, "#F6EADF", TERRA)
k = zone("Kernel Linux", 40, 130, 720, 150, AREIA, CARAMELO)
ima = box("IMA\nmede executáveis e arquivos lidos por root\n(ascii_runtime_measurements)", 60, 165, 220, 95)
kint = box("atebeagle_kint.ko\nponteiros da sys_call_table\n(/proc, modo 0400)", 300, 165, 210, 95)
procm = box("/proc/modules\n/proc/kallsyms\nflag de taint", 530, 165, 210, 95)

ag = zone("Agente atebeagle (systemd, ciclo de 60 s)", 40, 300, 720, 290, AREIA, CARAMELO)
l2 = box("Coletor L2 (imagem)\nIMA + hash direto dos\ncaminhos críticos", 60, 340, 200, 80, fill=CREME, stroke=MOSTARDA)
l3 = box("Coletor L3.1 (runtime)\nsyscall table, módulos,\ntaint vs. referência de boot", 290, 340, 210, 80,
         fill=CREME, stroke=MOSTARDA)
bl = box("Baseline dourada\nASSINADA (Ed25519)", 540, 340, 200, 80, fill=CREME, stroke=MOSTARDA)
appr = box("Appraiser + Matriz de decisão\nALTERED, UNAUTHORIZED, MISSING,\nSYSCALL_TABLE, MODULE_NEW  →  PASS / FAIL",
           60, 440, 440, 60, fill=CREME, stroke=TERRA, bold=True)
pub = box("Publicador\népoca monotônica (fsync) · cadeia prev_hash\nassinatura Ed25519 · boot_id · timestamp",
          60, 515, 440, 60, fill=CREME, stroke=TERRA, bold=True)
gate = box("Gate local\nFAIL: apaga token, LED USR3,\npara o workload", 540, 440, 200, 135, fill="#F8E9E2", stroke=TERRA)

wl = box("Workload (sensor de temperatura)\nsó transmite com token de capacidade válido", 60, 615, 680, 55,
         fill=CREME, stroke=GRAFITE)

# ---------------- zona do validador
zone("Validador externo (notebook / servidor)  |  lado confiável", 820, 90, 700, 510, "#EEF1E9", VERDE)
ver = box("Verificação do envelope\nassinatura Ed25519 · época > última (anti-replay)\nprev_hash encadeado · janela de tempo",
          840, 135, 400, 75, stroke=VERDE, bold=True)
rem = box("Reavaliação remota L2\ncom a SUA cópia da baseline\n(pega agente que mente PASS)", 840, 230, 400, 70,
          stroke=VERDE)
sm = box("Máquina de estados\nUNKNOWN → TRUSTED ⇄ SUSPECT\nqualquer FAIL → REVOKED\n(chave revogada, só sai por re-provisionamento)",
         840, 320, 400, 90, stroke=TERRA, bold=True)
dms = box("Dead man's switch\nsilêncio > 2,5 × intervalo\n= REVOKED", 1270, 320, 230, 90, fill="#F8E9E2", stroke=TERRA)
ia = box("Detector de anomalias (IA)\nIsolation Forest + z-score robusto\nsobre telemetria do ciclo\n→ SUSPECT (revisão humana)",
         1270, 135, 230, 165, fill="#FBF3DF", stroke=MOSTARDA, bold=True)
tok = box("State-Gated I/O\ntoken HMAC curto, ligado à geração da chave\nrevogação invalida todos os tokens",
          840, 430, 400, 75, stroke=TERRA)
data = box("Consumidor dos dados\nPOST /data aceito só se TRUSTED", 840, 525, 400, 60, stroke=GRAFITE)
dash = box("Painel de demonstração\nestado, época, achados, eventos", 1270, 430, 230, 75, stroke=GRAFITE)
adm = box("Administrador\nre-provisiona com chave nova", 1270, 525, 230, 60, fill=AREIA, stroke=GRAFITE)

# ---------------- autoridade offline e L1
auth = box("Autoridade de baseline (offline)\nmede imagem limpa e assina\nchave privada nunca vai à placa",
           820, 625, 330, 95, fill=AREIA, stroke=GRAFITE, dashed=True)
l1 = box("L1 Plataforma: FORA do escopo implementado\nAM335x GP sem raiz de confiança em silício (sem TPM / Secure Boot)\n"
         "→ análise de lacuna: ataque com ring 0 pode falsificar as medições",
         1170, 625, 350, 95, fill="#F2E6E0", stroke=TERRA, dashed=True, size=11)

# arestas
arrow(ima, l2, exit_=(0.5, 1), entry=(0.5, 0))
arrow(kint, l3, exit_=(0.5, 1), entry=(0.5, 0))
arrow(procm, l3, exit_=(0.5, 1), entry=(1, 0.3))
arrow(l2, appr, exit_=(0.5, 1), entry=(0.2, 0))
arrow(l3, appr, exit_=(0.5, 1), entry=(0.7, 0))
arrow(bl, appr, exit_=(0.5, 1), entry=(1, 0.3))
arrow(appr, pub, exit_=(0.5, 1), entry=(0.5, 0))
arrow(appr, gate, "FAIL", color=TERRA, exit_=(1, 0.6), entry=(0, 0.3))
arrow(gate, wl, "token", exit_=(0.5, 1), entry=(0.85, 0))
arrow(pub, ver, "veredito assinado (HTTP/TLS)", color=TERRA, exit_=(1, 0.5), entry=(0, 0.5))
arrow(ver, rem, exit_=(0.5, 1), entry=(0.5, 0))
arrow(rem, sm, exit_=(0.5, 1), entry=(0.5, 0))
arrow(ver, ia, "telemetria", exit_=(1, 0.5), entry=(0, 0.3))
arrow(ia, sm, "SUSPECT", color=MOSTARDA, exit_=(0.5, 1), entry=(1, 0.3))
arrow(dms, sm, "silêncio", color=TERRA, exit_=(0, 0.5), entry=(1, 0.5))
arrow(sm, tok, exit_=(0.5, 1), entry=(0.5, 0))
arrow(tok, gate, "token no ACK", color=VERDE, exit_=(0, 0.5), entry=(1, 0.6), dashed=True)
arrow(wl, data, "dados + token", exit_=(1, 0.5), entry=(0, 0.5))
arrow(tok, data, exit_=(0.5, 1), entry=(0.5, 0))
arrow(sm, dash, exit_=(1, 0.8), entry=(0, 0.5), dashed=True)
arrow(adm, sm, exit_=(0.5, 0), entry=(1, 0.85), dashed=True)
arrow(auth, bl, "baseline assinada", dashed=True, exit_=(0, 0.3), entry=(1, 0.5))
arrow(auth, rem, dashed=True, exit_=(0.9, 0), entry=(0.1, 1))

xml = ('<mxfile host="atebeagle"><diagram name="Arquitetura ATEBEAGLE"><mxGraphModel dx="1600" dy="900" '
       'grid="1" gridSize="10" page="1" pageWidth="1560" pageHeight="760" background="#FFFFFF"><root>'
       '<mxCell id="0"/><mxCell id="1" parent="0"/>' + "".join(cells) + "</root></mxGraphModel></diagram></mxfile>")
out = Path(__file__).resolve().parents[1] / "docs" / "arquitetura.drawio"
out.write_text(xml, encoding="utf-8")
print(out)
