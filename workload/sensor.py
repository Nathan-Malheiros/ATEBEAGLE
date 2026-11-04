"""Workload de demonstração: lê a temperatura do SoC (ou simula) e envia ao validador.

Só consegue enviar com o token de capacidade emitido para um dispositivo TRUSTED.
  python3 workload/sensor.py --url http://192.168.7.1:8700 --token /run/atebeagle/workload.token
"""
import argparse
import glob
import json
import random
import time
import urllib.error
import urllib.request


def read_temp():
    for p in glob.glob("/sys/class/thermal/thermal_zone*/temp"):
        try:
            return round(int(open(p).read()) / 1000, 1)
        except (OSError, ValueError):
            pass
    return round(40 + random.random() * 5, 1)


def send(url, token_path, device_id):
    try:
        token = open(token_path).read().strip()
    except OSError:
        token = ""
    req = urllib.request.Request(url.rstrip("/") + "/data", method="POST",
                                 data=json.dumps({"device_id": device_id, "token": token,
                                                  "value": {"temp_c": read_temp()}}).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())
    except OSError as e:
        return {"accepted": False, "reason": str(e)}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--token", default="/run/atebeagle/workload.token")
    ap.add_argument("--device-id", default="bbb-01")
    ap.add_argument("--every", type=float, default=5)
    a = ap.parse_args()
    while True:
        r = send(a.url, a.token, a.device_id)
        print("enviado" if r.get("accepted") else f"BLOQUEADO: {r.get('reason')}", flush=True)
        time.sleep(a.every)
