"""Configuração do agente e do validador (JSON, sem dependências externas)."""
from __future__ import annotations

import copy
import json

AGENT_DEFAULTS = {
    "device_id": "bbb-01",
    "interval_s": 60,
    "state_dir": "/var/lib/atebeagle",
    "device_key": "/etc/atebeagle/device.key",
    "baseline_pubkey": "/etc/atebeagle/baseline_authority.pub",
    "validator_url": "http://192.168.7.1:8700",
    "send_evidence": True,
    "timeout_s": 5,
    "l2": {
        # "ima" usa o log do kernel; "fs" faz hashing direto (fallback se o IMA não existir)
        "collector": "ima",
        "ima_log": "/sys/kernel/security/ima/ascii_runtime_measurements",
        "baseline": "/etc/atebeagle/baseline.json",
        "root": "/",
        # só o que estiver sob estes prefixos é avaliado (ruído de /tmp, /proc etc. é ignorado).
        # "auto" = exatamente os diretórios cobertos pela baseline assinada.
        "monitored_prefixes": "auto",
        "fs_paths": ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/opt/atebeagle"],
        "check_missing": True,
    },
    "l3": {
        "enabled": True,
        "proc_root": "/proc",
        "kint_path": "/proc/atebeagle_kint",
    },
    "gate": {
        "token_file": "/run/atebeagle/workload.token",
        "led": "/sys/class/leds/beaglebone:green:usr3/brightness",
        "on_fail_cmd": ["systemctl", "stop", "atebeagle-workload.service"],
    },
}

VALIDATOR_DEFAULTS = {
    "listen": "0.0.0.0",
    "port": 8700,
    "state_file": "validator_state.json",
    "devices": {},  # device_id -> {"pubkey": "<b64>", "baseline": "<path opcional>"}
    "deadman_factor": 2.5,  # silêncio > fator * intervalo = FAIL
    "max_clock_skew_s": 120,
    "max_epoch_gap": 3,
    "token_ttl_factor": 2.0,
    "suspect_blocks_io": False,
    "admin_token": "troque-isto",
    "anomaly": {"enabled": True, "warmup": 20, "threshold": 6.0},
    "tls": {"cert": None, "key": None},
}


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load(path: str | None, defaults: dict) -> dict:
    if not path:
        return copy.deepcopy(defaults)
    with open(path, "r", encoding="utf-8") as f:
        return _merge(defaults, json.load(f))


def load_agent(path=None):
    return load(path, AGENT_DEFAULTS)


def load_validator(path=None):
    return load(path, VALIDATOR_DEFAULTS)
