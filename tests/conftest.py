"""Ambiente simulado: um "root" falso da placa, um /proc falso e chaves de teste."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from atebeagle import baseline as bmod, config, crypto  # noqa: E402
from atebeagle.common import write_json  # noqa: E402
from fakeboard import make_fake_board  # noqa: E402


@pytest.fixture
def board(tmp_path):
    root, proc = make_fake_board(tmp_path)
    keys = tmp_path / "keys"
    dev_pub = crypto.generate_keypair(str(keys / "device.key"), str(keys / "device.pub"))
    crypto.generate_keypair(str(keys / "authority.key"), str(keys / "authority.pub"))
    bl = bmod.sign(bmod.build(str(root), ["/usr/bin", "/opt/atebeagle"]),
                   crypto.load_private(str(keys / "authority.key")))
    write_json(str(tmp_path / "baseline.json"), bl)
    agent_cfg = config._merge(config.AGENT_DEFAULTS, {
        "device_id": "bbb-01",
        "interval_s": 60,
        "state_dir": str(tmp_path / "state"),
        "device_key": str(keys / "device.key"),
        "baseline_pubkey": str(keys / "authority.pub"),
        "validator_url": "http://127.0.0.1:1",
        "l2": {"collector": "fs", "root": str(root), "fs_paths": ["/usr/bin", "/opt/atebeagle"],
               "baseline": str(tmp_path / "baseline.json")},
        "l3": {"proc_root": str(proc), "kint_path": str(tmp_path / "no_kint")},
        "gate": {"token_file": str(tmp_path / "run/workload.token"), "led": None, "on_fail_cmd": None},
    })
    val_cfg = config._merge(config.VALIDATOR_DEFAULTS, {
        "state_file": str(tmp_path / "validator_state.json"),
        "devices": {"bbb-01": {"pubkey": dev_pub, "baseline": str(tmp_path / "baseline.json")}},
        "anomaly": {"enabled": True, "warmup": 10, "threshold": 6.0},
    })
    return {"tmp": tmp_path, "root": root, "proc": proc, "agent": agent_cfg, "validator": val_cfg}
