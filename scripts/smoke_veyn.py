#!/usr/bin/env python3
# Copyright (C) 2026 xingxerx
#
# Licensed under the Apache License 2.0. See the LICENSE file in the
# repository root for the full terms.

"""End-to-end smoke test for the third real DUCTEI consumer pair:
VEYN (ductei_bridge) -> ductei-qallow-relay -> real `qallow ingest` ->
real LMDB.

VEYN's own daemon writes directly into a DUCTEI channel in-process
(veyn-core/src/ductei_bridge.rs) rather than through a separate relay,
so there is no "ductei-veyn-relay" binary to build -- the second hop
reuses ductei-qallow-relay unmodified, since it already just tails
"some directory with an accepted.jsonl" (see ductei-qallow/src/bin/
relay.rs) regardless of which repo produced it. That is the third real
producer flowing through DUCTEI's spine (ATRIUM harness-roadmap/
02-spine-flow.md, "VEYN pair second").

The harness drives the exact production path (DucteiBridge::open /
.forward) via veyn-core's `ductei_bridge_smoke` example, without
booting the full async daemon.

Scenarios, tailored to VEYN's actual architecture rather than copied
verbatim from the LIMEN/Qallow pairs (whose "malformed X" scenarios
don't map 1:1 onto an in-process, best-effort bridge):
  1. good event             ductei_bridge_smoke -> real accepted.jsonl
                             -> qallow-relay -> qallow ingest -> LMDB
  2. restart replicability  a second qallow-relay process resumes from
                             its persisted cursor
  3. coalescing honored     two HRV samples for the same device inside
                             the default 1/min window -> only one
                             envelope ever reaches the channel (real
                             CoalescePolicy::default_policy, not
                             simulated)
  4. malformed input        an events file missing a required field
                             aborts ductei_bridge_smoke before the
                             corresponding envelope is ever written

Usage:
  python scripts/smoke_veyn.py --veyn <VEYN checkout> \
      --qallow-cli <path to built qallow_cli binary> \
      [--qallow-relay <ductei-qallow-relay>] [--workdir DIR]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PASS = "PASS"
FAIL = "FAIL"
_failures: list[str] = []


def check(ok: bool, what: str, detail: str = "") -> None:
    tag = PASS if ok else FAIL
    line = f"  [{tag}] {what}"
    if detail and not ok:
        line += f"\n         expected: {detail}"
    print(line)
    if not ok:
        _failures.append(what)


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def run_bridge_smoke(smoke_bin: Path, pair_dir: Path, events: list[dict]) -> subprocess.CompletedProcess:
    """Runs ductei_bridge_smoke against `pair_dir`. The log MUST be named
    accepted.jsonl (and the reject log rejected.jsonl) -- ductei-qallow-relay
    hardcodes that filename when tailing a source directory."""
    pair_dir.mkdir(parents=True, exist_ok=True)
    events_file = pair_dir / "events.json"
    events_file.write_text(json.dumps(events))
    return subprocess.run(
        [str(smoke_bin), str(pair_dir / "accepted.jsonl"), str(pair_dir / "rejected.jsonl"), str(events_file)],
        capture_output=True, text=True,
    )


def run_qallow_relay(qallow_relay: Path, source_dir: Path, out_dir: Path, qallow_cli: Path) -> None:
    subprocess.run(
        [str(qallow_relay), str(source_dir), str(out_dir), "--once", "--qallow-cli", str(qallow_cli)],
        check=True, capture_output=True, text=True,
    )


def qallow_get(qallow_cli: Path, store_dir: Path, key: str) -> str | None:
    out = subprocess.run(
        [str(qallow_cli), "get", str(store_dir), key],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if out == "NOT_FOUND":
        return None
    assert out.startswith("FOUND:")
    return out[len("FOUND:"):]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--veyn", type=Path, required=True, help="path to a VEYN checkout")
    parser.add_argument("--qallow-cli", type=Path, required=True)
    parser.add_argument("--qallow-relay", type=Path, default=None)
    parser.add_argument("--workdir", type=Path, default=None)
    args = parser.parse_args()

    ductei_root = Path(__file__).resolve().parent.parent
    qallow_relay = args.qallow_relay
    if qallow_relay is None:
        subprocess.run(["cargo", "build", "-p", "ductei-qallow"],
                        check=True, cwd=ductei_root, capture_output=True, text=True)
        exe = ".exe" if os.name == "nt" else ""
        qallow_relay = ductei_root / "target" / "debug" / f"ductei-qallow-relay{exe}"

    if not args.qallow_cli.exists():
        print(f"qallow_cli binary not found: {args.qallow_cli}")
        return 2

    print(f"smoke-veyn: building ductei_bridge_smoke in {args.veyn} ...")
    subprocess.run(
        ["cargo", "build", "-p", "veyn-core", "--example", "ductei_bridge_smoke"],
        check=True, cwd=args.veyn, capture_output=True, text=True,
    )
    exe = ".exe" if os.name == "nt" else ""
    smoke_bin = args.veyn / "target" / "debug" / "examples" / f"ductei_bridge_smoke{exe}"
    if not smoke_bin.exists():
        print(f"ductei_bridge_smoke binary not found after build: {smoke_bin}")
        return 2

    workdir = args.workdir or Path(tempfile.mkdtemp(prefix="ductei-smoke-veyn-"))
    veyn_dir = workdir / "veyn"
    if veyn_dir.exists():
        shutil.rmtree(veyn_dir)
    veyn_dir.mkdir(parents=True)

    print(f"smoke-veyn: workdir={veyn_dir}")
    print(f"smoke-veyn: smoke-bin={smoke_bin}")
    print(f"smoke-veyn: qallow-relay={qallow_relay}")
    print(f"smoke-veyn: qallow-cli={args.qallow_cli}\n")

    def bridge(pair_name: str, events: list[dict]) -> subprocess.CompletedProcess:
        return run_bridge_smoke(smoke_bin, veyn_dir / pair_name, events)

    def relay(source_dir: Path, out_name: str) -> Path:
        out_dir = veyn_dir / out_name
        run_qallow_relay(qallow_relay, source_dir, out_dir, args.qallow_cli)
        return out_dir

    def get(store_dir: Path, key: str) -> str | None:
        return qallow_get(args.qallow_cli, store_dir, key)

    pair1 = veyn_dir / "pair1"

    # --- scenario 1: good event --------------------------------------
    print("scenario 1: good event")
    r1 = bridge("pair1", [
        {"device_id": "ble-strap-1", "source": "ble", "metric": "heart_rate", "value": 72.0, "unit": "bpm"},
    ])
    check(r1.returncode == 0, "ductei_bridge_smoke exits 0 for a valid event", r1.stderr)
    accepted1 = read_jsonl(pair1 / "accepted.jsonl")
    check(len(accepted1) == 1, "exactly one envelope in VEYN's own accepted.jsonl", "1 line")
    if accepted1:
        check(accepted1[0]["scopes"] == ["veyn.sensor.ble"],
              "envelope carries the ble sensor scope, deny-by-default at the source", '["veyn.sensor.ble"]')

    out1 = relay(pair1, "qallow-out-1")
    hr_key = accepted1[0]["key"] if accepted1 else "?"
    v1 = get(out1 / "qallow-store", f"veyn.sensor.ble|{hr_key}")
    check(v1 is not None, "VEYN-originated event readable from real LMDB via `qallow get`", "FOUND:<payload json>")
    if v1:
        payload = json.loads(v1)
        check(payload.get("device_id") == "ble-strap-1", "stored payload round-trips device_id",
              "device_id == ble-strap-1")

    # --- scenario 2: restart replicability -----------------------------
    print("scenario 2: restart replicability")
    node_before = (out1 / "ductei" / "relay-node-id").read_text().strip()
    accepted_before = len(read_jsonl(out1 / "ductei" / "accepted.jsonl"))

    r2 = bridge("pair1", [
        {"device_id": "eeg-headset", "source": "eeg", "metric": "rem_detected", "value": 1.0, "unit": "bool"},
    ])
    check(r2.returncode == 0, "ductei_bridge_smoke exits 0 for the second event", r2.stderr)

    out1b = relay(pair1, "qallow-out-1")  # same out dir: fresh process = restart
    node_after = (out1b / "ductei" / "relay-node-id").read_text().strip()
    check(node_after == node_before, "qallow-relay node id survives restart", f"{node_before} (got {node_after})")

    accepted_after = read_jsonl(out1b / "ductei" / "accepted.jsonl")
    check(len(accepted_after) == accepted_before + 1,
          "restarted relay appended exactly one new line, prior log intact",
          f"{accepted_before + 1} (got {len(accepted_after)})")

    all_pair1 = read_jsonl(pair1 / "accepted.jsonl")
    rem_key = next(e["key"] for e in all_pair1 if e["scopes"] == ["veyn.rem_event"])
    v2 = get(out1b / "qallow-store", f"veyn.rem_event|{rem_key}")
    check(v2 is not None, "post-restart REM event also reachable in LMDB", "FOUND:<payload json>")

    # --- scenario 3: coalescing honored ---------------------------------
    print("scenario 3: coalescing honored (real CoalescePolicy)")
    device = "watch-coalesce-1"
    r3 = bridge("pair3", [
        {"device_id": device, "source": "healthkit", "metric": "hrv", "value": 55.0, "unit": "ms"},
        {"device_id": device, "source": "healthkit", "metric": "hrv", "value": 57.0, "unit": "ms"},
    ])
    check(r3.returncode == 0, "ductei_bridge_smoke exits 0 (coalescing is not an error)", r3.stderr)
    accepted3 = read_jsonl(veyn_dir / "pair3" / "accepted.jsonl")
    check(len(accepted3) == 1,
          "only one of two HRV samples inside the coalescing window reaches the channel",
          "1 line (second sample coalesced away by the real adapter)")
    # The channel-log assertion above is the real, sufficient evidence
    # that the production CoalescePolicy ran and dropped the second
    # sample; no separate LMDB round-trip needed for this scenario.

    # --- scenario 4: malformed input -------------------------------------
    print("scenario 4: malformed input")
    pair4 = veyn_dir / "pair4"
    pair4.mkdir(parents=True, exist_ok=True)
    events_file = pair4 / "events.json"
    events_file.write_text(json.dumps([
        {"device_id": "bad-1", "source": "ble", "metric": "heart_rate", "unit": "bpm"}  # missing "value"
    ]))
    r4 = subprocess.run(
        [str(smoke_bin), str(pair4 / "accepted.jsonl"), str(pair4 / "rejected.jsonl"), str(events_file)],
        capture_output=True, text=True,
    )
    check(r4.returncode != 0, "ductei_bridge_smoke aborts (nonzero exit) on a malformed event spec",
          "nonzero exit")
    accepted4 = read_jsonl(pair4 / "accepted.jsonl")
    check(len(accepted4) == 0, "no envelope written for the malformed event", "0 lines")

    print()
    if _failures:
        print(f"smoke-veyn: {len(_failures)} check(s) failed:")
        for f in _failures:
            print(f"  - {f}")
        return 1
    print("smoke-veyn: all four scenarios passed, invariants held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
