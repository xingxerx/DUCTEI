#!/usr/bin/env python3
# Copyright (C) 2026 xingxerx
#
# Licensed under the Apache License 2.0. See the LICENSE file in the
# repository root for the full terms.

"""End-to-end smoke test for the second real DUCTEI consumer pair:
limend -> ductei-limen-relay -> ductei-qallow-relay -> `qallow ingest`
-> real LMDB (ql_persist_merge_blob).

Sibling of scripts/smoke_e2e.py; reuses its limend/relay helpers and
extends the chain one hop further, into Qallow. See ATRIUM
harness-roadmap/02-spine-flow.md for the "Qallow pair first" ordering.

Scenarios (same four as smoke_e2e.py, replayed through the extra hop):
  1. good job              limend -> relay -> qallow-relay -> qallow
                            ingest -> key readable via `qallow get`
  2. restart replicability a second qallow-relay process resumes from
                            its persisted cursor, doesn't re-forward
  3. malformed request     never reaches the LIMEN channel, so never
                            reaches the qallow-relay's source log
  4. malformed cert        never reaches the LIMEN channel either;
                            covered identically to smoke_e2e.py

Invariant coverage specific to this hop:
  I4  persistence before ack   a file in qallow-out/sent/ implies
                                `qallow get` returns the value
  I5  bounded sessions         this relay's own accepted.jsonl carries
                                exactly one line per forwarded job

Usage:
  python scripts/smoke_qallow.py --limen <LIMEN checkout> \
      --qallow-cli <path to qallow_cli's built `qallow` binary> \
      [--relay <ductei-limen-relay>] [--qallow-relay <ductei-qallow-relay>] \
      [--workdir DIR]
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


def run_limend(spool: Path, limen_dir: Path) -> None:
    subprocess.run(
        [sys.executable, "-m", "limen.limend", str(spool), "--once"],
        check=True, cwd=limen_dir, capture_output=True, text=True,
    )


def run_relay(relay: Path, spool: Path) -> None:
    subprocess.run([str(relay), str(spool), "--once"], check=True, capture_output=True, text=True)


def run_qallow_relay(qallow_relay: Path, limen_ductei_dir: Path, out_dir: Path, qallow_cli: Path) -> None:
    subprocess.run(
        [str(qallow_relay), str(limen_ductei_dir), str(out_dir),
         "--once", "--qallow-cli", str(qallow_cli)],
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


def write_request(spool: Path, job_id: str) -> None:
    request = {
        "job_id": job_id,
        "qubo": [[["a", "a"], -1.0], [["b", "b"], -1.0], [["a", "b"], 2.0]],
        "fidelity_target": 0.9,
        "credit_budget": 10.0,
        "offline": True,
    }
    (spool / "pending" / f"{job_id}.json").write_text(json.dumps(request))


def scenario_good_job(spool, limen_ductei, out_dir, limen_dir, relay, qallow_relay, qallow_cli) -> None:
    print("scenario 1: good job (through Qallow hop)")
    write_request(spool, "qsmoke-good-1")
    run_limend(spool, limen_dir)
    run_relay(relay, spool)
    run_qallow_relay(qallow_relay, limen_ductei, out_dir, qallow_cli)

    sent = list((out_dir / "sent").glob("*qsmoke-good-1*"))
    check(len(sent) == 1, "exactly one frame archived to qallow-out/sent/",
          "one file matching *qsmoke-good-1*")

    value = qallow_get(qallow_cli, out_dir / "qallow-store", "qallow.semantic.cert|limen.cert.qsmoke-good-1")
    check(value is not None, "key readable back out of real LMDB via `qallow get`",
          "FOUND:<cert json>")
    if value:
        cert = json.loads(value)
        check(cert.get("job_id") == "qsmoke-good-1",
              "stored value is the real cert JSON, job_id round-trips",
              "job_id == qsmoke-good-1")

    # I4: sent/ implies the value is actually gettable.
    if sent:
        check(value is not None, "sent/ archival implies LMDB actually has the value (I4)",
              "sent file present -> qallow get succeeds")

    accepted = read_jsonl(out_dir / "ductei" / "accepted.jsonl")
    ours = [e for e in accepted if e.get("key") == "limen.cert.qsmoke-good-1"]
    check(len(ours) == 1, "exactly one line in this relay's own accepted.jsonl (I5)",
          "one accepted.jsonl line for qsmoke-good-1")


def scenario_restart(spool, limen_ductei, out_dir, limen_dir, relay, qallow_relay, qallow_cli) -> None:
    print("scenario 2: restart replicability (Qallow hop)")
    accepted_before = len(read_jsonl(out_dir / "ductei" / "accepted.jsonl"))
    node_id_before = (out_dir / "ductei" / "relay-node-id").read_text().strip()

    write_request(spool, "qsmoke-restart-2")
    run_limend(spool, limen_dir)
    run_relay(relay, spool)
    run_qallow_relay(qallow_relay, limen_ductei, out_dir, qallow_cli)  # fresh process: restart by construction

    node_id_after = (out_dir / "ductei" / "relay-node-id").read_text().strip()
    check(node_id_after == node_id_before, "qallow-relay node id survives restart",
          f"{node_id_before} (got {node_id_after})")

    accepted = read_jsonl(out_dir / "ductei" / "accepted.jsonl")
    check(len(accepted) == accepted_before + 1,
          "restarted relay appended exactly one line, prior log intact",
          f"{accepted_before + 1} lines (got {len(accepted)})")

    value = qallow_get(qallow_cli, out_dir / "qallow-store", "qallow.semantic.cert|limen.cert.qsmoke-restart-2")
    check(value is not None, "post-restart job also reachable in LMDB", "FOUND:<cert json>")

    # re-running once more with nothing new pending must not re-append.
    run_qallow_relay(qallow_relay, limen_ductei, out_dir, qallow_cli)
    accepted2 = read_jsonl(out_dir / "ductei" / "accepted.jsonl")
    check(len(accepted2) == accepted_before + 1,
          "idle re-run (nothing new upstream) does not re-forward",
          f"still {accepted_before + 1} lines (got {len(accepted2)})")


def scenario_malformed_request(spool, limen_ductei, out_dir, limen_dir, qallow_relay, qallow_cli) -> None:
    print("scenario 3: malformed request (never reaches the Qallow hop)")
    bad = spool / "pending" / "qsmoke-badreq-3.json"
    bad.write_text("{this is not json")
    run_limend(spool, limen_dir)
    check(not bad.exists(), "malformed request removed from pending/", "gone")
    check((spool / "failed" / "qsmoke-badreq-3.json").exists(),
          "malformed request witnessed in spool/failed/", "present")

    run_qallow_relay(qallow_relay, limen_ductei, out_dir, qallow_cli)
    value = qallow_get(qallow_cli, out_dir / "qallow-store", "qallow.semantic.cert|limen.cert.qsmoke-badreq-3")
    check(value is None, "nothing from the malformed request ever reaches LMDB", "NOT_FOUND")


def scenario_malformed_cert(spool, limen_ductei, out_dir, relay, qallow_relay, qallow_cli) -> None:
    print("scenario 4: malformed cert (never reaches the Qallow hop)")
    bad = spool / "certs" / "qsmoke-badcert-4.json"
    bad.write_text('{"job_id": "qsmoke-badcert-4", "backend": 42}')
    run_relay(relay, spool)
    check(not bad.exists(), "malformed cert removed from certs/", "gone")
    check((spool / "failed" / "qsmoke-badcert-4.json").exists(),
          "malformed cert witnessed in spool/failed/", "present")

    run_qallow_relay(qallow_relay, limen_ductei, out_dir, qallow_cli)
    value = qallow_get(qallow_cli, out_dir / "qallow-store", "qallow.semantic.cert|limen.cert.qsmoke-badcert-4")
    check(value is None, "nothing from the malformed cert ever reaches LMDB", "NOT_FOUND")


def build_relays(ductei_root: Path) -> tuple[Path, Path]:
    subprocess.run(["cargo", "build", "-p", "ductei-limen", "-p", "ductei-qallow"],
                    check=True, cwd=ductei_root, capture_output=True, text=True)
    exe = ".exe" if os.name == "nt" else ""
    return (
        ductei_root / "target" / "debug" / f"ductei-limen-relay{exe}",
        ductei_root / "target" / "debug" / f"ductei-qallow-relay{exe}",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limen", type=Path, required=True)
    parser.add_argument("--qallow-cli", type=Path, required=True,
                        help="path to the built qallow_cli binary (`qallow` / `qallow.exe`)")
    parser.add_argument("--relay", type=Path, default=None)
    parser.add_argument("--qallow-relay", type=Path, default=None)
    parser.add_argument("--workdir", type=Path, default=None)
    args = parser.parse_args()

    ductei_root = Path(__file__).resolve().parent.parent
    relay = args.relay
    qallow_relay = args.qallow_relay
    if relay is None or qallow_relay is None:
        built_relay, built_qallow_relay = build_relays(ductei_root)
        relay = relay or built_relay
        qallow_relay = qallow_relay or built_qallow_relay

    if not args.qallow_cli.exists():
        print(f"qallow_cli binary not found: {args.qallow_cli}")
        return 2

    workdir = args.workdir or Path(tempfile.mkdtemp(prefix="ductei-smoke-qallow-"))
    root = workdir / "loop"
    if root.exists():
        shutil.rmtree(root)
    spool = root / "spool"
    limen_ductei = root / "ductei"   # ductei-limen-relay's own state dir
    out_dir = root / "qallow-out"    # ductei-qallow-relay's own state dir
    for d in ("pending", "done", "certs", "failed"):
        (spool / d).mkdir(parents=True)

    print(f"smoke-qallow: spool={spool}")
    print(f"smoke-qallow: relay={relay}")
    print(f"smoke-qallow: qallow-relay={qallow_relay}")
    print(f"smoke-qallow: qallow-cli={args.qallow_cli}\n")

    scenario_good_job(spool, limen_ductei, out_dir, args.limen, relay, qallow_relay, args.qallow_cli)
    scenario_restart(spool, limen_ductei, out_dir, args.limen, relay, qallow_relay, args.qallow_cli)
    scenario_malformed_request(spool, limen_ductei, out_dir, args.limen, qallow_relay, args.qallow_cli)
    scenario_malformed_cert(spool, limen_ductei, out_dir, relay, qallow_relay, args.qallow_cli)

    print()
    if _failures:
        print(f"smoke-qallow: {len(_failures)} check(s) failed:")
        for f in _failures:
            print(f"  - {f}")
        return 1
    print("smoke-qallow: all four scenarios passed, invariants held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
