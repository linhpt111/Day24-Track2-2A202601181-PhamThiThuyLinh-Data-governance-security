"""Append-only tamper-evident JSONL ledger."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ZERO_HASH = "0" * 64


def _line_hash(entry: dict) -> str:
    payload = {k: v for k, v in entry.items() if k != "hash"}
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def append(entry: dict, path: Path) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    prev_hash = ZERO_HASH
    if path.exists():
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            prev_hash = json.loads(lines[-1]).get("hash", ZERO_HASH)

    record = dict(entry)
    record["prev_hash"] = prev_hash
    record["hash"] = _line_hash(record)

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    return record


def verify(path: Path) -> bool:
    if not path.exists():
        return True

    prev_hash = ZERO_HASH
    try:
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        for line in lines:
            record = json.loads(line)
            if not record.get("reason"):
                return False
            if record.get("prev_hash") != prev_hash:
                return False
            if record.get("hash") != _line_hash(record):
                return False
            prev_hash = record["hash"]
    except (json.JSONDecodeError, OSError, TypeError):
        return False
    return True
