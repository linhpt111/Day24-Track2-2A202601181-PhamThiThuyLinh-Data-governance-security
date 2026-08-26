"""Contained runner: split untrusted search, private reads, and egress."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, tools
from agent.policy import PolicyContext, check


REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
CUSTOMERS_FILE = Path(__file__).resolve().parent.parent / "data" / "customers.json"
AGENT_ID = "lab24-governed-agent"


def _hash_args(args: dict) -> str:
    encoded = json.dumps(args, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _ticket_id(doc_id: str) -> int | None:
    match = re.match(r"ticket-(\d+)", doc_id)
    return int(match.group(1)) if match else None


def _ticket_customer_index() -> dict[int, str]:
    customers = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
    index: dict[int, str] = {}
    for customer in customers:
        for ticket in customer.get("related_tickets", []):
            index[int(ticket)] = str(customer["customer_id"])
    return index


def _entry(
    *,
    run_id: str,
    tool: str,
    args: dict,
    classification: str,
    decision: str,
    reason: str,
    agent_owner: str,
) -> dict:
    return {
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "agent_id": AGENT_ID,
        "run_id": run_id,
        "tool": tool,
        "args_hash": _hash_args(args),
        "classification": classification,
        "decision": decision,
        "reason": reason,
        "agent_owner": agent_owner,
    }


def _authorize(
    *,
    ledger_path: Path,
    run_id: str,
    tool: str,
    args: dict,
    classification: str,
    purpose: str,
    owner: str,
    depth: int,
    egress: bool,
) -> bool:
    allow, reason = check(
        PolicyContext(
            data_classification=classification,
            request_purpose=purpose,
            agent_owner=owner,
            delegation_depth=depth,
            egress_enabled=egress,
        )
    )
    ledger.append(
        _entry(
            run_id=run_id,
            tool=tool,
            args=args,
            classification=classification,
            decision="allow" if allow else "deny",
            reason=reason,
            agent_owner=owner,
        ),
        ledger_path,
    )
    return allow


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    ledger_path = (log_dir or REPORTS_DIR) / "ledger.jsonl"

    if not _authorize(
        ledger_path=ledger_path,
        run_id="run-a",
        tool="search_docs",
        args={"query": message},
        classification="internal",
        purpose="summarize-tickets",
        owner="run-a",
        depth=0,
        egress=False,
    ):
        return "Khong the tim ticket do policy tu choi."

    docs = tools.search_docs(message)
    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)

    ticket_ids = sorted({ticket for doc in docs if (ticket := _ticket_id(doc["id"])) is not None})
    customer_by_ticket = _ticket_customer_index()
    customer_ids = sorted(
        {customer_by_ticket[ticket] for ticket in ticket_ids if ticket in customer_by_ticket}
    )

    for customer_id in customer_ids:
        if _authorize(
            ledger_path=ledger_path,
            run_id="run-b",
            tool="read_customer",
            args={"customer_id": customer_id},
            classification="restricted",
            purpose="support-reconciliation",
            owner="run-b",
            depth=1,
            egress=False,
        ):
            tools.read_customer(customer_id)

    if injected is not None:
        _authorize(
            ledger_path=ledger_path,
            run_id="run-c",
            tool="http_post",
            args={"url": injected.target_url, "body": {"records": "[restricted]"}},
            classification="restricted",
            purpose="blocked-injected-egress",
            owner="run-c",
            depth=1,
            egress=True,
        )

    return llm.summarize(docs)
