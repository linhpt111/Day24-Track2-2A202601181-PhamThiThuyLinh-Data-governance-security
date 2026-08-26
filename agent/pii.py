"""PII detection and redaction for the lab agent."""
from __future__ import annotations

import re


EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
CCCD_RE = re.compile(r"\b\d{12}\b")
PHONE_RE = re.compile(r"\b0(?:[\s.-]?\d){9,10}\b")
BANK_RE = re.compile(r"\b\d{8,16}\b")


def _add_entity(entities: list[dict], kind: str, start: int, end: int) -> None:
    if any(start < e["end"] and e["start"] < end for e in entities):
        return
    entities.append({"type": kind, "start": start, "end": end})


def _near_label(text: str, start: int, labels: tuple[str, ...], window: int = 56) -> bool:
    prefix = text[max(0, start - window) : start].lower()
    return any(label.lower() in prefix for label in labels)


def detect(text: str) -> list[dict]:
    entities: list[dict] = []

    for match in EMAIL_RE.finditer(text):
        _add_entity(entities, "EMAIL", match.start(), match.end())

    for match in CCCD_RE.finditer(text):
        if _near_label(text, match.start(), ("cccd", "can cuoc", "căn cước"), 40):
            _add_entity(entities, "VN_CCCD", match.start(), match.end())

    for match in PHONE_RE.finditer(text):
        if _near_label(
            text,
            match.start(),
            ("sđt", "sdt", "dien thoai", "điện thoại", "phone", "lien he", "liên hệ"),
            56,
        ):
            _add_entity(entities, "VN_PHONE", match.start(), match.end())

    for match in BANK_RE.finditer(text):
        if _near_label(
            text,
            match.start(),
            ("stk", "tai khoan", "tài khoản", "chuyen khoan", "chuyển khoản"),
            64,
        ):
            _add_entity(entities, "VN_BANK_ACCOUNT", match.start(), match.end())

    return sorted(entities, key=lambda e: (e["start"], e["end"], e["type"]))


def redact(text: str) -> str:
    redacted = text
    for entity in sorted(detect(text), key=lambda e: e["start"], reverse=True):
        replacement = f"[REDACTED_{entity['type']}]"
        redacted = redacted[: entity["start"]] + replacement + redacted[entity["end"] :]
    return redacted
