"""Blast radius: who ELSE received this campaign?

Scans a corpus of messages (a folder of .eml files and/or .mbox exports from
your mail gateway) and correlates them with the indicators of the analysed
message. In production you would run the equivalent query in your mail
security stack - see docs/HUNTING_QUERIES.md.
"""
from __future__ import annotations

import mailbox
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Dict, Iterator, List, Tuple

from .auth import org_domain
from .parser import attachments, bodies, identity, origin_ip, received_chain
from .urls import extract_links


def _norm_subject(s: str) -> str:
    s = re.sub(r"^(re|fwd?|tr)\s*:\s*", "", s.strip(), flags=re.I)
    return re.sub(r"\s+", " ", s).lower()


def _iter_messages(corpus: str) -> Iterator[Tuple[str, object]]:
    for path in sorted(Path(corpus).rglob("*")):
        if path.suffix.lower() == ".eml":
            with open(path, "rb") as fh:
                yield str(path), BytesParser(policy=policy.default).parse(fh)
        elif path.suffix.lower() == ".mbox":
            box = mailbox.mbox(str(path), factory=lambda f: BytesParser(policy=policy.default).parse(f))
            for n, m in enumerate(box):
                yield f"{path}#{n}", m


def indicators_of(msg) -> Dict[str, set]:
    ident = identity(msg)
    text, html = bodies(msg)
    return {
        "sender": {ident["from_addr"]} - {""},
        "return_path_domain": {org_domain(str(ident["return_path_domain"]))} - {""},
        "subject": {_norm_subject(str(ident["subject"]))} - {""},
        "url_domain": {org_domain(l.host) for l in extract_links(text, html)} - {""},
        "attachment_sha256": {a["sha256"] for a in attachments(msg)},
        "origin_ip": {origin_ip(received_chain(msg))} - {""},
    }


def scan_corpus(corpus: str, target_msg, target_path: str, min_reasons: int = 2) -> Dict[str, object]:
    """Return every corpus message sharing >= min_reasons indicators with the target.

    Two shared indicators keep false positives low (a shared sender alone is
    just a mailing list; sender + URL domain is a campaign).
    """
    wanted = indicators_of(target_msg)
    me = Path(target_path).resolve()
    scanned, matched = 0, []
    for source, msg in _iter_messages(corpus):
        if not source.split("#")[0].endswith("mbox") and Path(source).resolve() == me:
            continue
        scanned += 1
        have = indicators_of(msg)
        reasons = [k for k, v in wanted.items() if v and v & have[k]]
        if len(reasons) >= min_reasons:
            ident = identity(msg)
            matched.append({
                "source": source,
                "date": ident["date"],
                "subject": ident["subject"],
                "recipients": ident["recipients"],
                "reasons": reasons,
            })
    patient_zero = identity(target_msg)["recipients"]
    everyone = sorted(set(patient_zero) | {r for m in matched for r in m["recipients"]})
    dates = [m["date"] for m in matched if m["date"]]
    size = len(everyone)
    scope = "contained" if size <= 1 else "limited" if size <= 10 else "widespread"
    return {
        "scanned": scanned,
        "matched": matched,
        "patient_zero": patient_zero,
        "unique_recipients": everyone,
        "scope": scope,
        "dates": dates,
    }
