"""Orchestrates the 5-step investigation and returns one JSON-serialisable dict.

    1. Read the full headers, prove the spoof
    2. Check SPF, DKIM and DMARC
    3. Run every link (and attachment hash) through VirusTotal
    4. Trace who else received it
    5. End with a one-page report naming the verdict and the blast radius
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Dict, Optional

from . import __version__
from .auth import alignment, lookup_dns, org_domain, parse_authentication
from .blast import scan_corpus
from .parser import (attachments, bodies, file_sha256, identity, load_eml,
                     origin_ip, received_chain)
from .scoring import Finding, evaluate, recommendations, score, verdict
from .urls import defang, extract_links
from .virustotal import VirusTotal


def collect_iocs(ident, origin, links, atts) -> list:
    iocs = []
    if ident["from_addr"]:
        iocs.append({"type": "email", "value": ident["from_addr"], "defanged": ident["from_addr"].replace("@", "[@]").replace(".", "[.]")})
    if ident["reply_to"] and ident["reply_to"] != ident["from_addr"]:
        iocs.append({"type": "email", "value": ident["reply_to"], "defanged": ident["reply_to"].replace("@", "[@]").replace(".", "[.]")})
    if ident["return_path_domain"]:
        iocs.append({"type": "domain", "value": ident["return_path_domain"], "defanged": defang(ident["return_path_domain"])})
    if origin:
        iocs.append({"type": "ip", "value": origin, "defanged": origin.replace(".", "[.]")})
    seen = set()
    for l in links:
        if l.url not in seen:
            seen.add(l.url)
            iocs.append({"type": "url", "value": l.url, "defanged": defang(l.url)})
    for a in atts:
        iocs.append({"type": "sha256", "value": a["sha256"], "defanged": a["sha256"], "context": a["filename"]})
    return iocs


def analyze(path: str, corpus: Optional[str] = None, vt: Optional[VirusTotal] = None,
            dns: bool = True, vt_max: int = 6) -> Dict[str, object]:
    msg = load_eml(path)
    ident = identity(msg)
    chain = received_chain(msg)
    origin = origin_ip(chain)
    text, html = bodies(msg)
    atts = attachments(msg)
    links = extract_links(text, html)

    auth = parse_authentication(msg)
    auth["alignment"] = alignment(ident, auth)
    dns_info = lookup_dns(str(ident["from_domain"])) if dns else {"available": False}

    intel: Dict[str, Dict] = {"urls": {}, "files": {}}
    if vt:
        # most suspicious links first, so the free-tier quota is spent wisely
        ranked = sorted(links, key=lambda l: -len(l.flags))[:vt_max]
        for l in ranked:
            intel["urls"][l.url] = vt.url(l.url)
        for a in atts:
            intel["files"][a["sha256"]] = vt.file(a["sha256"])

    ctx = {"identity": ident, "chain": chain, "auth": auth, "links": links,
           "attachments": atts, "text": text, "html": html, "vt": intel if vt else None}
    findings = evaluate(ctx)
    v = verdict(findings)

    blast = scan_corpus(corpus, msg, path) if corpus else None
    if blast is None:
        blast = {"scanned": 0, "matched": [], "patient_zero": ident["recipients"],
                 "unique_recipients": ident["recipients"], "scope": "unknown (no corpus given)", "dates": []}

    sample_sha = file_sha256(path)
    return {
        "tool": f"phishscope {__version__}",
        "case_id": "PI-" + sample_sha[:8].upper(),
        "sample": {"path": path, "sha256": sample_sha},
        "verdict": v["label"],
        "confidence": v["confidence"],
        "risk_score": int(v["score"]),
        "identity": ident,
        "origin_ip": origin,
        "received_chain": [asdict(h) for h in chain],
        "authentication": auth,
        "dns": dns_info,
        "links": [asdict(l) for l in links],
        "attachments": atts,
        "threat_intel": intel if vt else None,
        "findings": [asdict(f) for f in findings],
        "iocs": collect_iocs(ident, origin, links, atts),
        "blast_radius": blast,
        "recommendations": recommendations(v["label"]),
    }
