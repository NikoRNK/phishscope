"""SPF / DKIM / DMARC: read what the receiving MTA concluded, then check alignment.

Key idea: SPF or DKIM *passing* proves nothing about the visible From address.
DMARC only passes when a passing mechanism is ALIGNED with the From domain.
Attackers routinely send mail that passes SPF - for their own domain.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

AUTH_RE = re.compile(
    r"\b(spf|dkim|dmarc|arc)\s*=\s*"
    r"(pass|fail|softfail|hardfail|neutral|none|temperror|permerror|policy|bestguesspass)",
    re.I,
)

# Poor-man's public-suffix list. Install `tldextract` for production accuracy.
_MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp",
    "co.nz", "com.br", "com.tr", "co.in", "com.cn", "com.mx", "co.za",
    "gouv.fr", "asso.fr",
}


def org_domain(host: str) -> str:
    """Approximate the organizational (registrable) domain of a host."""
    host = (host or "").lower().strip(".")
    try:  # optional accuracy boost
        import tldextract  # type: ignore
        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except Exception:
        pass
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in _MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _dkim_signatures(msg) -> List[Dict[str, str]]:
    sigs = []
    for raw in msg.get_all("DKIM-Signature", []):
        flat = " ".join(str(raw).split())
        tags = {}
        for chunk in flat.split(";"):
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                tags[k.strip()] = v.strip()
        sigs.append({"d": tags.get("d", "").lower(), "s": tags.get("s", ""), "a": tags.get("a", "")})
    return sigs


def parse_authentication(msg) -> Dict[str, object]:
    """Parse the receiving server's verdicts (the TOPMOST Authentication-Results).

    Only trust the header added by your own gateway; lower ones can be forged.
    """
    results = {"spf": "missing", "dkim": "missing", "dmarc": "missing"}
    details: Dict[str, str] = {}
    headers = msg.get_all("Authentication-Results", [])
    if headers:
        text = " ".join(str(headers[0]).split())
        details["authserv_id"] = text.split(";", 1)[0].strip()
        for mech, state in AUTH_RE.findall(text):
            mech = mech.lower()
            if mech in results and results[mech] == "missing":
                results[mech] = state.lower()
        for key in ("smtp.mailfrom", "header.from", "header.d", "header.i", "smtp.remote-ip"):
            m = re.search(re.escape(key) + r"=([^\s;]+)", text)
            if m:
                details[key] = m.group(1).strip("<>")
    received_spf = msg.get("Received-SPF")
    if received_spf and results["spf"] == "missing":
        m = re.match(r"\s*(\w+)", str(received_spf))
        if m:
            results["spf"] = m.group(1).lower()
    return {"results": results, "details": details, "dkim_signatures": _dkim_signatures(msg)}


def alignment(ident: Dict[str, object], auth: Dict[str, object]) -> Dict[str, Optional[bool]]:
    """Relaxed DMARC alignment: compare organizational domains."""
    from_org = org_domain(str(ident.get("from_domain", "")))
    mailfrom = auth["details"].get("smtp.mailfrom", "")  # type: ignore[union-attr]
    spf_dom = str(ident.get("return_path_domain") or (mailfrom.rsplit("@", 1)[1] if "@" in mailfrom else ""))
    spf_aligned = (org_domain(spf_dom) == from_org) if spf_dom and from_org else None
    sigs = auth.get("dkim_signatures", [])
    dkim_aligned = None
    if sigs and from_org:
        dkim_aligned = any(org_domain(s["d"]) == from_org for s in sigs)  # type: ignore[index]
    return {"spf_aligned": spf_aligned, "dkim_aligned": dkim_aligned}


def _txt(name: str) -> Optional[List[str]]:
    """TXT lookup via dnspython. None = dnspython missing, [] = no record/error."""
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return None
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=4)
        return ["".join(s.decode() for s in r.strings) for r in answers]
    except Exception:
        return []


def lookup_dns(from_domain: str) -> Dict[str, object]:
    """Fetch the *published* SPF and DMARC policy of the visible From domain."""
    out: Dict[str, object] = {"available": False, "spf": "", "dmarc": "", "dmarc_policy": ""}
    if not from_domain:
        return out
    dmarc_txt = _txt(f"_dmarc.{org_domain(from_domain)}")
    if dmarc_txt is None:
        return out
    out["available"] = True
    for rec in dmarc_txt:
        if rec.lower().startswith("v=dmarc1"):
            out["dmarc"] = rec
            m = re.search(r"\bp=(\w+)", rec)
            out["dmarc_policy"] = m.group(1).lower() if m else ""
    for rec in _txt(from_domain) or []:
        if rec.lower().startswith("v=spf1"):
            out["spf"] = rec
    return out
