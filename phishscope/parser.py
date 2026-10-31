"""Email parsing: sender identity, Received chain, bodies, attachments.

Everything here is pure stdlib and side-effect free so it can be unit-tested
on raw .eml files without network access.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from typing import Dict, List, Optional, Tuple

IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
FROM_RE = re.compile(r"^from\s+(\S+)", re.I)
BY_RE = re.compile(r"\bby\s+(\S+)", re.I)

# RFC 5737 documentation ranges are used by the bundled samples. We treat them
# as "public" so the sample campaign behaves like real internet traffic.
_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global or any(ip in net for net in _DOC_NETS)


@dataclass
class Hop:
    index: int
    from_host: str
    by_host: str
    ip: str
    public_ip: bool
    timestamp: str
    delay_s: Optional[int]
    raw: str


def load_eml(path: str) -> EmailMessage:
    """Load a raw RFC 5322 message from disk."""
    with open(path, "rb") as fh:
        return BytesParser(policy=policy.default).parse(fh)


def split_addr(value) -> Tuple[str, str, str]:
    """Return (display_name, address, domain) - all lower-cased except the name."""
    name, addr = parseaddr(str(value or ""))
    addr = addr.strip().lower()
    domain = addr.rsplit("@", 1)[1] if "@" in addr else ""
    return name.strip(), addr, domain


def identity(msg: EmailMessage) -> Dict[str, object]:
    """Collect every field an attacker can lie about, side by side."""
    f_name, f_addr, f_dom = split_addr(msg.get("From"))
    _, rp_addr, rp_dom = split_addr(msg.get("Return-Path"))
    _, rt_addr, rt_dom = split_addr(msg.get("Reply-To"))
    mid = str(msg.get("Message-ID", "")).strip("<> \t\r\n")
    mid_dom = mid.rsplit("@", 1)[1].lower() if "@" in mid else ""
    raw_recips = [str(x) for key in ("To", "Cc", "Delivered-To") for x in msg.get_all(key, [])]
    recips = sorted({a.lower() for _, a in getaddresses(raw_recips) if a})
    return {
        "subject": str(msg.get("Subject", "")).strip(),
        "date": str(msg.get("Date", "")).strip(),
        "from_name": f_name,
        "from_addr": f_addr,
        "from_domain": f_dom,
        "return_path": rp_addr,
        "return_path_domain": rp_dom,
        "reply_to": rt_addr,
        "reply_to_domain": rt_dom,
        "message_id": mid,
        "message_id_domain": mid_dom,
        "x_originating_ip": str(msg.get("X-Originating-IP", "")).strip("[] "),
        "recipients": recips,
    }


def received_chain(msg: EmailMessage) -> List[Hop]:
    """Return the Received headers ordered origin -> mailbox, with hop delays.

    Only the hops added by *your own* infrastructure can be trusted; anything
    below them was written by whoever sent the message.
    """
    raw = [" ".join(str(h).split()) for h in msg.get_all("Received", [])]
    raw.reverse()  # headers are prepended, so last = first hop
    hops: List[Hop] = []
    prev = None
    for i, r in enumerate(raw, 1):
        dt = None
        ts = ""
        if ";" in r:
            try:
                dt = parsedate_to_datetime(r.rsplit(";", 1)[1].strip())
                ts = dt.isoformat()
            except (TypeError, ValueError):
                dt = None
        from_clause = r.split(" by ", 1)[0]
        ips = [ip for ip in IPV4.findall(from_clause) if _valid(ip)]
        ip = ips[-1] if ips else ""
        m_from, m_by = FROM_RE.search(r), BY_RE.search(r)
        delay = None
        if dt and prev:
            try:
                delay = int((dt - prev).total_seconds())
            except TypeError:
                delay = None
        hops.append(Hop(i, m_from.group(1) if m_from else "", m_by.group(1) if m_by else "",
                        ip, is_public_ip(ip) if ip else False, ts, delay, r))
        prev = dt or prev
    return hops


def origin_ip(hops: List[Hop]) -> str:
    """First public IP in the chain = best guess for the real sender."""
    for hop in hops:
        if hop.public_ip:
            return hop.ip
    return ""


def _valid(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def bodies(msg: EmailMessage) -> Tuple[str, str]:
    """Return (text, html) bodies concatenated across MIME parts."""
    text, html = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except Exception:  # broken charset etc. - never crash an investigation
            continue
        if isinstance(content, str):
            (text if ctype == "text/plain" else html).append(content)
    return "\n".join(text), "\n".join(html)


def attachments(msg: EmailMessage) -> List[Dict[str, object]]:
    """List attachments with hashes (never executes or opens them)."""
    out = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        name = part.get_filename()
        if not name and part.get_content_disposition() != "attachment":
            continue
        payload = part.get_payload(decode=True) or b""
        out.append({
            "filename": name or "(unnamed)",
            "content_type": part.get_content_type(),
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "md5": hashlib.md5(payload).hexdigest(),  # legacy IOC feeds still use MD5
        })
    return out


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
