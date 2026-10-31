"""URL extraction and static analysis (no network)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List
from urllib.parse import urlsplit

from .auth import org_domain
from .parser import IPV4

URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.I)
BARE_DOMAIN_RE = re.compile(r"^(?:https?://)?[\w.-]+\.[a-z]{2,}(?:/\S*)?$", re.I)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
}
RISKY_TLDS = {
    "zip", "mov", "xyz", "top", "click", "icu", "tk", "ml", "ga", "cf", "gq",
    "cam", "rest", "country", "work", "monster", "buzz",
}


@dataclass
class Link:
    url: str
    host: str
    anchor_text: str = ""
    flags: List[str] = field(default_factory=list)


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: List[tuple] = []
        self._href = None
        self._buf: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._buf = []

    def handle_data(self, data):
        if self._href is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._buf).split())))
            self._href = None


def defang(value: str) -> str:
    """Make an IOC safe to paste in tickets and chats (hxxp, [.])."""
    return re.sub(r"^http", "hxxp", value, flags=re.I).replace(".", "[.]")


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def analyze_link(link: Link) -> Link:
    parts = urlsplit(link.url)
    host = link.host
    flags = []
    if IPV4.fullmatch(host):
        flags.append("ip_host")
    if "xn--" in host:
        flags.append("punycode")
    if host in SHORTENERS:
        flags.append("shortener")
    if "@" in parts.netloc:
        flags.append("userinfo")  # http://paypal.com@evil.tld/
    if host.rsplit(".", 1)[-1] in RISKY_TLDS:
        flags.append("risky_tld")
    if parts.scheme == "http":
        flags.append("no_tls")
    if host.count(".") >= 4:
        flags.append("deep_subdomain")
    text = link.anchor_text
    if text and BARE_DOMAIN_RE.match(text):
        shown = _host(text if text.lower().startswith("http") else "http://" + text)
        if shown and org_domain(shown) != org_domain(host):
            flags.append("anchor_mismatch")  # text says A, href goes to B
    link.flags = flags
    return link


def extract_links(text: str, html: str) -> List[Link]:
    """Union of <a href> targets (with anchor text) and raw URLs in the bodies."""
    found: Dict[str, Link] = {}
    parser = _AnchorParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    for href, anchor in parser.links:
        if href and href.lower().startswith(("http://", "https://")):
            found.setdefault(href, Link(href, _host(href), anchor))
    for blob in (text, html):
        for raw in URL_RE.findall(blob):
            url = raw.rstrip(".,;:!?")
            found.setdefault(url, Link(url, _host(url)))
    return [analyze_link(link) for link in found.values()]
