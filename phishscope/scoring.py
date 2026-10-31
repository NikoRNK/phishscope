"""Detection rules, risk score and verdict.

Every rule is an explicit, explainable heuristic: a Finding carries an ID, a
weight, human-readable evidence and (where relevant) a MITRE ATT&CK technique.
Nothing is a black box - an analyst can defend every point of the score.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List

from .auth import org_domain
from .urls import defang

# brand keyword -> legitimate registrable domains
BRANDS: Dict[str, set] = {
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com", "office365.com"},
    "paypal": {"paypal.com", "paypal.me"},
    "google": {"google.com", "gmail.com", "googlemail.com", "youtube.com", "googleapis.com", "gstatic.com", "googleusercontent.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.fr", "amazon.co.uk", "amazonaws.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "linkedin": {"linkedin.com"},
    "netflix": {"netflix.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "laposte": {"laposte.fr", "laposte.net"},
    "ameli": {"ameli.fr"},
    "impots": {"impots.gouv.fr", "dgfip.finances.gouv.fr"},
}

RISKY_EXT = {
    ".html": 15, ".htm": 15, ".shtml": 15, ".svg": 10, ".iso": 18, ".img": 18,
    ".lnk": 20, ".js": 20, ".vbs": 20, ".wsf": 20, ".hta": 22, ".exe": 25,
    ".scr": 25, ".bat": 20, ".cmd": 20, ".ps1": 20, ".jar": 20,
    ".docm": 18, ".xlsm": 18, ".pptm": 18, ".one": 15,
}
DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|js|vbs|html?|lnk|bat|cmd)$", re.I)

URGENCY = re.compile(
    r"urgent|immediately|within \d+ ?(hours|h)\b|account.{0,30}(suspend|lock|disabled)|verify your|"
    r"password.{0,25}expir|action required|unusual (sign-?in|activity)|"
    r"immédiatement|sous \d+ ?h\b|compte.{0,30}(suspendu|bloqué|désactivé)|vérifiez|action requise|activité inhabituelle",
    re.I,
)

URL_FLAG_WEIGHTS = {
    "anchor_mismatch": 20, "userinfo": 20, "ip_host": 15, "punycode": 15,
    "risky_tld": 8, "shortener": 8, "no_tls": 4, "deep_subdomain": 5,
}
URL_FLAG_TITLES = {
    "anchor_mismatch": "Link text shows one domain, href goes to another",
    "userinfo": "Credentials trick in URL (user@host)",
    "ip_host": "Link points to a raw IP address",
    "punycode": "Punycode (IDN homograph) domain",
    "risky_tld": "Link uses a TLD heavily abused by phishing",
    "shortener": "URL shortener hides the real destination",
    "no_tls": "Link is plain HTTP (no TLS)",
    "deep_subdomain": "Excessive subdomain depth",
}


@dataclass
class Finding:
    id: str
    category: str  # auth | identity | url | attachment | content | intel
    title: str
    weight: int
    evidence: str
    mitre: str = ""


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _normalize_label(label: str) -> str:
    """Undo common homoglyph tricks: rn->m, vv->w, 0->o, 1->l."""
    return label.replace("rn", "m").replace("vv", "w").replace("0", "o").replace("1", "l")


def lookalike_of(domain: str) -> str:
    """Return the brand a domain imitates ('' if none / if it is the real one).

    Token-based so 'ameliorate.com' is not flagged for 'ameli', while
    'rnicrosoft-support.com' (rn->m) or 'paypa1.com' are.
    """
    org = org_domain(domain)
    if not org:
        return ""
    for legit in BRANDS.values():
        if org in legit:
            return ""
    label = org.split(".")[0].lower()
    norm = _normalize_label(label)
    tokens = [t for t in re.split(r"[-_]", norm) if t]
    for brand in BRANDS:
        if brand in tokens:
            return brand
        if len(brand) >= 6 and any(t.startswith(brand) or t.endswith(brand) for t in tokens):
            return brand
        if len(norm) > 4 and levenshtein(norm, brand) <= 1:
            return brand
    return ""


# ---------------------------------------------------------------- rules --
def _auth_rules(ctx) -> List[Finding]:
    out: List[Finding] = []
    res = ctx["auth"]["results"]
    table = {
        "spf": {"fail": 20, "hardfail": 20, "softfail": 12, "none": 8, "neutral": 6, "permerror": 8, "temperror": 4},
        "dkim": {"fail": 15, "none": 8, "neutral": 6, "permerror": 8},
        "dmarc": {"fail": 25, "none": 8, "permerror": 8},
    }
    for mech, states in table.items():
        state = res.get(mech, "missing")
        if state in states:
            out.append(Finding(f"AUTH_{mech.upper()}_{state.upper()}", "auth", f"{mech.upper()} = {state}",
                               states[state], f"Authentication-Results: {mech}={state}", "T1656"))
    if all(res.get(m) == "missing" for m in ("spf", "dkim", "dmarc")):
        out.append(Finding("AUTH_NO_RESULTS", "auth", "No Authentication-Results header", 3,
                           "Cannot verify sender authenticity"))
    al = ctx["auth"]["alignment"]
    if res.get("spf") == "pass" and al["spf_aligned"] is False:
        out.append(Finding("SPF_PASS_NOT_ALIGNED", "auth", "SPF passes - for a DIFFERENT domain than From", 12,
                           f"Return-Path {ctx['identity']['return_path_domain']} vs From {ctx['identity']['from_domain']}", "T1656"))
    if res.get("dkim") == "pass" and al["dkim_aligned"] is False:
        out.append(Finding("DKIM_PASS_NOT_ALIGNED", "auth", "DKIM passes - for a DIFFERENT domain than From", 8,
                           "d= domain does not match From", "T1656"))
    return out


def _identity_rules(ctx) -> List[Finding]:
    out: List[Finding] = []
    i = ctx["identity"]
    from_org = org_domain(i["from_domain"])
    if i["return_path_domain"] and from_org and org_domain(i["return_path_domain"]) != from_org:
        out.append(Finding("RETURN_PATH_MISMATCH", "identity", "Envelope sender differs from visible From", 15,
                           f"From {i['from_addr']} / Return-Path {i['return_path']}", "T1656"))
    if i["reply_to_domain"] and from_org and org_domain(i["reply_to_domain"]) != from_org:
        out.append(Finding("REPLY_TO_MISMATCH", "identity", "Replies are redirected to another domain", 15,
                           f"Reply-To {i['reply_to']} vs From {i['from_addr']}", "T1656"))
    if i["message_id_domain"] and from_org and org_domain(i["message_id_domain"]) != from_org:
        out.append(Finding("MSGID_MISMATCH", "identity", "Message-ID generated by a different domain", 5,
                           f"Message-ID domain {i['message_id_domain']}"))
    m = re.search(r"[\w.+-]+@([\w.-]+)", i["from_name"])
    if m and org_domain(m.group(1)) != from_org:
        out.append(Finding("DISPLAY_NAME_EMAIL", "identity", "Display name contains a different email address", 20,
                           f"Display name '{i['from_name']}'", "T1656"))
    for brand, legit in BRANDS.items():
        if brand in i["from_name"].lower() and from_org and from_org not in legit:
            out.append(Finding("DISPLAY_NAME_BRAND", "identity", f"Display name impersonates '{brand}'", 20,
                               f"'{i['from_name']}' sent from {from_org}", "T1656"))
            break
    for field_name, label in (("from_domain", "From"), ("reply_to_domain", "Reply-To")):
        brand = lookalike_of(i[field_name]) if i[field_name] else ""
        if brand:
            out.append(Finding("LOOKALIKE_SENDER", "identity", f"{label} domain imitates '{brand}'", 25,
                               f"{defang(i[field_name])} resembles {brand}", "T1583.001"))
            break
    return out


def _chain_rules(ctx) -> List[Finding]:
    bad = [h for h in ctx["chain"] if h.delay_s is not None and h.delay_s < -60]
    if bad:
        return [Finding("HOP_TIME_ANOMALY", "identity", "Received timestamps go backwards", 10,
                        f"hop {bad[0].index}: {bad[0].delay_s}s - forged or misconfigured relay")]
    return []


def _url_rules(ctx) -> List[Finding]:
    out: List[Finding] = []
    links = ctx["links"]
    for flag, weight in URL_FLAG_WEIGHTS.items():
        hit = [l for l in links if flag in l.flags]
        if hit:
            sample = ", ".join(defang(l.url) for l in hit[:3])
            out.append(Finding(f"URL_{flag.upper()}", "url", URL_FLAG_TITLES[flag], weight, sample, "T1566.002"))
    imitations = [(l, lookalike_of(l.host)) for l in links if l.host]
    imitations = [(l, b) for l, b in imitations if b]
    if imitations:
        l, b = imitations[0]
        out.append(Finding("URL_LOOKALIKE", "url", f"Link domain imitates '{b}'", 25, defang(l.url), "T1566.002"))
    return out


def _attachment_rules(ctx) -> List[Finding]:
    out: List[Finding] = []
    for att in ctx["attachments"]:
        name = att["filename"].lower()
        if DOUBLE_EXT.search(name):
            out.append(Finding("ATT_DOUBLE_EXT", "attachment", "Double extension masquerade", 25,
                               att["filename"], "T1036.007"))
            continue
        ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
        if ext in RISKY_EXT:
            out.append(Finding("ATT_RISKY_EXT", "attachment", f"High-risk attachment type ({ext})", RISKY_EXT[ext],
                               f"{att['filename']} sha256={att['sha256'][:16]}...", "T1566.001"))
    return out


def _content_rules(ctx) -> List[Finding]:
    blob = ctx["text"] + " " + re.sub(r"<[^>]+>", " ", ctx["html"]) + " " + ctx["identity"]["subject"]
    hits = {m.group(0).lower() for m in URGENCY.finditer(blob)}
    if hits:
        return [Finding("CONTENT_URGENCY", "content", "Pressure / urgency language", 8 if len(hits) > 1 else 5,
                        ", ".join(sorted(hits)[:4]))]
    return []


def _intel_rules(ctx) -> List[Finding]:
    out: List[Finding] = []
    vt = ctx.get("vt") or {}
    for url, res in vt.get("urls", {}).items():
        mal = int(res.get("malicious", 0) or 0) + int(res.get("suspicious", 0) or 0)
        if mal >= 3:
            out.append(Finding("VT_URL_MALICIOUS", "intel", f"{mal} VirusTotal engines flag the URL", 40, defang(url), "T1566.002"))
        elif mal >= 1:
            out.append(Finding("VT_URL_SUSPICIOUS", "intel", f"{mal} VirusTotal engine(s) flag the URL", 20, defang(url), "T1566.002"))
    for sha, res in vt.get("files", {}).items():
        mal = int(res.get("malicious", 0) or 0)
        if mal >= 3:
            out.append(Finding("VT_FILE_MALICIOUS", "intel", f"{mal} VirusTotal engines flag the attachment", 40, sha[:16] + "...", "T1566.001"))
    return out


def evaluate(ctx) -> List[Finding]:
    findings: List[Finding] = []
    for rule in (_auth_rules, _identity_rules, _chain_rules, _url_rules,
                 _attachment_rules, _content_rules, _intel_rules):
        findings.extend(rule(ctx))
    return sorted(findings, key=lambda f: -f.weight)


def score(findings: List[Finding]) -> int:
    return min(100, sum(f.weight for f in findings))


def verdict(findings: List[Finding]) -> Dict[str, str]:
    total = score(findings)
    cats = {f.category for f in findings}
    confirmed = any(f.id in ("VT_URL_MALICIOUS", "VT_FILE_MALICIOUS") for f in findings)
    if total >= 70 or confirmed:
        label = "MALICIOUS"
    elif total >= 35:
        label = "SUSPICIOUS"
    else:
        label = "LIKELY BENIGN"
    if label == "LIKELY BENIGN":
        confidence = "HIGH" if total < 15 else "MEDIUM"
    elif len(cats) >= 3 or confirmed:
        confidence = "HIGH"
    elif len(cats) == 2:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"
    return {"label": label, "confidence": confidence, "score": str(total)}


def recommendations(label: str) -> List[str]:
    if label == "MALICIOUS":
        return [
            "Purge the message from every mailbox found in the blast radius (compliance search + purge).",
            "Block sender, Return-Path domain, URLs and origin IP at the mail gateway, proxy and DNS.",
            "Hunt proxy / DNS / EDR logs for contact with the IOCs; treat any hit as a compromised account.",
            "Force password reset + revoke sessions/tokens for users who clicked or opened the attachment.",
            "Warn recipients, report to the impersonated brand and the hosting provider's abuse contact.",
            "Add the IOCs to the TIP / SIEM watchlists and record the case.",
        ]
    if label == "SUSPICIOUS":
        return [
            "Quarantine the message and ask recipients not to interact with it.",
            "Detonate the attachment / URL in a sandbox and re-score with the result.",
            "Hunt for the same sender and URL domains across the mail store.",
            "Escalate to L2 if any recipient clicked.",
        ]
    return ["No action required. Close the ticket and document the reasoning (headers authenticate and align)."]
