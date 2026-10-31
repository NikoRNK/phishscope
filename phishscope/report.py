"""Render the analysis as an analyst-ready Markdown report (+ JSON / CSV)."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Dict, List


def _esc(v) -> str:
    return str(v).replace("|", "\\|").replace("\n", " ")


def _table(headers: List[str], rows: List[List[object]]) -> str:
    if not rows:
        return "_none_\n"
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(_esc(c) for c in r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def _summary(r: Dict) -> str:
    i, a = r["identity"], r["authentication"]["results"]
    flagged = sum(1 for l in r["links"] if l["flags"])
    cats = sorted({f["category"] for f in r["findings"]})
    who = f"{i['from_name']} <{i['from_addr']}>" if i["from_name"] else i["from_addr"]
    s = (f"A message claiming to come from **{who}** was relayed by **{i['return_path_domain'] or 'unknown'}**"
         f" (origin IP `{r['origin_ip'] or 'n/a'}`). Authentication: SPF={a['spf']}, DKIM={a['dkim']}, DMARC={a['dmarc']}. "
         f"{len(r['findings'])} indicator(s) fired across {len(cats)} categor{'y' if len(cats) == 1 else 'ies'} "
         f"({', '.join(cats) or 'none'}); {flagged} of {len(r['links'])} link(s) flagged.")
    return s


def render_markdown(r: Dict) -> str:
    i, auth, blast = r["identity"], r["authentication"], r["blast_radius"]
    al = auth["alignment"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    icon = {"MALICIOUS": "🔴", "SUSPICIOUS": "🟠", "LIKELY BENIGN": "🟢"}.get(r["verdict"], "⚪")
    L: List[str] = []
    L.append(f"# Phishing Investigation Report — {r['case_id']}\n")
    L.append(f"> **Subject:** {_esc(i['subject'])}  \n> **Generated:** {now} · **Tool:** {r['tool']} · "
             f"**Sample SHA-256:** `{r['sample']['sha256']}`\n")

    # ---- page 1: executive summary -----------------------------------------
    L.append("## 1. Verdict\n")
    L.append(f"### {icon} {r['verdict']} — risk {r['risk_score']}/100 — confidence {r['confidence']}\n")
    L.append(_summary(r) + "\n")
    L.append("## 2. Blast radius\n")
    L.append(f"- **Scope:** {blast['scope']}")
    L.append(f"- **Unique recipients:** {len(blast['unique_recipients'])} "
             f"({', '.join(blast['unique_recipients']) or 'n/a'})")
    L.append(f"- **Related messages found:** {len(blast['matched'])} (of {blast['scanned']} scanned)\n")
    if blast["matched"]:
        L.append(_table(["Message", "Recipients", "Shared indicators"],
                        [[m["source"], ", ".join(m["recipients"]), ", ".join(m["reasons"])] for m in blast["matched"]]))
    L.append("## 3. Recommended actions\n")
    L += [f"{n}. {a}" for n, a in enumerate(r["recommendations"], 1)]
    L.append("\n---\n")

    # ---- details ---------------------------------------------------------
    L.append("## 4. Proof of spoof — who the message says it is vs who sent it\n")
    L.append(_table(["Field", "Value", "Note"], [
        ["From (visible)", f"{i['from_name']} <{i['from_addr']}>", "What the victim sees"],
        ["Return-Path (envelope)", i["return_path"] or "—", "Where bounces go — who SPF really checked"],
        ["Reply-To", i["reply_to"] or "—", "Where the victim's answer goes"],
        ["Message-ID domain", i["message_id_domain"] or "—", "Which system generated the message"],
        ["Origin IP", r["origin_ip"] or "—", "First public hop in the Received chain"],
    ]))
    L.append("## 5. SPF · DKIM · DMARC\n")
    res = auth["results"]
    L.append(_table(["Mechanism", "Result", "Aligned with From?"], [
        ["SPF", res["spf"], {True: "yes", False: "**NO**", None: "unknown"}[al["spf_aligned"]]],
        ["DKIM", res["dkim"], {True: "yes", False: "**NO**", None: "unknown"}[al["dkim_aligned"]]],
        ["DMARC", res["dmarc"], "—"],
    ]))
    dns = r["dns"]
    if dns.get("available"):
        L.append(f"Published DMARC policy for `{i['from_domain']}`: `{dns.get('dmarc_policy') or 'none found'}`  \n"
                 f"Published SPF: `{dns.get('spf') or 'none found'}`\n")
    L.append("## 6. Findings\n")
    L.append(_table(["Weight", "ID", "Finding", "Evidence", "ATT&CK"],
                    [[f["weight"], f["id"], f["title"], f["evidence"], f["mitre"] or "—"] for f in r["findings"]]))
    L.append("## 7. Links\n")
    L.append(_table(["URL (defanged)", "Anchor text", "Flags"],
                    [[_defang(l["url"]), l["anchor_text"] or "—", ", ".join(l["flags"]) or "—"] for l in r["links"]]))
    L.append("## 8. Attachments\n")
    L.append(_table(["File", "Type", "Size", "SHA-256"],
                    [[a["filename"], a["content_type"], a["size"], a["sha256"]] for a in r["attachments"]]))
    if r["threat_intel"]:
        L.append("## 9. VirusTotal\n")
        rows = []
        for url, v in r["threat_intel"]["urls"].items():
            rows.append(["URL", _defang(url), v.get("status"), v.get("malicious", "—"), v.get("permalink", "")])
        for sha, v in r["threat_intel"]["files"].items():
            rows.append(["File", sha[:16] + "…", v.get("status"), v.get("malicious", "—"), v.get("permalink", "")])
        L.append(_table(["Kind", "Indicator", "Status", "Malicious engines", "Link"], rows))
    L.append("## 10. Indicators of compromise (defanged)\n")
    L.append(_table(["Type", "Value"], [[x["type"], x["defanged"]] for x in r["iocs"]]))
    L.append("## Appendix A — Received chain (origin → mailbox)\n")
    L.append(_table(["#", "From", "By", "IP", "Timestamp", "Δ s"],
                    [[h["index"], h["from_host"], h["by_host"], h["ip"] or "—", h["timestamp"], h["delay_s"] if h["delay_s"] is not None else "—"]
                     for h in r["received_chain"]]))
    return "\n".join(L)


def _defang(url: str) -> str:
    from .urls import defang
    return defang(url)


def render_json(r: Dict) -> str:
    return json.dumps(r, indent=2, ensure_ascii=False)


def render_iocs_csv(r: Dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "defanged", "context", "case_id", "verdict"])
    for x in r["iocs"]:
        w.writerow([x["type"], x["value"], x["defanged"], x.get("context", ""), r["case_id"], r["verdict"]])
    return buf.getvalue()
