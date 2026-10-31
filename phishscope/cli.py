"""Command line interface.

    phishscope analyze suspicious.eml --corpus ./mailstore --out report.md
    phishscope headers suspicious.eml
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .engine import analyze
from .parser import load_eml, received_chain
from .report import render_iocs_csv, render_json, render_markdown
from .virustotal import VirusTotal

COLORS = {"MALICIOUS": "\033[91m", "SUSPICIOUS": "\033[93m", "LIKELY BENIGN": "\033[92m"}


def _cmd_analyze(args) -> int:
    key = args.vt_key or os.environ.get("VT_API_KEY")
    vt = VirusTotal(key, cache_dir=args.cache) if key and not args.no_vt else None
    if not vt and not args.no_vt:
        print("[i] No VirusTotal key (use --vt-key or $VT_API_KEY): running offline, intel step skipped.", file=sys.stderr)
    result = analyze(args.eml, corpus=args.corpus, vt=vt, dns=not args.no_dns, vt_max=args.vt_max)
    md = render_markdown(result)
    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(render_json(result), encoding="utf-8")
    if args.iocs:
        Path(args.iocs).write_text(render_iocs_csv(result), encoding="utf-8")
    color = COLORS.get(result["verdict"], "")
    reset = "\033[0m" if sys.stdout.isatty() and color else ""
    color = color if sys.stdout.isatty() else ""
    print(f"{color}[{result['verdict']}]{reset} case={result['case_id']} score={result['risk_score']}/100 "
          f"confidence={result['confidence']} recipients={len(result['blast_radius']['unique_recipients'])}")
    if not args.out:
        print()
        print(md)
    return 2 if result["verdict"] == "MALICIOUS" else 0  # non-zero exit = SOAR-friendly


def _cmd_headers(args) -> int:
    for h in received_chain(load_eml(args.eml)):
        delay = f"+{h.delay_s}s" if h.delay_s is not None else "—"
        print(f"{h.index:>2}  {h.timestamp or '—':<26} {delay:>7}  {h.from_host or '?'} [{h.ip or '—'}] -> {h.by_host or '?'}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="phishscope", description="Phishing email investigation toolkit for SOC analysts.")
    p.add_argument("--version", action="version", version=f"phishscope {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="full investigation of one .eml")
    a.add_argument("eml", help="path to the suspicious message (.eml)")
    a.add_argument("--corpus", help="folder of .eml/.mbox files to compute the blast radius")
    a.add_argument("--vt-key", help="VirusTotal API key (default: $VT_API_KEY)")
    a.add_argument("--vt-max", type=int, default=6, help="max URLs sent to VirusTotal (free tier = 4 req/min)")
    a.add_argument("--no-vt", action="store_true", help="never contact VirusTotal")
    a.add_argument("--no-dns", action="store_true", help="skip live SPF/DMARC DNS lookups")
    a.add_argument("--cache", default=".vt_cache", help="VirusTotal cache directory")
    a.add_argument("--out", help="write the Markdown report here")
    a.add_argument("--json", help="write the full result as JSON here")
    a.add_argument("--iocs", help="write IOCs as CSV here")
    a.set_defaults(func=_cmd_analyze)

    h = sub.add_parser("headers", help="print the Received chain with hop delays")
    h.add_argument("eml")
    h.set_defaults(func=_cmd_headers)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:  # e.g. `phishscope analyze x.eml | head`
        return 0
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
