# Methodology — how PhishScope thinks like a SOC analyst

PhishScope encodes the five-step phishing triage playbook. Each step produces
evidence that the next step uses, and the final report must *name a verdict*
and *quantify the blast radius* — the two things a SOC manager actually needs.

| # | Analyst question | Module | Output |
|---|------------------|--------|--------|
| 1 | Is the sender who they claim to be? | `parser.py` | Identity table (From / Return-Path / Reply-To / Message-ID), Received chain, origin IP |
| 2 | Did the mail authenticate **and align**? | `auth.py` | SPF / DKIM / DMARC verdicts + alignment + published policy |
| 3 | Where do the links and files lead? | `urls.py`, `virustotal.py` | Flagged links, defanged IOCs, VirusTotal reputation |
| 4 | Who else received it? | `blast.py` | Campaign matches, unique recipients, scope |
| 5 | What do we tell the manager? | `scoring.py`, `report.py` | Verdict, confidence, actions, Markdown / JSON / CSV |

## Step 1 — Read the full headers, prove the spoof

An email carries *two* sender identities:

* **Header From** — what the user sees. Fully attacker-controlled.
* **Envelope sender (Return-Path / MAIL FROM)** — where bounces go, and the
  identity SPF actually validates.

Whenever these belong to different organisations, someone is either spoofing
or sending on behalf of a legitimate third party (mailing platforms). Context
decides; PhishScope flags it and lets the other evidence break the tie.

**Trust boundary of `Received` headers.** Headers are *prepended* by each hop,
so the bottom ones were written by the sender and can be forged. Only the hops
added by your own infrastructure are trustworthy. PhishScope reorders the
chain origin → mailbox, computes inter-hop delays, and picks the first public
IP as the *best guess* origin. Negative delays (time going backwards) are a
forgery / misconfiguration signal.

## Step 2 — SPF, DKIM, DMARC (and why *pass* ≠ *safe*)

* **SPF** validates the envelope sender against the sending IP.
* **DKIM** validates a cryptographic signature by the domain in `d=`.
* **DMARC** requires that SPF *or* DKIM passes **and is aligned** with the
  visible From domain, then applies the owner's policy (`none` / `quarantine` /
  `reject`).

The classic trap: an attacker registers `evil.tld`, publishes a valid SPF
record, sends mail with `From: ceo@yourcompany.com`. SPF = **pass** (for
`evil.tld`), DMARC = **fail**. PhishScope surfaces this as
`SPF_PASS_NOT_ALIGNED` so a junior analyst is never fooled by a green "pass".

Only the **topmost** `Authentication-Results` header (added by your own
gateway) is parsed; lower ones may have been injected by the attacker.

## Step 3 — Run every link through threat intel

* URLs are extracted from both `<a href>` and raw text; anchor text is compared
  with the real destination (`anchor_mismatch`).
* Static red flags: raw IP host, punycode (IDN homograph), shorteners,
  `user@host` tricks, abused TLDs, no TLS, brand look-alikes (`rn`→`m`,
  `0`→`o`, `1`→`l`, token + Levenshtein matching).
* Optional: VirusTotal v3 lookup for URLs and attachment SHA-256. The tool only
  *looks up* reputation; it never fetches or detonates anything. Responses are
  cached for 24 h and throttled to respect the public API quota.
* All IOCs are **defanged** (`hxxps://evil[.]tld`) so they are safe to paste in
  tickets and chat.

## Step 4 — Trace who else received it

Phishing is a campaign. A single message is an alert; thirty messages is an
incident. `blast.py` correlates the sample against a corpus of `.eml`/`.mbox`
files on six indicators — sender, Return-Path domain, normalised subject, URL
registrable domains, attachment hashes, origin IP — and requires **at least
two** shared indicators to count as the same campaign (one alone is usually a
mailing list). Scope is labelled `contained` (≤1 recipient), `limited` (≤10),
`widespread` (>10).

In production the same logic runs inside your mail security stack — see
[`HUNTING_QUERIES.md`](HUNTING_QUERIES.md).

## Step 5 — One-page report: verdict + blast radius

Page one of the report answers, in order: **verdict & confidence → blast
radius → actions**. Everything below the fold is evidence for the sceptical
reviewer. Every point of the risk score traces back to a named finding with a
weight and, where relevant, a MITRE ATT&CK technique.

### Confidence

* `HIGH` — three or more independent evidence categories agree (auth, identity,
  url, attachment, content, intel) or threat intel confirmed the IOC.
* `MEDIUM` — two categories.
* `LOW` — a single category carries the score (e.g. only the content looks
  pushy). Analyst review required.

## Known limitations

* Heuristics, not ML: precise and explainable, but a clever attacker with a
  clean domain, valid DKIM and no links can evade it. Humans stay in the loop.
* `org_domain()` uses a small suffix list; install `tldextract` for exact
  registrable-domain logic (auto-detected).
* The corpus scan is a stand-in for a real mail-store query.
* No click telemetry: whether a user *clicked* must come from proxy / EDR /
  Safe Links logs (see hunting queries).
