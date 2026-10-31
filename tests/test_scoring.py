from conftest import SAMPLES
from phishscope.engine import analyze
from phishscope.scoring import levenshtein, lookalike_of


def test_lookalike():
    assert lookalike_of("rnicrosoft-support.example") == "microsoft"
    assert lookalike_of("paypa1.com") == "paypal"
    assert lookalike_of("microsoft.com") == ""
    assert lookalike_of("ameliorate.com") == ""


def test_levenshtein():
    assert levenshtein("kitten", "sitting") == 3


def test_phish_is_malicious_and_explained():
    r = analyze(str(SAMPLES / "phish_01.eml"), corpus=str(SAMPLES / "mailstore"), dns=False)
    ids = {f["id"] for f in r["findings"]}
    assert r["verdict"] == "MALICIOUS" and r["confidence"] == "HIGH"
    assert {"AUTH_DMARC_FAIL", "SPF_PASS_NOT_ALIGNED", "REPLY_TO_MISMATCH",
            "URL_ANCHOR_MISMATCH", "URL_IP_HOST", "ATT_RISKY_EXT"} <= ids


def test_benign_scores_zero():
    r = analyze(str(SAMPLES / "mailstore" / "benign_01.eml"), dns=False)
    assert r["verdict"] == "LIKELY BENIGN" and r["risk_score"] == 0


def test_blast_radius_finds_campaign_not_noise():
    r = analyze(str(SAMPLES / "phish_01.eml"), corpus=str(SAMPLES / "mailstore"), dns=False)
    b = r["blast_radius"]
    assert len(b["matched"]) == 2  # phish_02 + phish_03, never the benign mail
    assert set(b["unique_recipients"]) == {
        "alice@corp-victim.example", "bob@corp-victim.example",
        "carol@corp-victim.example", "dave@corp-victim.example"}
    assert b["scope"] == "limited"
