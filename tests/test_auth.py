from conftest import SAMPLES
from phishscope.auth import alignment, org_domain, parse_authentication
from phishscope.parser import identity, load_eml


def test_org_domain():
    assert org_domain("mail.news.example.com") == "example.com"
    assert org_domain("foo.bar.co.uk") == "bar.co.uk"
    assert org_domain("impots.gouv.fr") == "impots.gouv.fr"


def test_spf_pass_but_not_aligned():
    msg = load_eml(SAMPLES / "phish_01.eml")
    auth = parse_authentication(msg)
    assert auth["results"] == {"spf": "pass", "dkim": "none", "dmarc": "fail"}
    assert alignment(identity(msg), auth)["spf_aligned"] is False


def test_benign_is_aligned():
    msg = load_eml(SAMPLES / "mailstore" / "benign_01.eml")
    auth = parse_authentication(msg)
    al = alignment(identity(msg), auth)
    assert al == {"spf_aligned": True, "dkim_aligned": True}
