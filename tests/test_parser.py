from conftest import SAMPLES
from phishscope.parser import (attachments, bodies, identity, load_eml,
                               origin_ip, received_chain)


def test_identity_exposes_spoof():
    ident = identity(load_eml(SAMPLES / "phish_01.eml"))
    assert ident["from_domain"] == "microsoft.com"
    assert ident["return_path_domain"] == "mail-relay-77.bulkmailer.example"
    assert ident["reply_to_domain"] == "rnicrosoft-support.example"


def test_received_chain_is_origin_first_with_delays():
    hops = received_chain(load_eml(SAMPLES / "phish_01.eml"))
    assert len(hops) == 3
    assert hops[0].ip == "203.0.113.45"
    assert hops[1].delay_s == 11
    assert origin_ip(hops) == "203.0.113.45"


def test_attachment_hashed_not_executed():
    atts = attachments(load_eml(SAMPLES / "phish_01.eml"))
    assert atts[0]["filename"] == "Secure_Document.html"
    assert len(atts[0]["sha256"]) == 64


def test_bodies_extracted():
    text, html = bodies(load_eml(SAMPLES / "phish_01.eml"))
    assert "expires within 24 hours" in text
    assert "<a href" in html
