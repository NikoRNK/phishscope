from phishscope.urls import defang, extract_links


def test_anchor_mismatch_detected():
    html = '<a href="http://evil.example/x">https://login.microsoftonline.com</a>'
    link = extract_links("", html)[0]
    assert "anchor_mismatch" in link.flags and "no_tls" in link.flags


def test_ip_and_shortener_and_punycode():
    links = {l.host: l for l in extract_links("http://203.0.113.9/a https://bit.ly/x http://xn--pple-43d.example/", "")}
    assert "ip_host" in links["203.0.113.9"].flags
    assert "shortener" in links["bit.ly"].flags
    assert "punycode" in links["xn--pple-43d.example"].flags


def test_defang():
    assert defang("https://evil.example/a") == "hxxps://evil[.]example/a"
