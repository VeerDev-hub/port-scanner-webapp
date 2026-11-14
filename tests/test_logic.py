"""Unit tests for parsing, signatures, vuln matching, authorization, reporting."""

import pytest

from scanner import authorization, reporting
from scanner.evasion import Evasion, expand_decoys
from scanner.models import (HostResult, PortResult, PortState, ScanResult, Service, Vulnerability)
from scanner.service import signatures
from scanner.vulns import match as vuln_match
from scanner.discovery import expand_targets
import cli


# ---- port parsing ----------------------------------------------------------
def test_parse_ports_list_and_range():
    ports, q = cli.parse_ports("22,80,1000-1002")
    assert ports == [22, 80, 1000, 1001, 1002]
    assert q == "22,80,1000-1002"


def test_parse_ports_all():
    ports, q = cli.parse_ports("-")
    assert ports[0] == 1 and ports[-1] == 65535 and len(ports) == 65535


@pytest.mark.parametrize("bad", ["", "0", "70000", "5-3", "abc"])
def test_parse_ports_rejects_bad(bad):
    with pytest.raises(ValueError):
        cli.parse_ports(bad)


# ---- target expansion ------------------------------------------------------
def test_expand_targets_cidr():
    hosts = expand_targets("192.168.0.0/30")
    assert hosts == ["192.168.0.1", "192.168.0.2"]


def test_expand_targets_range():
    hosts = expand_targets("10.0.0.5-8")
    assert hosts == ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"]


def test_expand_targets_single_ip():
    assert expand_targets("127.0.0.1") == ["127.0.0.1"]


# ---- signatures ------------------------------------------------------------
@pytest.mark.parametrize("banner,svc,prod,ver", [
    ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n", "ssh", "OpenSSH", "8.9p1"),
    ("HTTP/1.1 200 OK\r\nServer: nginx/1.17.6\r\n\r\n", "http", "nginx", "1.17.6"),
    ("220 (vsFTPd 2.3.4)\r\n", "ftp", "vsFTPd", "2.3.4"),
])
def test_signature_match(banner, svc, prod, ver):
    s, p, v = signatures.match(banner)
    assert (s, p, v) == (svc, prod, ver)


def test_signature_no_match():
    assert signatures.match("totally unknown banner") == ("", "", "")


# ---- vuln matching ---------------------------------------------------------
def test_vuln_exact_version():
    hits = vuln_match.lookup("vsftpd", "2.3.4")
    assert any(h.cve == "CVE-2011-2523" for h in hits)


def test_vuln_range_and_lt():
    assert any(h.cve == "CVE-2024-6387" for h in vuln_match.lookup("OpenSSH", "9.1"))
    assert not vuln_match.lookup("OpenSSH", "9.9")  # above the fixed version
    assert vuln_match.lookup("nginx", "1.10.0")     # < 1.21.0 => matched


def test_vuln_unknown_product():
    assert vuln_match.lookup("nothinghere", "1.0") == []


# ---- authorization ---------------------------------------------------------
def test_authorization_allows_private():
    authorization.check("192.168.1.10")      # no raise
    authorization.check("10.0.0.1")
    authorization.check("127.0.0.1")


def test_authorization_blocks_public():
    with pytest.raises(authorization.AuthorizationError):
        authorization.check("8.8.8.8")


def test_authorization_override():
    authorization.check("8.8.8.8", authorized=True)   # explicit override, no raise


def test_authorization_added_cidr(tmp_path):
    authorization.add_allowed("203.0.113.0/24")
    authorization.check("203.0.113.5")


# ---- evasion ---------------------------------------------------------------
def test_expand_decoys_includes_real_source_and_me():
    decoys = expand_decoys("1.2.3.4,ME,RND:2", "10.0.0.9")
    assert "10.0.0.9" in decoys     # real source always present
    assert "1.2.3.4" in decoys
    assert len(decoys) >= 4         # 1 explicit + ME + 2 random (+ ensured real)


def test_evasion_summary_labels():
    ev = Evasion(frag_mtu=8, decoys=["1.1.1.1"], source_port=53)
    notes = ev.summary()
    assert any("fragment" in n.lower() for n in notes)
    assert ev.active


# ---- reporting (escaping) --------------------------------------------------
def _sample_result():
    svc = Service(name="http", product="nginx", version="1.17.6",
                  banner="<script>alert(1)</script>",
                  vulns=[Vulnerability("CVE-2021-23017", "high", 7.7, "off-by-one")])
    port = PortResult(host="10.0.0.1", port=80, state=PortState.OPEN, reason="syn-ack", service=svc)
    host = HostResult(host="10.0.0.1", hostname="lab", ports=[port])
    return ScanResult("10.0.0.1", "syn", "80", 0.0, 1.0, hosts=[host])


def test_report_html_escapes_banner():
    html_out = reporting.render(_sample_result(), "html")
    assert "<script>alert(1)</script>" not in html_out
    assert "CVE-2021-23017" in html_out


def test_report_json_and_csv_and_xml():
    r = _sample_result()
    assert '"CVE-2021-23017"' in reporting.render(r, "json")
    assert "CVE-2021-23017" in reporting.render(r, "csv")
    xml = reporting.render(r, "xml")
    assert "<reconrun" in xml and "CVE-2021-23017" in xml
