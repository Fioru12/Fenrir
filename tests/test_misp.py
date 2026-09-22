import io
import json
import os
import sys
import urllib.error

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.collector import ThreatIntelCollector


def _fake_response(payload: dict):
    data = json.dumps(payload).encode()

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return data

    return FakeResp()


MISP_PAYLOAD = {
    "response": {
        "Attribute": [
            {"value": "1.2.3.4", "type": "ip-dst", "to_ids": True,
             "comment": "C2 server", "timestamp": "1700000000",
             "Event": {"info": "Takeover"}},
            {"value": "evil.example", "type": "domain", "to_ids": False,
             "comment": "", "date": "2024-01-01",
             "Event": {"info": "Phishing"}},
            {"value": "", "type": ""},
        ]
    }
}


def test_fetch_misp_normalizes(monkeypatch):
    import core.collector as coll

    def fake_urlopen(req, timeout=15):
        assert req.full_url == "https://misp.local/attributes/restSearch/json"
        assert req.get_header("Authorization") == "KEY"
        return _fake_response(MISP_PAYLOAD)

    monkeypatch.setattr(coll.urllib.request, "urlopen", fake_urlopen)
    res = ThreatIntelCollector().fetch_misp_attributes("https://misp.local", "KEY")
    assert len(res) == 2
    assert res[0] == {
        "indicator_type": "ip-dst", "indicator": "1.2.3.4", "name": "C2 server",
        "source": "MISP", "severity": "HIGH", "date_added": "1700000000",
    }
    assert res[1]["severity"] == "MEDIUM"
    assert res[1]["name"] == "Phishing"


def test_fetch_misp_requires_both():
    import pytest
    c = ThreatIntelCollector()
    with pytest.raises(ValueError):
        c.fetch_misp_attributes("", "KEY")
    with pytest.raises(ValueError):
        c.fetch_misp_attributes("https://misp.local", "")


def test_fetch_misp_auth_rejected(monkeypatch):
    import core.collector as coll

    def fake_urlopen(req, timeout=15):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, io.BytesIO(b""))

    monkeypatch.setattr(coll.urllib.request, "urlopen", fake_urlopen)
    import pytest
    with pytest.raises(ValueError, match="rifiutata"):
        ThreatIntelCollector().fetch_misp_attributes("https://misp.local", "BAD")


def test_aggregate_feeds_includes_misp(monkeypatch):
    c = ThreatIntelCollector()
    monkeypatch.setattr(c, "fetch_cisa_kev", lambda: [{"indicator": "CVE-1"}])
    monkeypatch.setattr(c, "fetch_misp_attributes", lambda u, k: [{"indicator": "1.2.3.4"}])
    res = c.aggregate_feeds(misp_url="https://misp.local", misp_api_key="KEY")
    assert [r["indicator"] for r in res] == ["CVE-1", "1.2.3.4"]


def test_aggregate_feeds_misp_failure_isolated(monkeypatch):
    c = ThreatIntelCollector()
    monkeypatch.setattr(c, "fetch_cisa_kev", lambda: [{"indicator": "CVE-1"}])

    def boom(u, k):
        raise RuntimeError("down")

    monkeypatch.setattr(c, "fetch_misp_attributes", boom)
    assert c.aggregate_feeds(misp_url="https://misp.local", misp_api_key="KEY") == [{"indicator": "CVE-1"}]
