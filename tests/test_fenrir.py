import pytest
import os
import tempfile
import urllib.error
from unittest.mock import patch, MagicMock
from storage.database import FenrirDatabase
from core.collector import ThreatIntelCollector


def _make_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return FenrirDatabase(db_path=path), path


def test_database_init_and_save():
    db, path = _make_db()
    iocs = [
        {"indicator_type": "CVE", "indicator": "CVE-2024-1234", "name": "Test Vuln", "source": "CISA KEV", "severity": "HIGH", "date_added": "2024-01-01"},
        {"indicator_type": "IP", "indicator": "10.0.0.1", "name": "C2 Server", "source": "OTX", "severity": "CRITICAL", "date_added": "2024-01-02"}
    ]
    count = db.save_iocs(iocs)
    assert count == 2
    os.remove(path)


def test_database_dedup():
    db, path = _make_db()
    iocs = [{"indicator_type": "CVE", "indicator": "CVE-2024-1234", "name": "Test", "source": "CISA", "severity": "HIGH", "date_added": "2024-01-01"}]
    db.save_iocs(iocs)
    count = db.save_iocs(iocs)
    assert count == 0
    stats = db.get_stats()
    assert stats["total_iocs"] == 1
    os.remove(path)


def test_database_search():
    db, path = _make_db()
    iocs = [
        {"indicator_type": "CVE", "indicator": "CVE-2024-5678", "name": "WinRAR Bug", "source": "CISA", "severity": "HIGH", "date_added": "2024-01-01"},
        {"indicator_type": "IP", "indicator": "192.168.1.100", "name": "Malware C2", "source": "OTX", "severity": "CRITICAL", "date_added": "2024-01-02"}
    ]
    db.save_iocs(iocs)
    results = db.search_ioc("WinRAR")
    assert len(results) == 1
    assert results[0]["indicator"] == "CVE-2024-5678"
    os.remove(path)


def test_database_search_by_type():
    db, path = _make_db()
    iocs = [
        {"indicator_type": "CVE", "indicator": "CVE-2024-1111", "name": "Test1", "source": "CISA", "severity": "HIGH", "date_added": "2024-01-01"},
        {"indicator_type": "IP", "indicator": "10.0.0.50", "name": "Test2", "source": "OTX", "severity": "HIGH", "date_added": "2024-01-02"}
    ]
    db.save_iocs(iocs)
    results = db.search_ioc("CVE-2024")
    assert len(results) >= 1
    os.remove(path)


def test_database_stats():
    db, path = _make_db()
    assert db.get_stats()["total_iocs"] == 0
    db.save_iocs([{"indicator_type": "CVE", "indicator": "CVE-2024-0001", "name": "A", "source": "S", "severity": "HIGH", "date_added": "2024-01-01"}])
    assert db.get_stats()["total_iocs"] == 1
    os.remove(path)


def test_database_empty_search():
    db, path = _make_db()
    results = db.search_ioc("NONEXISTENT")
    assert len(results) == 0
    os.remove(path)


def test_fetch_cisa_kev_parses_a_real_response():
    fake_payload = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-1234", "vulnerabilityName": "Test Vuln", "dateAdded": "2024-01-01"}
        ]
    }
    fake_response = MagicMock()
    fake_response.read.return_value = __import__("json").dumps(fake_payload).encode()
    fake_response.__enter__.return_value = fake_response

    collector = ThreatIntelCollector()
    with patch("core.collector.urllib.request.urlopen", return_value=fake_response):
        results = collector.fetch_cisa_kev()

    assert results == [{
        "indicator_type": "CVE",
        "indicator": "CVE-2024-1234",
        "name": "Test Vuln",
        "source": "CISA KEV",
        "severity": "HIGH",
        "date_added": "2024-01-01",
    }]


def test_fetch_cisa_kev_propagates_the_error_instead_of_inventing_data():
    """Trovato in revisione: in caso di errore, il metodo restituiva IOC
    finti (CVE-2023-38831, un IP marcato "AlienVault OTX") indistinguibili
    da dati reali -- stessa forma, stesso "source" -- che finivano salvati
    nel database delle minacce come se fossero autentici."""
    collector = ThreatIntelCollector()
    with patch("core.collector.urllib.request.urlopen", side_effect=urllib.error.URLError("offline")):
        with pytest.raises(urllib.error.URLError):
            collector.fetch_cisa_kev()


def test_aggregate_feeds_returns_empty_when_the_feed_is_unreachable_not_fake_data():
    collector = ThreatIntelCollector()
    with patch("core.collector.urllib.request.urlopen", side_effect=urllib.error.URLError("offline")):
        results = collector.aggregate_feeds()
    assert results == []


def test_aggregate_feeds_one_failing_feed_does_not_discard_another_feeds_iocs():
    """aggregate_feeds isola i fallimenti per fonte: se in futuro si
    aggiunge un secondo feed, uno irraggiungibile non deve azzerare gli IOC
    gia' raccolti dagli altri."""
    collector = ThreatIntelCollector()
    good_iocs = [{"indicator_type": "CVE", "indicator": "CVE-2024-9999", "name": "X", "source": "CISA KEV", "severity": "HIGH", "date_added": "2024-01-01"}]
    with patch.object(collector, "fetch_cisa_kev", return_value=good_iocs):
        results = collector.aggregate_feeds()
    assert results == good_iocs
