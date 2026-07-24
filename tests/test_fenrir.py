import pytest
import os
import tempfile
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


def test_collector_fallback_offline():
    collector = ThreatIntelCollector()
    results = collector.fetch_cisa_kev()
    assert len(results) >= 2
    assert results[0]["indicator_type"] == "CVE"


def test_collector_aggregate():
    collector = ThreatIntelCollector()
    results = collector.aggregate_feeds()
    assert len(results) >= 2
    for r in results:
        assert "indicator_type" in r
        assert "indicator" in r
        assert "severity" in r
