"""Tests for main.py's CLI wiring and lock file mechanism - previously
0% covered by any test (only core.collector/storage.database were tested
directly)."""
import os
import time
import tempfile
import pytest

import main


@pytest.fixture
def isolated_lock(tmp_path, monkeypatch):
    lock_path = str(tmp_path / "fenrir.lock")
    monkeypatch.setattr(main, "LOCK_FILE", lock_path)
    return lock_path


def test_acquire_lock_succeeds_when_no_lock_exists(isolated_lock):
    assert main._acquire_lock() is True
    assert os.path.exists(isolated_lock)


def test_acquire_lock_fails_when_lock_already_held(isolated_lock):
    assert main._acquire_lock() is True
    assert main._acquire_lock() is False


def test_acquire_lock_removes_stale_lock_and_succeeds(isolated_lock, monkeypatch):
    with open(isolated_lock, "w", encoding="utf-8") as f:
        f.write("pid=1\ntime=0\n")
    old_time = time.time() - main.LOCK_MAX_AGE_SECONDS - 60
    os.utime(isolated_lock, (old_time, old_time))

    assert main._acquire_lock() is True


def test_run_update_skips_when_lock_held(isolated_lock, capsys):
    with open(isolated_lock, "w", encoding="utf-8") as f:
        f.write("pid=1\n")
    main.run_update()
    out = capsys.readouterr().out
    assert "salto questa esecuzione" in out


def test_run_update_success_without_otx_key(isolated_lock, monkeypatch, capsys, tmp_path):
    monkeypatch.delenv("OTX_API_KEY", raising=False)

    class FakeCollector:
        def fetch_cisa_kev(self):
            return [{"indicator": "1.2.3.4", "indicator_type": "ipv4addr"}]

    class FakeDB:
        def __init__(self, path):
            pass

        def save_iocs(self, iocs):
            return len(iocs)

        def get_stats(self):
            return {"total_iocs": 1}

    monkeypatch.setattr(main, "ThreatIntelCollector", FakeCollector)
    monkeypatch.setattr(main, "FenrirDatabase", FakeDB)

    main.run_update()
    out = capsys.readouterr().out
    assert "OTX_API_KEY non impostata" in out
    assert "Added 1 new unique IOCs" in out
    assert not os.path.exists(main.LOCK_FILE), "lock must be released even on success"


def test_run_update_releases_lock_even_when_feed_fetch_raises(isolated_lock, monkeypatch, capsys):
    class FailingCollector:
        def fetch_cisa_kev(self):
            raise ConnectionError("feed down")

    class FakeDB:
        def __init__(self, path):
            pass

        def save_iocs(self, iocs):
            return 0

        def get_stats(self):
            return {"total_iocs": 0}

    monkeypatch.delenv("OTX_API_KEY", raising=False)
    monkeypatch.setattr(main, "ThreatIntelCollector", FailingCollector)
    monkeypatch.setattr(main, "FenrirDatabase", FakeDB)

    main.run_update()
    out = capsys.readouterr().out
    assert "Feed CISA KEV non raggiungibile" in out
    assert not os.path.exists(main.LOCK_FILE)


def test_run_search_prints_results(monkeypatch, capsys):
    class FakeDB:
        def __init__(self, path):
            pass

        def search_ioc(self, query):
            return [{"indicator_type": "ipv4addr", "indicator": "1.2.3.4", "severity": "CRITICAL", "source": "CISA", "name": "Test IOC"}]

    monkeypatch.setattr(main, "FenrirDatabase", FakeDB)
    main.run_search("1.2.3.4")
    out = capsys.readouterr().out
    assert "Found 1 matching" in out
    assert "1.2.3.4" in out


def test_run_search_no_results(monkeypatch, capsys):
    class FakeDB:
        def __init__(self, path):
            pass

        def search_ioc(self, query):
            return []

    monkeypatch.setattr(main, "FenrirDatabase", FakeDB)
    main.run_search("nonexistent")
    out = capsys.readouterr().out
    assert "No matching IOCs found" in out


def test_main_dispatches_update_subcommand(monkeypatch):
    called = {}
    monkeypatch.setattr(main, "run_update", lambda: called.setdefault("update", True))
    monkeypatch.setattr("sys.argv", ["main.py", "update"])
    main.main()
    assert called.get("update") is True


def test_main_dispatches_search_subcommand(monkeypatch):
    called = {}
    monkeypatch.setattr(main, "run_search", lambda query: called.setdefault("query", query))
    monkeypatch.setattr("sys.argv", ["main.py", "search", "CVE-2024-1234"])
    main.main()
    assert called["query"] == "CVE-2024-1234"


def test_main_defaults_to_update_then_search_cve(monkeypatch):
    called = []
    monkeypatch.setattr(main, "run_update", lambda: called.append("update"))
    monkeypatch.setattr(main, "run_search", lambda query: called.append(("search", query)))
    monkeypatch.setattr("sys.argv", ["main.py"])
    main.main()
    assert called == ["update", ("search", "CVE")]
