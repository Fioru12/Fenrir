import pytest
import os
import socket
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


def test_fetch_cisa_kev_returns_all_entries_not_just_the_first_20():
    """Trovato in revisione: il metodo troncava il catalogo a vulns[:20],
    scartando il 98% delle voci reali (oltre 1300 nel catalogo CISA KEV)."""
    fake_payload = {
        "vulnerabilities": [
            {"cveID": f"CVE-2024-{i:04d}", "vulnerabilityName": f"Vuln {i}", "dateAdded": "2024-01-01"}
            for i in range(25)
        ]
    }
    fake_response = MagicMock()
    fake_response.read.return_value = __import__("json").dumps(fake_payload).encode()
    fake_response.__enter__.return_value = fake_response

    collector = ThreatIntelCollector()
    with patch("core.collector.urllib.request.urlopen", return_value=fake_response):
        results = collector.fetch_cisa_kev()

    assert len(results) == 25


def test_fetch_cisa_kev_saves_all_entries_to_db_not_just_the_first_20():
    fake_payload = {
        "vulnerabilities": [
            {"cveID": f"CVE-2024-{i:04d}", "vulnerabilityName": f"Vuln {i}", "dateAdded": "2024-01-01"}
            for i in range(25)
        ]
    }
    fake_response = MagicMock()
    fake_response.read.return_value = __import__("json").dumps(fake_payload).encode()
    fake_response.__enter__.return_value = fake_response

    collector = ThreatIntelCollector()
    with patch("core.collector.urllib.request.urlopen", return_value=fake_response):
        results = collector.fetch_cisa_kev()

    db, path = _make_db()
    count = db.save_iocs(results)
    assert count == 25
    assert db.get_stats()["total_iocs"] == 25
    os.remove(path)


def test_fetch_cisa_kev_respects_explicit_optional_limit():
    fake_payload = {
        "vulnerabilities": [
            {"cveID": f"CVE-2024-{i:04d}", "vulnerabilityName": f"Vuln {i}", "dateAdded": "2024-01-01"}
            for i in range(25)
        ]
    }
    fake_response = MagicMock()
    fake_response.read.return_value = __import__("json").dumps(fake_payload).encode()
    fake_response.__enter__.return_value = fake_response

    collector = ThreatIntelCollector()
    with patch("core.collector.urllib.request.urlopen", return_value=fake_response):
        results = collector.fetch_cisa_kev(limit=5)

    assert len(results) == 5


def test_fetch_cisa_kev_discards_entries_with_missing_cve_id(caplog):
    fake_payload = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-0001", "vulnerabilityName": "Good Vuln", "dateAdded": "2024-01-01"},
            {"cveID": None, "vulnerabilityName": "Missing CVE ID", "dateAdded": "2024-01-02"},
            {"vulnerabilityName": "Missing CVE ID Key Entirely", "dateAdded": "2024-01-03"},
        ]
    }
    fake_response = MagicMock()
    fake_response.read.return_value = __import__("json").dumps(fake_payload).encode()
    fake_response.__enter__.return_value = fake_response

    collector = ThreatIntelCollector()
    with caplog.at_level("WARNING"):
        with patch("core.collector.urllib.request.urlopen", return_value=fake_response):
            results = collector.fetch_cisa_kev()

    assert len(results) == 1
    assert results[0]["indicator"] == "CVE-2024-0001"
    assert any("scartata" in r.message for r in caplog.records)


def test_fetch_cisa_kev_discarded_entries_never_reach_the_database():
    fake_payload = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-0001", "vulnerabilityName": "Good Vuln", "dateAdded": "2024-01-01"},
            {"cveID": None, "vulnerabilityName": "Missing CVE ID", "dateAdded": "2024-01-02"},
        ]
    }
    fake_response = MagicMock()
    fake_response.read.return_value = __import__("json").dumps(fake_payload).encode()
    fake_response.__enter__.return_value = fake_response

    collector = ThreatIntelCollector()
    with patch("core.collector.urllib.request.urlopen", return_value=fake_response):
        results = collector.fetch_cisa_kev()

    db, path = _make_db()
    db.save_iocs(results)
    assert db.get_stats()["total_iocs"] == 1
    results_search = db.search_ioc("CVE")
    assert all(r["indicator"] is not None for r in results_search)
    os.remove(path)


def test_fetch_otx_pulses_normalizes_indicators_with_source_otx():
    fake_payload = {
        "results": [
            {
                "name": "Pulse 1",
                "modified": "2024-02-01T00:00:00",
                "indicators": [
                    {"indicator": "1.2.3.4", "type": "IPv4", "description": "C2 server", "created": "2024-02-01T00:00:00"},
                    {"indicator": "evil.example.com", "type": "domain", "description": "Phishing domain", "created": "2024-02-02T00:00:00"},
                ],
            }
        ]
    }
    fake_response = MagicMock()
    fake_response.read.return_value = __import__("json").dumps(fake_payload).encode()
    fake_response.__enter__.return_value = fake_response

    collector = ThreatIntelCollector()
    with patch("core.collector.urllib.request.urlopen", return_value=fake_response) as mock_urlopen:
        results = collector.fetch_otx_pulses(api_key="fake-key")

    assert results == [
        {
            "indicator_type": "IPv4",
            "indicator": "1.2.3.4",
            "name": "C2 server",
            "source": "OTX",
            "severity": "MEDIUM",
            "date_added": "2024-02-01T00:00:00",
        },
        {
            "indicator_type": "domain",
            "indicator": "evil.example.com",
            "name": "Phishing domain",
            "source": "OTX",
            "severity": "MEDIUM",
            "date_added": "2024-02-02T00:00:00",
        },
    ]
    # Verifica che la chiave venga inviata nell'header corretto
    called_req = mock_urlopen.call_args[0][0]
    assert called_req.get_header("X-otx-api-key") == "fake-key"


def test_fetch_otx_pulses_discards_indicators_with_missing_fields(caplog):
    fake_payload = {
        "results": [
            {
                "name": "Pulse 1",
                "indicators": [
                    {"indicator": "1.2.3.4", "type": "IPv4", "description": "Good"},
                    {"indicator": None, "type": "IPv4", "description": "Missing indicator"},
                    {"type": "IPv4", "description": "Missing indicator key entirely"},
                    {"indicator": "5.6.7.8", "type": None, "description": "Missing type"},
                ],
            }
        ]
    }
    fake_response = MagicMock()
    fake_response.read.return_value = __import__("json").dumps(fake_payload).encode()
    fake_response.__enter__.return_value = fake_response

    collector = ThreatIntelCollector()
    with caplog.at_level("WARNING"):
        with patch("core.collector.urllib.request.urlopen", return_value=fake_response):
            results = collector.fetch_otx_pulses(api_key="fake-key")

    assert len(results) == 1
    assert results[0]["indicator"] == "1.2.3.4"
    assert any("scartato" in r.message for r in caplog.records)


def test_fetch_otx_pulses_empty_api_key_raises_value_error():
    collector = ThreatIntelCollector()
    with pytest.raises(ValueError):
        collector.fetch_otx_pulses(api_key="")


def test_fetch_otx_pulses_none_api_key_raises_value_error():
    collector = ThreatIntelCollector()
    with pytest.raises(ValueError):
        collector.fetch_otx_pulses(api_key=None)


def test_fetch_otx_pulses_401_raises_clear_error_not_silent_crash():
    collector = ThreatIntelCollector()
    http_error = urllib.error.HTTPError(
        url="https://otx.alienvault.com/api/v1/pulses/subscribed",
        code=401,
        msg="Unauthorized",
        hdrs=None,
        fp=None,
    )
    with patch("core.collector.urllib.request.urlopen", side_effect=http_error):
        with pytest.raises(ValueError, match="non valida"):
            collector.fetch_otx_pulses(api_key="invalid-key")


def test_fetch_otx_pulses_network_error_propagates_not_silenced():
    collector = ThreatIntelCollector()
    with patch("core.collector.urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
        with pytest.raises(urllib.error.URLError):
            collector.fetch_otx_pulses(api_key="fake-key")


def test_aggregate_feeds_skips_otx_when_no_api_key_provided():
    collector = ThreatIntelCollector()
    good_iocs = [{"indicator_type": "CVE", "indicator": "CVE-2024-9999", "name": "X", "source": "CISA KEV", "severity": "HIGH", "date_added": "2024-01-01"}]
    with patch.object(collector, "fetch_cisa_kev", return_value=good_iocs):
        with patch.object(collector, "fetch_otx_pulses") as mock_otx:
            results = collector.aggregate_feeds(otx_api_key=None)
    mock_otx.assert_not_called()
    assert results == good_iocs


def test_aggregate_feeds_includes_otx_when_api_key_provided():
    collector = ThreatIntelCollector()
    cisa_iocs = [{"indicator_type": "CVE", "indicator": "CVE-2024-9999", "name": "X", "source": "CISA KEV", "severity": "HIGH", "date_added": "2024-01-01"}]
    otx_iocs = [{"indicator_type": "IPv4", "indicator": "1.2.3.4", "name": "C2", "source": "OTX", "severity": "MEDIUM", "date_added": "2024-02-01"}]
    with patch.object(collector, "fetch_cisa_kev", return_value=cisa_iocs):
        with patch.object(collector, "fetch_otx_pulses", return_value=otx_iocs) as mock_otx:
            results = collector.aggregate_feeds(otx_api_key="fake-key")
    mock_otx.assert_called_once_with("fake-key")
    assert results == cisa_iocs + otx_iocs


def test_main_run_update_skips_otx_cleanly_when_env_var_not_set(monkeypatch, tmp_path, capsys):
    """La funzione di update di main.py non deve mai crashare per l'assenza
    di OTX_API_KEY: deve stampare un messaggio di skip chiaro e continuare
    normalmente con il solo CISA KEV."""
    import main as fenrir_main

    monkeypatch.delenv("OTX_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)

    cisa_iocs = [{"indicator_type": "CVE", "indicator": "CVE-2024-0001", "name": "X", "source": "CISA KEV", "severity": "HIGH", "date_added": "2024-01-01"}]
    with patch.object(fenrir_main.ThreatIntelCollector, "fetch_cisa_kev", return_value=cisa_iocs):
        with patch.object(fenrir_main.ThreatIntelCollector, "fetch_otx_pulses") as mock_otx:
            fenrir_main.run_update()

    mock_otx.assert_not_called()
    captured = capsys.readouterr()
    assert "OTX_API_KEY" in captured.out
    assert "[SKIP]" in captured.out or "SKIP" in captured.out


def test_aggregate_feeds_one_failing_feed_does_not_discard_another_feeds_iocs():
    """aggregate_feeds isola i fallimenti per fonte: se in futuro si
    aggiunge un secondo feed, uno irraggiungibile non deve azzerare gli IOC
    gia' raccolti dagli altri."""
    collector = ThreatIntelCollector()
    good_iocs = [{"indicator_type": "CVE", "indicator": "CVE-2024-9999", "name": "X", "source": "CISA KEV", "severity": "HIGH", "date_added": "2024-01-01"}]
    with patch.object(collector, "fetch_cisa_kev", return_value=good_iocs):
        results = collector.aggregate_feeds()
    assert results == good_iocs


# ---------------------------------------------------------------------------
# Deduplica case-insensitive degli indicatori
# ---------------------------------------------------------------------------

def test_database_dedup_is_case_insensitive():
    """CVE-2024-1234 e cve-2024-1234 devono essere trattati come lo stesso
    indicatore: il secondo salvataggio non deve creare una riga duplicata."""
    db, path = _make_db()
    db.save_iocs([{"indicator_type": "CVE", "indicator": "CVE-2024-1234", "name": "Test", "source": "CISA", "severity": "HIGH", "date_added": "2024-01-01"}])
    count = db.save_iocs([{"indicator_type": "CVE", "indicator": " cve-2024-1234 ", "name": "Test dup", "source": "CISA", "severity": "HIGH", "date_added": "2024-01-01"}])
    assert count == 0
    assert db.get_stats()["total_iocs"] == 1
    os.remove(path)


def test_database_search_is_case_insensitive():
    db, path = _make_db()
    db.save_iocs([{"indicator_type": "CVE", "indicator": "CVE-2024-1234", "name": "Test", "source": "CISA", "severity": "HIGH", "date_added": "2024-01-01"}])
    results = db.search_ioc("cve-2024-1234")
    assert len(results) == 1
    assert results[0]["indicator"] == "CVE-2024-1234"
    os.remove(path)


# ---------------------------------------------------------------------------
# Escape dei metacaratteri LIKE (% e _) nella ricerca
# ---------------------------------------------------------------------------

def test_database_search_escapes_underscore_wildcard():
    """Senza escape, '_' in LIKE fa match con qualsiasi carattere: una
    ricerca di 'TEST_1' non deve intercettare 'TESTX1'."""
    db, path = _make_db()
    db.save_iocs([
        {"indicator_type": "HASH", "indicator": "TEST_1", "name": "Literal underscore", "source": "S", "severity": "HIGH", "date_added": "2024-01-01"},
        {"indicator_type": "HASH", "indicator": "TESTX1", "name": "Unrelated", "source": "S", "severity": "HIGH", "date_added": "2024-01-01"},
    ])
    results = db.search_ioc("TEST_1")
    indicators = {r["indicator"] for r in results}
    assert indicators == {"TEST_1"}
    os.remove(path)


def test_database_search_escapes_percent_wildcard():
    db, path = _make_db()
    db.save_iocs([
        {"indicator_type": "HASH", "indicator": "AB%CD", "name": "Literal percent", "source": "S", "severity": "HIGH", "date_added": "2024-01-01"},
        {"indicator_type": "HASH", "indicator": "ABXXCD", "name": "Unrelated", "source": "S", "severity": "HIGH", "date_added": "2024-01-01"},
    ])
    results = db.search_ioc("AB%CD")
    indicators = {r["indicator"] for r in results}
    assert indicators == {"AB%CD"}
    os.remove(path)


# ---------------------------------------------------------------------------
# Lock file per prevenire update concorrenti
# ---------------------------------------------------------------------------

def test_run_update_skips_cleanly_when_lock_file_already_exists(monkeypatch, tmp_path, capsys):
    import main as fenrir_main

    monkeypatch.chdir(tmp_path)
    lock_path = tmp_path / fenrir_main.LOCK_FILE
    lock_path.write_text("")

    with patch.object(fenrir_main.ThreatIntelCollector, "fetch_cisa_kev") as mock_fetch:
        fenrir_main.run_update()

    mock_fetch.assert_not_called()
    captured = capsys.readouterr()
    assert "già in corso" in captured.out or "SKIP" in captured.out
    # Il lock preesistente non va toccato/rimosso da un run che non l'ha creato lui stesso.
    assert lock_path.exists()


def test_run_update_creates_and_removes_lock_file_on_success(monkeypatch, tmp_path):
    import main as fenrir_main

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    lock_path = tmp_path / fenrir_main.LOCK_FILE

    cisa_iocs = [{"indicator_type": "CVE", "indicator": "CVE-2024-0001", "name": "X", "source": "CISA KEV", "severity": "HIGH", "date_added": "2024-01-01"}]
    with patch.object(fenrir_main.ThreatIntelCollector, "fetch_cisa_kev", return_value=cisa_iocs):
        fenrir_main.run_update()

    assert not lock_path.exists()


def test_run_update_removes_lock_file_even_if_an_exception_is_raised(monkeypatch, tmp_path):
    """Il lock file deve essere rimosso anche se l'update fallisce con
    un'eccezione non gestita altrimenti, per non bloccare permanentemente
    le esecuzioni successive."""
    import main as fenrir_main

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    lock_path = tmp_path / fenrir_main.LOCK_FILE

    with patch.object(fenrir_main, "FenrirDatabase", side_effect=RuntimeError("boom")):
        with pytest.raises(RuntimeError):
            fenrir_main.run_update()

    assert not lock_path.exists()


# ---------------------------------------------------------------------------
# Retry/backoff per errori di rete transitori
# ---------------------------------------------------------------------------

def test_fetch_cisa_kev_retries_on_transient_network_error_then_succeeds():
    fake_payload = {"vulnerabilities": [{"cveID": "CVE-2024-1234", "vulnerabilityName": "Test", "dateAdded": "2024-01-01"}]}
    fake_response = MagicMock()
    fake_response.read.return_value = __import__("json").dumps(fake_payload).encode()
    fake_response.__enter__.return_value = fake_response

    transient_error = urllib.error.URLError(socket.timeout("timed out"))
    collector = ThreatIntelCollector()
    with patch("core.collector.time.sleep") as mock_sleep:
        with patch("core.collector.urllib.request.urlopen", side_effect=[transient_error, transient_error, fake_response]) as mock_urlopen:
            results = collector.fetch_cisa_kev()

    assert len(results) == 1
    assert mock_urlopen.call_count == 3
    assert mock_sleep.call_count == 2


def test_fetch_cisa_kev_gives_up_after_max_retries_on_persistent_transient_error():
    transient_error = urllib.error.URLError(socket.timeout("timed out"))
    collector = ThreatIntelCollector()
    with patch("core.collector.time.sleep"):
        with patch("core.collector.urllib.request.urlopen", side_effect=transient_error) as mock_urlopen:
            with pytest.raises(urllib.error.URLError):
                collector.fetch_cisa_kev()

    from core.collector import MAX_NETWORK_RETRIES
    assert mock_urlopen.call_count == MAX_NETWORK_RETRIES


def test_fetch_cisa_kev_does_not_retry_non_transient_url_error():
    """Un URLError la cui reason non e' un problema di connessione (es. un
    generico errore applicativo) non deve essere ritentato."""
    non_transient_error = urllib.error.URLError("some non-network reason string")
    collector = ThreatIntelCollector()
    with patch("core.collector.time.sleep") as mock_sleep:
        with patch("core.collector.urllib.request.urlopen", side_effect=non_transient_error) as mock_urlopen:
            with pytest.raises(urllib.error.URLError):
                collector.fetch_cisa_kev()

    assert mock_urlopen.call_count == 1
    mock_sleep.assert_not_called()


def test_fetch_cisa_kev_does_not_retry_http_error():
    http_error = urllib.error.HTTPError(url="https://www.cisa.gov", code=401, msg="Unauthorized", hdrs=None, fp=None)
    collector = ThreatIntelCollector()
    with patch("core.collector.time.sleep") as mock_sleep:
        with patch("core.collector.urllib.request.urlopen", side_effect=http_error) as mock_urlopen:
            with pytest.raises(urllib.error.HTTPError):
                collector.fetch_cisa_kev()

    assert mock_urlopen.call_count == 1
    mock_sleep.assert_not_called()


def test_fetch_otx_pulses_retries_on_transient_network_error_then_succeeds():
    fake_payload = {"results": []}
    fake_response = MagicMock()
    fake_response.read.return_value = __import__("json").dumps(fake_payload).encode()
    fake_response.__enter__.return_value = fake_response

    transient_error = urllib.error.URLError(ConnectionError("connection refused"))
    collector = ThreatIntelCollector()
    with patch("core.collector.time.sleep") as mock_sleep:
        with patch("core.collector.urllib.request.urlopen", side_effect=[transient_error, fake_response]) as mock_urlopen:
            results = collector.fetch_otx_pulses(api_key="fake-key")

    assert results == []
    assert mock_urlopen.call_count == 2
    assert mock_sleep.call_count == 1
