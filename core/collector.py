import json
import logging
import socket
import time
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

OTX_PULSES_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# Numero massimo di tentativi (incluso il primo) per gli errori di rete
# transitori (timeout, connessione rifiutata) e attesa di base, in secondi,
# fra un tentativo e il successivo (cresce linearmente: 1s, 2s, ...).
MAX_NETWORK_RETRIES = 3
RETRY_BACKOFF_BASE_SECONDS = 1


def _is_transient_network_error(error: urllib.error.URLError) -> bool:
    """True solo per errori di rete transitori (timeout, connessione
    rifiutata/reset), per cui ha senso ritentare. Un URLError la cui
    `reason` non e' un errore di connessione (es. un errore applicativo)
    non viene considerato transitorio.
    """
    reason = error.reason
    if isinstance(reason, (socket.timeout, TimeoutError, ConnectionError, OSError)):
        return True
    return isinstance(error, TimeoutError)


def _urlopen_with_retry(req, timeout, max_retries=MAX_NETWORK_RETRIES):
    """Esegue urllib.request.urlopen ritentando SOLO in caso di errori di
    rete transitori (URLError con causa di timeout/connessione). Gli errori
    applicativi (es. HTTPError 401, dati malformati) non vengono ritentati e
    si propagano immediatamente al chiamante.
    """
    attempt = 0
    while True:
        attempt += 1
        try:
            return urllib.request.urlopen(req, timeout=timeout)
        except urllib.error.HTTPError:
            # Errore applicativo (es. 401): non ha senso ritentare.
            raise
        except urllib.error.URLError as error:
            if not _is_transient_network_error(error) or attempt >= max_retries:
                raise
            wait_seconds = RETRY_BACKOFF_BASE_SECONDS * attempt
            logger.warning(
                "Errore di rete transitorio (tentativo %d/%d): %s. Nuovo tentativo tra %ds.",
                attempt, max_retries, error, wait_seconds
            )
            time.sleep(wait_seconds)

class ThreatIntelCollector:
    """
    Collects and normalizes Threat Intelligence Indicators of Compromise (IOCs)
    from public threat feeds. Implementati oggi: CISA KEV (sempre attivo) e
    AlienVault OTX (opzionale, richiede API key). AbuseIPDB non e' ancora
    integrato.
    """

    def __init__(self):
        pass

    def fetch_cisa_kev(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Fetches Known Exploited Vulnerabilities from CISA catalog.

        Se il feed non e' raggiungibile, propaga l'errore invece di
        restituire dati finti: un fallback silenzioso qui inquinerebbe il
        database delle minacce con IOC inventati, indistinguibili da quelli
        reali (stessa forma, stesso "source": "CISA KEV") per chiunque li
        consulti dopo, inclusa una ricerca in Fenrir stesso.

        Di default scarica l'intero catalogo (oltre 1300 voci). `limit` e'
        un parametro esplicito, opzionale, pensato solo per chi vuole
        eseguire test rapidi: non deve mai diventare un cap silenzioso.
        """
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        req = urllib.request.Request(url, headers={"User-Agent": "Fenrir-CTI/1.0"})
        with _urlopen_with_retry(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            vulns = data.get("vulnerabilities", [])
            if limit is not None:
                vulns = vulns[:limit]
            results = []
            for v in vulns:
                cve_id = v.get("cveID")
                vuln_name = v.get("vulnerabilityName")
                if not cve_id or not vuln_name:
                    logger.warning(
                        "Entry CISA KEV scartata per dati mancanti (cveID=%r, vulnerabilityName=%r)",
                        cve_id, vuln_name
                    )
                    continue
                results.append({
                    "indicator_type": "CVE",
                    "indicator": cve_id,
                    "name": vuln_name,
                    "source": "CISA KEV",
                    "severity": "HIGH",
                    "date_added": v.get("dateAdded")
                })
            return results

    def fetch_otx_pulses(self, api_key: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetches subscribed pulses (IOC bundles) from AlienVault OTX.

        Ogni pulse contiene un array `indicators` (IP, dominio, hash, CVE,
        ecc.), normalizzati qui nello stesso schema dizionario usato da
        `fetch_cisa_kev` per compatibilita' con `save_iocs`. Il campo
        `source` e' sempre "OTX", per distinguerli dagli IOC CISA KEV.

        Richiede una API key valida (gratuita, ottenibile registrandosi su
        https://otx.alienvault.com). Se la chiave e' assente o vuota viene
        sollevato un ValueError esplicito, cosi' il chiamante puo' saltare
        il feed in modo pulito invece di andare in crash o inventare dati.
        """
        if not api_key:
            raise ValueError(
                "OTX_API_KEY assente o vuota: impossibile interrogare AlienVault OTX. "
                "Registrati gratuitamente su https://otx.alienvault.com per ottenerne una."
            )

        url = f"{OTX_PULSES_URL}?limit={limit}"
        req = urllib.request.Request(url, headers={"X-OTX-API-KEY": api_key, "User-Agent": "Fenrir-CTI/1.0"})
        try:
            with _urlopen_with_retry(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as error:
            if error.code == 401:
                raise ValueError("OTX_API_KEY non valida (HTTP 401 da AlienVault OTX).") from error
            raise

        pulses = data.get("results", [])
        results: List[Dict[str, Any]] = []
        for pulse in pulses:
            pulse_name = pulse.get("name")
            for ind in pulse.get("indicators", []):
                indicator_value = ind.get("indicator")
                indicator_type = ind.get("type")
                if not indicator_value or not indicator_type:
                    logger.warning(
                        "Indicatore OTX scartato per dati mancanti (indicator=%r, type=%r)",
                        indicator_value, indicator_type
                    )
                    continue
                results.append({
                    "indicator_type": indicator_type,
                    "indicator": indicator_value,
                    "name": ind.get("description") or pulse_name or indicator_value,
                    "source": "OTX",
                    "severity": "MEDIUM",
                    "date_added": ind.get("created") or pulse.get("modified") or pulse.get("created")
                })
        return results

    def aggregate_feeds(self, otx_api_key: Optional[str] = None) -> List[Dict[str, Any]]:
        """Ogni feed fallisce indipendentemente: uno irraggiungibile non deve
        azzerare gli IOC gia' raccolti dagli altri.

        `otx_api_key` e' opzionale: se assente il feed OTX viene semplicemente
        saltato (nessun crash), dato che richiede una API key gratuita non
        disponibile di default in questo ambiente.
        """
        feed_data: List[Dict[str, Any]] = []
        try:
            feed_data.extend(self.fetch_cisa_kev())
        except Exception as error:
            logger.warning("Feed CISA KEV non raggiungibile, nessun IOC recuperato da questa fonte: %s", error)

        if otx_api_key:
            try:
                feed_data.extend(self.fetch_otx_pulses(otx_api_key))
            except Exception as error:
                logger.warning("Feed OTX non raggiungibile, nessun IOC recuperato da questa fonte: %s", error)

        return feed_data
