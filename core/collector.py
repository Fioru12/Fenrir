import json
import logging
import urllib.request
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class ThreatIntelCollector:
    """
    Collects and normalizes Threat Intelligence Indicators of Compromise (IOCs)
    from public threat feeds. Oggi implementato solo per CISA KEV: AlienVault
    OTX e AbuseIPDB non sono ancora integrati.
    """

    def __init__(self):
        pass

    def fetch_cisa_kev(self) -> List[Dict[str, Any]]:
        """Fetches Known Exploited Vulnerabilities from CISA catalog.

        Se il feed non e' raggiungibile, propaga l'errore invece di
        restituire dati finti: un fallback silenzioso qui inquinerebbe il
        database delle minacce con IOC inventati, indistinguibili da quelli
        reali (stessa forma, stesso "source": "CISA KEV") per chiunque li
        consulti dopo, inclusa una ricerca in Fenrir stesso.
        """
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        req = urllib.request.Request(url, headers={"User-Agent": "Fenrir-CTI/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            vulns = data.get("vulnerabilities", [])
            results = []
            for v in vulns[:20]: # Grab top 20
                results.append({
                    "indicator_type": "CVE",
                    "indicator": v.get("cveID"),
                    "name": v.get("vulnerabilityName"),
                    "source": "CISA KEV",
                    "severity": "HIGH",
                    "date_added": v.get("dateAdded")
                })
            return results

    def aggregate_feeds(self) -> List[Dict[str, Any]]:
        """Ogni feed fallisce indipendentemente: uno irraggiungibile non deve
        azzerare gli IOC gia' raccolti dagli altri."""
        feed_data: List[Dict[str, Any]] = []
        try:
            feed_data.extend(self.fetch_cisa_kev())
        except Exception as error:
            logger.warning("Feed CISA KEV non raggiungibile, nessun IOC recuperato da questa fonte: %s", error)
        return feed_data
