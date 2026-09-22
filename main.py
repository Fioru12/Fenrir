import sys
import os
import argparse
from core.collector import ThreatIntelCollector
from storage.database import FenrirDatabase
from core.colors import Colors

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

import time

LOCK_FILE = "fenrir.lock"
LOCK_MAX_AGE_SECONDS = 900  # 15 minutes


def _acquire_lock() -> bool:
    """Acquires a lock file atomically. Automatically cleans up stale locks (> 15 min)."""
    if os.path.exists(LOCK_FILE):
        try:
            mtime = os.path.getmtime(LOCK_FILE)
            if time.time() - mtime > LOCK_MAX_AGE_SECONDS:
                print(f"{Colors.YELLOW}[WARN]{Colors.ENDC} Rilevato lock orfano/scaduto (> 15m), rimozione automatica.")
                os.remove(LOCK_FILE)
        except OSError:
            pass

    try:
        lock_fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_RDWR)
        with os.fdopen(lock_fd, "w", encoding="utf-8") as f:
            f.write(f"pid={os.getpid()}\ntime={time.time()}\n")
        return True
    except FileExistsError:
        return False


def run_update():
    # Lock file per evitare che due processi di update lanciati in parallelo
    # (es. due cron job sovrapposti) scrivano contemporaneamente sul DB
    # SQLite, rischiando di corromperlo.
    if not _acquire_lock():
        print(f"{Colors.YELLOW}[SKIP]{Colors.ENDC} Un altro update è già in corso, salto questa esecuzione.")
        return

    try:
        print(Colors.MAGENTA + "=" * 65 + Colors.ENDC)
        print(f"{Colors.BOLD} Fenrir - Threat Intelligence Aggregator & CTI Engine{Colors.ENDC}")
        print(Colors.MAGENTA + "=" * 65 + Colors.ENDC)

        collector = ThreatIntelCollector()
        db = FenrirDatabase("fenrir.db")

        otx_api_key = os.environ.get("OTX_API_KEY")
        misp_url = os.environ.get("MISP_URL")
        misp_api_key = os.environ.get("MISP_API_KEY")

        print(f"{Colors.CYAN}[*]{Colors.ENDC} Fetching and normalizing threat feeds (CISA KEV)...")
        iocs = []
        try:
            iocs.extend(collector.fetch_cisa_kev())
        except Exception as error:
            print(f"{Colors.YELLOW}[WARN]{Colors.ENDC} Feed CISA KEV non raggiungibile: {error}")

        if otx_api_key:
            print(f"{Colors.CYAN}[*]{Colors.ENDC} Fetching and normalizing threat feed (OTX)...")
            try:
                iocs.extend(collector.fetch_otx_pulses(otx_api_key))
            except Exception as error:
                print(f"{Colors.YELLOW}[WARN]{Colors.ENDC} Feed OTX non raggiungibile: {error}")
        else:
            print(f"{Colors.YELLOW}[SKIP]{Colors.ENDC} OTX_API_KEY non impostata, salto il feed OTX.")

        if misp_url and misp_api_key:
            print(f"{Colors.CYAN}[*]{Colors.ENDC} Fetching and normalizing threat feed (MISP)...")
            try:
                iocs.extend(collector.fetch_misp_attributes(misp_url, misp_api_key))
            except Exception as error:
                print(f"{Colors.YELLOW}[WARN]{Colors.ENDC} Feed MISP non raggiungibile: {error}")
        else:
            print(f"{Colors.YELLOW}[SKIP]{Colors.ENDC} MISP_URL/MISP_API_KEY non impostate, salto il feed MISP.")

        print(f"{Colors.CYAN}[*]{Colors.ENDC} Fetched {len(iocs)} indicators from feeds.")

        new_count = db.save_iocs(iocs)
        print(f"{Colors.GREEN}[SUCCESS]{Colors.ENDC} Added {new_count} new unique IOCs to database.")

        stats = db.get_stats()
        print(f"    Total IOCs indexed: {stats['total_iocs']}")
        print(Colors.MAGENTA + "=" * 65 + Colors.ENDC)
    finally:
        try:
            os.remove(LOCK_FILE)
        except OSError:
            pass

def run_search(query: str):
    print(Colors.MAGENTA + "=" * 65 + Colors.ENDC)
    print(f"{Colors.BOLD} Fenrir - IOC Lookup & Threat Intel Search{Colors.ENDC}")
    print(Colors.MAGENTA + "=" * 65 + Colors.ENDC)
    print(f"{Colors.CYAN}[*]{Colors.ENDC} Searching query: '{query}'")

    db = FenrirDatabase("fenrir.db")
    results = db.search_ioc(query)

    print(f"{Colors.CYAN}[*]{Colors.ENDC} Found {len(results)} matching indicator(s).\n")
    if results:
        print(f" {'TYPE':<8} {'INDICATOR':<20} {'SEV':<10} {'SOURCE':<12} {'NAME'}")
        print(f" {'-'*6:<8} {'-'*18:<20} {'-'*8:<10} {'-'*10:<12} {'-'*20}")
        for r in results:
            sev_color = Colors.RED if r['severity'] == 'CRITICAL' else Colors.YELLOW
            print(f" {r['indicator_type']:<8} {Colors.BOLD}{r['indicator']:<20}{Colors.ENDC} {sev_color}{r['severity']:<10}{Colors.ENDC} {r['source']:<12} {r['name'][:35]}")
    else:
        print(f" {Colors.YELLOW}No matching IOCs found in local intelligence database.{Colors.ENDC}")

    print(Colors.MAGENTA + "=" * 65 + Colors.ENDC)

def main():
    parser = argparse.ArgumentParser(description="Fenrir: Threat Intelligence Aggregator & CTI Engine")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    subparsers.add_parser("update", help="Fetch and update threat intelligence feeds")

    search_parser = subparsers.add_parser("search", help="Search IOC in local database")
    search_parser.add_argument("query", help="Indicator (CVE, IP, domain) or keyword to search")

    args = parser.parse_args()

    if args.command == "update":
        run_update()
    elif args.command == "search":
        run_search(args.query)
    else:
        run_update()
        run_search("CVE")

if __name__ == "__main__":
    main()
