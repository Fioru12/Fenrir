import sys
import argparse
from core.collector import ThreatIntelCollector
from storage.database import FenrirDatabase
from core.colors import Colors

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

def run_update():
    print(Colors.MAGENTA + "=" * 65 + Colors.ENDC)
    print(f"{Colors.BOLD} Fenrir - Threat Intelligence Aggregator & CTI Engine{Colors.ENDC}")
    print(Colors.MAGENTA + "=" * 65 + Colors.ENDC)

    collector = ThreatIntelCollector()
    db = FenrirDatabase("fenrir.db")

    print(f"{Colors.CYAN}[*]{Colors.ENDC} Fetching and normalizing threat feeds (CISA KEV, AlienVault OTX)...")
    iocs = collector.aggregate_feeds()
    print(f"{Colors.CYAN}[*]{Colors.ENDC} Fetched {len(iocs)} indicators from feeds.")

    new_count = db.save_iocs(iocs)
    print(f"{Colors.GREEN}[SUCCESS]{Colors.ENDC} Added {new_count} new unique IOCs to database.")

    stats = db.get_stats()
    print(f"    Total IOCs indexed: {stats['total_iocs']}")
    print(Colors.MAGENTA + "=" * 65 + Colors.ENDC)

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
