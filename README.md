<div align="center">

# FENRIR

### **Asgard Cybersecurity Suite — Module V (Threat Intelligence Aggregator)**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![CTI](https://img.shields.io/badge/Threat_Intel-Aggregator-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)

</div>

> **Fenrir** (*"Il lupo mitologico che divora la luce"* ) is a **Cyber Threat Intelligence (CTI) Aggregator and IOC Scraper** designed to collect, normalize, and index Indicators of Compromise from public feeds (CISA KEV, AlienVault OTX) into a searchable local SQLite database.

---

## Core Features

| Component | Description |
|:---|:---|
| **Feed Collector** | Ingests live threat feeds and CVE catalogs (CISA Known Exploited Vulnerabilities) |
| **Normalized Storage** | Stores indicators (CVEs, IPs, hashes) securely in a local SQLite database |
| **Fast IOC Lookup** | CLI search engine to query indicators during incident response or triage |

---

## Quick Start

```bash
# Fetch and update threat feeds
python main.py update

# Search for IOCs in local database
python main.py search CVE
```

---

<div align="center">

**Built by [Fioru12](https://github.com/Fioru12)** — Distributed under the MIT License.

</div>
