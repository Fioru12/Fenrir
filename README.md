<div align="center">

# FENRIR

### **Asgard Cybersecurity Suite — Module V (Threat Intelligence Aggregator)**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![CTI](https://img.shields.io/badge/Threat_Intel-Aggregator-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)

</div>

> **Perché ho costruito Fenrir?**  
> Avere accesso a feed CTI commerciali da decine di migliaia di euro è fuori budget per la maggior parte dei team emergenti. Fenrir nasce come aggregatore leggero e open-source capace di raccogliere cataloghi pubblici di minacce (come le vulnerabilità sfruttate attivamente del CISA KEV o feed OTX) e indicizzarli in un database SQLite locale, interrogabile in pochi millisecondi direttamente da riga di comando durante un'analisi.

---

## Funzionalità Principali

- **Feed Collector**: Ingestione automatica di cataloghi di vulnerabilità e IOC da fonti pubbliche.
- **Indicizzazione Locale**: Storage leggero basato su SQLite per query istantanee offline.
- **CLI di Ricerca**: Interrogazione immediata di CVE, IP o hash durante le fasi di triage.

---

## Quick Start

```bash
# Aggiorna i feed CTI locali
python main.py update

# Cerca un indicatore nel database
python main.py search CVE
```

---

<div align="center">

**Sviluppato da [Fioru12](https://github.com/Fioru12)** — Parte della Suite Asgard.

</div>
