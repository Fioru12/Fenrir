<div align="center">

# FENRIR

### **Asgard Cybersecurity Suite — Module V (Threat Intelligence Aggregator)**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![CTI](https://img.shields.io/badge/Threat_Intel-Aggregator-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)

</div>

> **Perché ho costruito Fenrir?**  
> Avere accesso a feed CTI commerciali da decine di migliaia di euro è fuori budget per la maggior parte dei team emergenti. Fenrir nasce come aggregatore leggero e open-source capace di raccogliere cataloghi pubblici di minacce e indicizzarli in un database SQLite locale, interrogabile in pochi millisecondi direttamente da riga di comando durante un'analisi.

---

## Stato attuale

Ad oggi sono implementati **due feed**:

- **CISA KEV** (Known Exploited Vulnerabilities) — sempre attivo, nessuna chiave richiesta. Ogni `update` scarica l'intero catalogo pubblicato da CISA (oltre 1300 voci), non più un sottoinsieme arbitrario.
- **AlienVault OTX** (Open Threat Exchange) — opzionale. Recupera i pulse (bundle di IOC: IP, domini, hash, CVE) a cui l'account OTX configurato è iscritto. Attivo solo se la variabile d'ambiente `OTX_API_KEY` è impostata; se assente, il feed viene saltato con un warning esplicito e `update` continua normalmente con il solo CISA KEV.

AbuseIPDB è citato nella visione del progetto ma **non è ancora integrato**.

### Nota su deduplica IOC case-insensitive

Dalla versione corrente, gli indicatori vengono normalizzati (`strip().upper()`) prima di essere salvati e prima di essere confrontati in ricerca, cosi' `CVE-2024-1234` e `cve-2024-1234` sono trattati come lo stesso indicatore. Non è stata scritta una migrazione per il database esistente: gli IOC salvati prima di questa versione potrebbero non deduplicare correttamente con nuovi inserimenti equivalenti ma con case diverso (es. un vecchio `cve-2024-1234` e un nuovo `CVE-2024-1234` risulterebbero come due righe distinte). Per un DB esistente con questo problema, la soluzione più semplice è rigenerarlo da zero con `python main.py update` dopo aver cancellato `fenrir.db`.

### Come ottenere una API key OTX (gratuita)

1. Registrati su https://otx.alienvault.com
2. Vai su **Settings > API Integration** per trovare la tua chiave personale
3. Impostala come variabile d'ambiente, ad esempio copiando `.env.example` in `.env` e valorizzando `OTX_API_KEY=<la-tua-chiave>`, oppure con `export OTX_API_KEY=<la-tua-chiave>` prima di lanciare `python main.py update`

Nota: l'endpoint usato (`/pulses/subscribed`) restituisce solo i pulse a cui il tuo account OTX è iscritto — iscriviti a qualche pulse/gruppo sul sito OTX per avere IOC da raccogliere.

---

## Funzionalità Principali

- **Feed Collector**: Ingestione automatica dell'intero catalogo CISA KEV, più i pulse OTX se configurato.
- **Indicizzazione Locale**: Storage leggero basato su SQLite per query istantanee offline.
- **CLI di Ricerca**: Interrogazione immediata di CVE, IP o hash durante le fasi di triage.

---

## Quick Start

```bash
# Aggiorna i feed CTI locali (CISA KEV sempre, OTX se OTX_API_KEY è impostata)
python main.py update

# Cerca un indicatore nel database
python main.py search CVE
```

---

<div align="center">

**Sviluppato da [Fioru12](https://github.com/Fioru12)** — Parte della Suite Asgard.

</div>
