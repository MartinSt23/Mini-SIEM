# Mini-SIEM – Projektplan

---

## Überblick

| Attribut | Wert |
|---|---|
| Projektname | Mini-SIEM |
| Sprache | Python 3.14.3 |
| Ziel | Logs sammeln, korrelieren, Angriffe erkennen & visualisieren |
| Gesamtdauer | ~4 Wochen (Teilzeit) |
| GitHub | github.com/MartinSt23/Mini-SIEM |

---

## Phase 1 – Fundament ✅ ABGESCHLOSSEN

### Was wurde gemacht
- Projektstruktur manuell im Explorer angelegt
- Virtuelle Umgebung (`.venv`) erstellt und aktiviert
- `pyproject.toml` mit allen Dependencies definiert
- `pip install -e ".[dev]"` erfolgreich ausgeführt
- `.gitignore` erstellt
- GitHub-Repo aufgesetzt, Personal Access Token für MartinSt23 konfiguriert
- Erster Push auf GitHub

### Dateien
```
Mini-SIEM/
├── .venv/                        ✅ erstellt
├── .gitignore                    ✅ erstellt
├── pyproject.toml                ✅ erstellt
└── src/siem/
    ├── __init__.py               ✅ erstellt
    └── normalizer/
        ├── __init__.py           ✅ erstellt
        ├── base.py               ✅ erstellt
        └── apache_parser.py      ✅ erstellt
```

---

## Phase 2 – Normalizer ✅ ABGESCHLOSSEN

### Was wurde gemacht
- `BaseParser` als abstrakte Basisklasse implementiert
- `ApacheParser` als Klasse implementiert (erbt von `BaseParser`)
- Regex-Pattern für Apache-Logs definiert
- `_classify()` Methode für HTTP-Statuscodes implementiert
- Erste manuelle Tests mit `test_quick.py`

### Erkannte Event-Typen
| HTTP Status | Event Type |
|---|---|
| 401 | LOGIN_FAILED |
| 500+ | SERVER_ERROR |
| 400–499 | CLIENT_ERROR |
| Rest | SUCCESS |

---

## Phase 3a – Rule Engine ✅ ABGESCHLOSSEN

### Was wurde gemacht
- `rule_engine.py` implementiert
- Erste Erkennungsregel: Brute-Force (`brute_force.py`)
- Regel erkennt 5+ fehlgeschlagene Logins in 60 Sekunden
- Manuell getestet: Alert erscheint beim 5. Versuch

### Dateien
```
src/siem/engine/
├── __init__.py                   ✅ erstellt
├── rule_engine.py                ✅ erstellt
└── rules/
    ├── __init__.py               ✅ erstellt
    └── brute_force.py            ✅ erstellt
```

---

## Phase 3b – Tests ✅ ABGESCHLOSSEN

### Was wurde gemacht
- `pytest` eingerichtet
- Erste Unit-Tests für `ApacheParser` geschrieben
- 2/2 Tests grün ✅

### Tests
```
tests/
├── __init__.py                   ✅ erstellt
└── unit/
    ├── __init__.py               ✅ erstellt
    └── test_apache_parser.py     ✅ 2 Tests, alle grün
```

---

## Phase 4 – Collector + Storage ⏳ OFFEN

### Ziel
Logs aus echten Dateien einlesen und in SQLite speichern.

### Aufgaben
- [ ] `file_watcher.py` – Logdateien in Echtzeit beobachten
- [ ] `models.py` – Datenbank-Modelle (Event, Alert)
- [ ] `repository.py` – Daten speichern und abfragen
- [ ] `scripts/generate_test_logs.py` – Testdaten erzeugen
- [ ] End-to-End-Test: Log-Zeile → Datenbank

---

## Phase 5 – Weitere Regeln ⏳ OFFEN

### Aufgaben
- [ ] `port_scan.py` – >20 Ports in 10 Sekunden
- [ ] `sql_injection.py` – Verdächtige URL-Parameter
- [ ] `directory_traversal.py` – `../` im Pfad
- [ ] Tests für alle neuen Regeln

---

## Phase 6 – Dashboard ⏳ OFFEN

### Aufgaben
- [ ] Flask-App aufsetzen
- [ ] Alerts-Tabelle anzeigen
- [ ] Live-Refresh per AJAX
- [ ] Severity-Farben (ROT/ORANGE/GELB/GRÜN)
- [ ] Wiener Zeit (GMT+1/+2) für Anzeige

---

## Phase 7 – Docker & CI/CD ⏳ OFFEN

### Aufgaben
- [ ] `Dockerfile` erstellen
- [ ] `docker-compose.yml` (SIEM + DB + Redis)
- [ ] GitHub Actions CI (pytest + ruff bei jedem Push)
- [ ] Code-Coverage > 70%

---

## Erkennungsregeln – Übersicht

| Regel | Status | Trigger | Schwere |
|---|---|---|---|
| Brute-Force | ✅ | >5 Fehlanmeldungen in 60s | HIGH |
| Port-Scan | ⏳ | >20 Ports in 10s | MEDIUM |
| SQL-Injection | ⏳ | Verdächtige URL-Parameter | CRITICAL |
| Directory Traversal | ⏳ | `../` im Pfad | HIGH |

---

*Zuletzt aktualisiert: März 2026*
