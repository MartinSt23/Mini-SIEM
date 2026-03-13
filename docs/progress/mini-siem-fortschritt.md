# Mini-SIEM – Was ich bisher gebaut habe & gelernt habe

---

## Projektstruktur – Übersicht

```
Mini-SIEM/
├── .venv/                        Python-Umgebung (nicht auf GitHub)
├── .gitignore                    Dateien die GitHub ignorieren soll
├── pyproject.toml                Projektdefinition & Dependencies
├── test_quick.py                 Manueller Schnelltest (nicht auf GitHub)
├── src/
│   └── siem/                    Das eigentliche Python-Package
│       ├── __init__.py
│       ├── normalizer/          Logs einlesen & zerlegen
│       │   ├── __init__.py
│       │   ├── base.py          Abstrakte Basisklasse
│       │   └── apache_parser.py Apache-Logs parsen
│       └── engine/              Angriffe erkennen
│           ├── __init__.py
│           ├── rule_engine.py   Koordiniert alle Regeln
│           └── rules/
│               ├── __init__.py
│               └── brute_force.py  Brute-Force-Erkennung
└── tests/
    ├── __init__.py
    └── unit/
        ├── __init__.py
        └── test_apache_parser.py   Automatische Tests
```

---

## Was jede Datei macht

### `pyproject.toml`
Definiert das Projekt – Name, Version, welche Libraries gebraucht werden. Ersetzt das alte `requirements.txt`. Mit `pip install -e ".[dev]"` werden alle Libraries installiert. Das `-e` bedeutet "editable" – Änderungen am Code wirken sofort.

### `.gitignore`
Sagt Git welche Dateien **nicht** auf GitHub hochgeladen werden sollen:
- `.venv/` – die virtuelle Umgebung (zu groß, jeder installiert sie selbst)
- `__pycache__/` – automatisch generierte Python-Dateien
- `*.db` – Datenbankdateien
- `.env` – Passwörter und Secrets
- `test_quick.py` – nur zum lokalen Testen

---

### `src/siem/normalizer/base.py`
```python
from abc import ABC, abstractmethod

class BaseParser(ABC):
    @abstractmethod
    def parse(self, raw: str) -> dict | None:
        pass
```
**Was es macht:** Definiert einen "Vertrag" – jeder Parser der von `BaseParser` erbt, **muss** eine `parse()` Methode haben. `ABC` = Abstract Base Class. Wenn man `parse()` vergisst zu implementieren, wirft Python sofort einen Fehler.

**Warum:** Später kann man NginxParser, SyslogParser usw. schreiben – alle funktionieren gleich, weil sie alle denselben "Vertrag" erfüllen.

---

### `src/siem/normalizer/apache_parser.py`
**Was es macht:** Nimmt eine rohe Apache-Logzeile und zerlegt sie in ein strukturiertes Dictionary.

**Eingabe:**
```
192.168.1.1 - - [01/Mar/2026:10:00:00 +0000] "GET /login HTTP/1.1" 401 512
```

**Ausgabe:**
```python
{
    "source_ip":  "192.168.1.1",
    "timestamp":  "01/Mar/2026:10:00:00 +0000",
    "method":     "GET",
    "path":       "/login",
    "status":     401,
    "size":       "512",
    "event_type": "LOGIN_FAILED"
}
```

**Wie:** Mit einem **Regex-Pattern** (`re.compile`) – ein Suchmuster das die Logzeile in Teile zerlegt. Jeder benannte Teil (`(?P<ip>...)`) wird später per `m.group("ip")` abgerufen.

**`_classify()`:** Übersetzt HTTP-Statuscodes in lesbare Event-Typen. Die Reihenfolge ist wichtig – vom Spezifischsten (`401`) zum Allgemeinsten (`>=400`), damit sich die Bedingungen nicht überschneiden.

---

### `src/siem/engine/rule_engine.py`
**Was es macht:** Koordiniert alle Erkennungsregeln. Bekommt ein Event, gibt entweder einen Alert zurück oder `None`.

**Wie:** Geht alle Regeln der Reihe nach durch. Sobald eine Regel anschlägt, wird der Alert zurückgegeben.

---

### `src/siem/engine/rules/brute_force.py`
**Was es macht:** Erkennt Brute-Force-Angriffe – also wenn jemand sehr oft versucht sich einzuloggen.

**Logik:**
1. Nur `LOGIN_FAILED` Events werden betrachtet
2. Pro IP-Adresse werden die letzten Fehlversuche gespeichert
3. Alles älter als 60 Sekunden wird verworfen (Sliding Window)
4. Bei 5+ Versuchen in 60 Sekunden → Alert mit Severity `HIGH`

**`defaultdict(list)`:** Ein Dictionary das automatisch eine leere Liste erstellt wenn ein neuer Key (IP-Adresse) auftaucht.

**UTC statt lokaler Zeit:** Intern immer UTC verwenden – eindeutig, keine Sommer/Winterzeit-Probleme. Erst beim Anzeigen auf Wiener Zeit (GMT+1/+2) umrechnen.

---

### `tests/unit/test_apache_parser.py`
**Was es macht:** Automatische Tests die prüfen ob der Parser korrekt funktioniert.

**Wie:** Mit `pytest` – man schreibt Funktionen die mit `test_` beginnen, und `assert` prüft ob ein Wert stimmt. Bei `pytest tests/` werden alle Tests automatisch gefunden und ausgeführt.

**Warum Tests:** Wenn man später Code ändert, merkt man sofort ob etwas kaputtgegangen ist.

---

## Wie alles zusammenhängt

```
Rohe Logzeile
     ↓
ApacheParser.parse()          → zerlegt die Zeile in ein Dictionary
     ↓
rule_engine.evaluate(event)   → gibt das Event an alle Regeln weiter
     ↓
brute_force.check(event)      → prüft ob ein Angriff vorliegt
     ↓
Alert Dictionary              → wird später in DB gespeichert & angezeigt
```

---

## Was ich gelernt habe

### Python-Konzepte

**Virtuelle Umgebung (venv)**
Isoliert Libraries pro Projekt. Jedes Projekt hat seine eigene Python-Umgebung – Änderungen in einem Projekt beeinflussen andere nicht. `venv` = virtual environment.

**Klassen und Vererbung**
```python
class ApacheParser(BaseParser):   # erbt von BaseParser
    def parse(self, ...):         # überschreibt die abstrakte Methode
```
`self` ist immer der erste Parameter einer Methode – Referenz auf die eigene Instanz.

**Abstrakte Klassen (ABC)**
Erzwingen dass Unterklassen bestimmte Methoden implementieren. Wenn man es vergisst, gibt es sofort einen Fehler – nicht erst später beim Ausführen.

**Regular Expressions (Regex)**
Suchmuster für Text. `\S+` = ein oder mehr Zeichen die kein Leerzeichen sind. `(?P<name>...)` = benannte Gruppe die man später per `.group("name")` abrufen kann. `r'...'` = raw string, damit `\S` nicht als Sonderzeichen interpretiert wird.

**`dict | None` als Rückgabetyp**
Eine Funktion kann entweder ein Dictionary oder `None` zurückgeben. `None` bedeutet "kein Ergebnis" – z.B. wenn eine Logzeile nicht geparst werden konnte.

**`defaultdict`**
Ein Dictionary das bei unbekannten Keys automatisch einen Standardwert erstellt – kein `KeyError` mehr.

**Einrückung in Python**
Python benutzt Einrückung (4 Leerzeichen) statt `{}` um Blöcke zu definieren. Alles was zur Klasse gehört, muss eingerückt sein.

---

### Git & GitHub

| Befehl | Bedeutung |
|---|---|
| `git init` | Neues Repository erstellen |
| `git add .` | Alle Änderungen vormerken |
| `git commit -m "..."` | Vorgemerktes als Snapshot speichern |
| `git push` | Snapshots zu GitHub hochladen |
| `git remote set-url` | GitHub-Adresse ändern |

**Commit Message Konvention:**
```
feat:     Neues Feature
fix:      Bugfix
refactor: Umstrukturierung
test:     Tests
docs:     Dokumentation
chore:    Sonstiges
```

**Personal Access Token:** Wenn man mehrere GitHub-Accounts hat, kann man per Token gezielt mit einem bestimmten Account pushen – ohne die gespeicherten Windows-Anmeldedaten zu ändern.

---

### Projektstruktur

**`src/`-Layout:** Code liegt in `src/siem/` statt direkt im Root. Verhindert dass Tests den Code direkt aus dem Ordner laden – sie müssen das installierte Package benutzen, genau wie echte Nutzer.

**`__init__.py`:** Macht einen Ordner zu einem Python-Package das importiert werden kann. Ohne diese Datei findet Python das Package nicht.

**`.gitignore`:** Wichtige Dateien die nie auf GitHub sollen: `.venv/`, Passwörter, Datenbankdateien, automatisch generierte Dateien.

---

## Bisherige Commits

| Commit | Was |
|---|---|
| `feat: initial project structure` | Ordner, pyproject.toml, .gitignore |
| `feat: add BaseParser and ApacheParser` | Normalizer fertiggestellt |
| `feat: add brute force detection rule` | Erste Erkennungsregel |
| `feat: add rule engine with brute force detection` | Rule Engine fertiggestellt |

---

## Nächste Schritte

1. **File Watcher** – echte Logdateien in Echtzeit beobachten
2. **Datenbank** – Events und Alerts in SQLite speichern
3. **Mehr Regeln** – Port-Scan, SQL-Injection
4. **Dashboard** – Flask-Web-UI für Alerts

---

*Erstellt: März 2026*
