# ARIA Password Tester

*Ein schlanker Web-Passwortstärke-Tester: Live-Analyse beim Tippen, echte Crack-Zeit-Schätzung, Have-I-Been-Pwned-Abgleich: und das Passwort verlässt dabei nie ungeschützt den eigenen Rechner.*

<p>
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue?style=flat-square">
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white">
  <img alt="FastAPI" src="https://img.shields.io/badge/backend-FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white">
  <img alt="Tests: 6 passing" src="https://img.shields.io/badge/tests-6%20passing-brightgreen?style=flat-square">
  <img alt="Keine Passwort-Speicherung" src="https://img.shields.io/badge/passwords-nie%20gespeichert-critical?style=flat-square">
</p>

## Was es ist

ARIA nimmt ein Passwort entgegen, das während des Tippens (debounced) an einen kleinen FastAPI-Endpunkt geschickt wird, und liefert in Echtzeit zurück: Shannon-Entropie, [zxcvbn](https://github.com/dropbox/zxcvbn)-Score, erkannte Schwachmuster, geschätzte Crack-Zeiten gegen vier realistische Angreiferprofile und optional einen Have-I-Been-Pwned-Abgleich. Das Frontend ist reines HTML/CSS/JS ohne Build-Schritt.

Kein Login, keine Datenbank, kein Tracking: die App hat genau zwei Endpunkte (`/api/health`, `/api/analyze`) und einen Zweck.

## Features

- Live-Analyse beim Tippen, debounced (220 ms), mit Schutz gegen veraltete/überholte Antworten
- zxcvbn-Score + Shannon-Entropie + regelbasierte Mustererkennung (Jahreszahlen, Tastatur-Walks, Trivialwörter, „Name+Zahl"-Schema, …)
- Geschätzte Crack-Zeiten gegen vier Angreiferprofile (Online-Bruteforce bis hypothetischer ASIC-Cluster)
- Have-I-Been-Pwned-Abgleich per **k-Anonymity**: nur ein 5-stelliger Hash-Präfix verlässt den Server, niemals das Passwort oder der volle Hash
- Fünfstufige Klartext-Bewertung (`weak` → `excellent`)
- Rotierende Zeichen-Animation während der Analyse
- Rate-Limiting pro IP, keine Passwort-Logs, generische Fehlerantworten (keine Stacktrace-Leaks)

## Sicherheit & Datenschutz

Das ist ein Sicherheits-Tool, entsprechend wird hier nichts dem Zufall überlassen:

| Maßnahme | Umsetzung |
|---|---|
| Keine Speicherung | Passwörter existieren nur für die Dauer eines Requests im Speicher. Keine Datenbank, keine Dateischreibzugriffe. |
| Keine Logs | Der einzige Log-Aufruf betrifft unbehandelte Server-Fehler: niemals den Passwort-Wert. Uvicorns Access-Log protokolliert standardmäßig nur Methode/Pfad/Status, keine Bodies. |
| HIBP ohne Preisgabe | SHA-1-Hash wird **lokal** gebildet; an `api.pwnedpasswords.com` geht nur der 5-Zeichen-Präfix (k-Anonymity). Ein Ausfall der HIBP-API lässt die restliche Analyse unberührt (fail-open, kein Absturz). |
| Rate-Limiting | `slowapi`, standardmäßig 30 Anfragen/Minute pro IP auf `/api/analyze`, über `RATE_LIMIT` konfigurierbar. |
| Generische Fehler | Unbehandelte Exceptions liefern `500` ohne Details: keine Stacktraces an den Client. |
| Non-root Container | Das Docker-Image läuft als dedizierter `appuser`, nicht als `root`. |
| Nur lokal erreichbar | `docker-compose.yml` bindet standardmäßig auf `127.0.0.1`, nicht auf alle Netzwerk-Interfaces: die App ist damit nicht versehentlich im LAN erreichbar. |
| Enges CORS | Default ist `http://localhost:8000`, nicht `*`. Nur erweitern, wenn die API tatsächlich von einer anderen Origin aus per Browser angesprochen werden soll. |
| `.env` bleibt lokal | `.env` ist gitignored und wird nie committet: nur `.env.example` als Vorlage. |

**Wenn du diese App über den eigenen Rechner hinaus erreichbar machen willst** (z. B. per Reverse-Proxy oder Tunnel): setze `CORS_ORIGINS` exakt auf die genutzte(n) Domain(s), belasse die Bindung hinter einem TLS-terminierenden Proxy und nicht direkt am offenen Port, und erhöhe bei Bedarf das Rate-Limit nicht großzügiger als nötig.

## Schnellstart (lokal)

### Variante A: Python-venv

```bash
python3 -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8000
```

Browser: http://localhost:8000

### Variante B: Docker

```bash
cp .env.example .env
docker compose up -d --build
```

Der Container lauscht nur auf `127.0.0.1:8000` (siehe `docker-compose.yml`) und läuft als non-root User. Healthcheck läuft automatisch gegen `/api/health`.

## Tests & CI

```bash
pip install -e ".[dev]"
ruff check app tests
pytest -q
```

Jeder Push/PR läuft automatisch durch dieselbe Pipeline (`.github/workflows/ci.yml`): Lint (`ruff`) + 6 Unit-Tests gegen die Analyse-Logik in `app/strength.py`.

## Konfiguration

Alle Variablen liegen in `.env` (aus `.env.example` kopieren, siehe oben):

| Variable | Default | Bedeutung |
|---|---|---|
| `HOST` | `0.0.0.0` | Bind-Adresse für uvicorn selbst (innerhalb des Containers/venv) |
| `PORT` | `8000` | Port für uvicorn |
| `LOG_LEVEL` | `INFO` | Log-Level |
| `RATE_LIMIT` | `30/minute` | Rate-Limit pro IP für `/api/analyze` |
| `ENABLE_HIBP` | `true` | Have-I-Been-Pwned-Abgleich ein-/ausschalten (bei `false` komplett offline nutzbar) |
| `CORS_ORIGINS` | `http://localhost:8000` | Erlaubte Origins, kommagetrennt |

## Ehrliche Grenzen

- **Kein Auth, keine Persistenz: by design.** Das ist ein Stateless-Utility-Tool, kein Passwort-Tresor. Wer Passwörter verwalten will, braucht einen Passwort-Manager, nicht dieses Tool.
- **Die Crack-Zeit-Schätzung ist ein vereinfachtes Brute-Force-Modell** (Zeichenraum^Länge / 2 gegen feste Angreifer-Raten), keine Simulation realer Angriffswerkzeuge. Der zxcvbn-Score daneben ist die realistischere Einschätzung, da er tatsächliche Angriffsmuster (Wörterbücher, Leetspeak, Tastatur-Walks) einbezieht.
- **HIBP-Ausfälle werden stillschweigend toleriert** (`breached`/`breach_count` werden dann `null`): bewusst so gebaut, damit ein Drittanbieter-Ausfall die Kernfunktion nie blockiert, aber es bedeutet auch: ein `null` ist kein Beweis für „nicht geleakt".
- **Kein Ersatz für organisatorische Passwort-Policies.** Die Bewertung ist eine Heuristik, keine Zertifizierung.

## Lizenz

MIT: siehe [LICENSE](LICENSE).
