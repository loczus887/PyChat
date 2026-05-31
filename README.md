# PyChat

System czatu tekstowego w czasie rzeczywistym oparty na autorskim protokole **PCS (PyChat-Secure)**. Architektura klient–serwer, szyfrowanie TLS 1.3, integralność ramek HMAC-SHA256, autoryzacja bcrypt.

## Wymagania

| Wymaganie | Wersja |
|---|---|
| Python | 3.12+ |
| OpenSSL | do generowania certyfikatów TLS |
| Docker (opcjonalnie) | 20.10+ |
| Docker Compose (opcjonalnie) | v2 |

## Instalacja

```bash
git clone <repo-url>
cd PyChat
python -m venv .venv

# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
```

## Szybki start (Docker)

Najprostszy sposób uruchomienia - serwer z TLS, użytkownikiem demo i logami:

```bash
docker compose up --build
```

Serwer nasłuchuje na `localhost:9000`. Przy pierwszym uruchomieniu tworzone są:

- certyfikat TLS w `./certs/` (montowany z kontenera)
- baza SQLite z użytkownikami demo: **alice** / **secret** i **bob** / **secret**

Klient lokalny (bez dodatkowych flag - ten sam sekret HMAC co Docker):

```bash
python run_client.py --host 127.0.0.1 --port 9000 --cafile certs/server.crt
```

## Uruchomienie lokalne (bez Docker)

### 1. Certyfikat TLS

```bash
python scripts/generate_certs.py certs
```

### 2. Użytkownik w bazie

```bash
python add_user.py alice mojehaslo --db pychat.db
```

### 3. Serwer

```bash
python -m server.main \
  --certfile certs/server.crt \
  --keyfile certs/server.key \
  --db pychat.db \
  --log-level INFO \
  --log-file logs/pychat.log
```

### 4. Klient

```bash
python run_client.py \
  --host 127.0.0.1 \
  --port 9000 \
  --cafile certs/server.crt \
  --hmac-secret pychat-default-secret
```

## Struktura projektu

```
PyChat/
├── pcs/              # Protokół PCS (ramki, HMAC, TLS, bcrypt)
├── server/           # Serwer asyncio
├── client/           # Klient CLI
├── db/               # SQLite - użytkownicy i role
├── tests/            # 164 testy automatyczne
├── scripts/          # Certyfikaty, Docker entrypoint, benchmark
├── Dockerfile
├── docker-compose.yml
└── .github/workflows/ci.yml
```

## Protokół PCS - skrót

```
Klient                          Serwer
  |--- TCP + TLS 1.3 ----------->|
  |--- AUTH_REQ (bcrypt hash) -->|
  |<-- AUTH_OK (session_token) --|
  |--- MSG_SEND ---------------->|--- MSG_BROADCAST --> inni klienci
  |--- PING ------------------->|
  |<-- PONG ---------------------|
  |--- BYE --------------------->|
```

Każda ramka: nagłówek 11 B + payload JSON + HMAC-SHA256 (32 B).

## Testy

```bash
# Wszystkie testy
pytest tests/ -q

# Tylko obciążeniowe
pytest tests/test_load.py -v

# Benchmark wydajności
python scripts/run_benchmark.py --quick
python scripts/run_benchmark.py          # pełny (50 klientów)
```

Szczegóły pomiarów: [PERFORMANCE.md](PERFORMANCE.md).

## CI/CD

GitHub Actions (`.github/workflows/ci.yml`):

- **test** - `pytest` na Python 3.12 i 3.13
- **benchmark** - szybki benchmark + artefakt JSON

Uruchamiane automatycznie przy push/PR do `main`/`master`.

## Logowanie

Serwer obsługuje logi konsolowe i plikowe:

```bash
python -m server.main \
  --certfile certs/server.crt \
  --keyfile certs/server.key \
  --log-level DEBUG \
  --log-file logs/pychat.log
```

Format logu:

```
2026-05-31 18:00:00 | INFO     | server.server          | auth_ok session=abc user=alice active=3
```

Logowane zdarzenia: połączenia, auth, wiadomości (bez treści), timeouty, błędy HMAC, replay, brute-force.

W Dockerze logi trafiają do `/app/data/logs/pychat.log` (wolumen `pychat-data`).

## Zmienne środowiskowe (Docker)

| Zmienna | Domyślnie | Opis |
|---|---|---|
| `PYCHAT_HOST` | `0.0.0.0` | Adres bind |
| `PYCHAT_PORT` | `9000` | Port PCS |
| `PYCHAT_LOG_LEVEL` | `INFO` | Poziom logów |
| `PYCHAT_LOG_FILE` | `/app/data/logs/pychat.log` | Plik logów |
| `PYCHAT_HMAC_SECRET` | `pychat-default-secret` | Fallback klucza HMAC |
| `PYCHAT_DEMO_USER` | `alice` | Użytkownik tworzony przy starcie |
| `PYCHAT_DEMO_PASSWORD` | `secret` | Hasło użytkownika demo |

