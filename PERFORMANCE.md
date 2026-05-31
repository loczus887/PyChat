# Analiza wydajności PyChat

## Metodologia

Benchmark uruchamia trzy scenariusze na lokalnym serwerze PCS (bez TLS, tryb testowy):

| Scenariusz | Opis | Metryka sukcesu |
|---|---|---|
| `concurrent_connections` | Równoległe logowanie N klientów | wszystkie sesje w stanie READY |
| `message_latency` | Pojedyncza wiadomość nadawca → odbiorca | średnia latencja < 100 ms |
| `broadcast_fanout` | Broadcast do N−1 odbiorców | czas dostarczenia < 100 ms |

Rate limit protokołu (10 req/s) jest respektowany - co 10 wiadomości wstrzymanie 1,05 s.

## Uruchomienie

```bash
# Szybki przebieg (CI, ~5 s)
python scripts/run_benchmark.py --quick

# Pełny przebieg (50 klientów, 20 wiadomości)
python scripts/run_benchmark.py

# Zapis wyników JSON
python scripts/run_benchmark.py --quick --output benchmarks/results.json
```

Wyniki pełnego obciążenia są też weryfikowane przez `pytest tests/test_load.py`.

## Wyniki referencyjne

Środowisko: Python 3.13, Windows 11, localhost, maj 2026.

### Tryb quick (CI)

| Scenariusz | Wynik | Limit |
|---|---|---|
| 10 równoległych połączeń | 0,004 s | wszystkie READY |
| Latencja wiadomości (średnia) | 0,09 ms | < 100 ms |
| Latencja wiadomości (p95) | 0,11 ms | - |
| Broadcast do 9 odbiorców | 0,37 ms | < 100 ms |

### Tryb full (docelowy MVP)

Parametry z dokumentacji Etap 2:

- ~50 jednoczesnych klientów
- opóźnienie < 100 ms w sieci lokalnej
- brak utraty wiadomości przy broadcast

Te kryteria są automatycznie sprawdzane w `tests/test_load.py`.

## CI/CD

Job `benchmark` w GitHub Actions uruchamia `--quick` po testach i publikuje artefakt `benchmark-results`.

