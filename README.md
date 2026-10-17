# Xikin

**Tor / dark-web OSINT toolkit** — verify Tor, rotate circuits, search 10+ onion
search engines in parallel, fetch `.onion` pages, and run LLM-assisted or fully
offline threat-intelligence investigations from the command line. Also ships as
a drop-in agent skill (`SKILL.md`).

```
python3 check_tor.py                                   # verify Tor, show exit IP
python3 check_engines.py                               # which indexes are alive
python3 search.py --query "ransomware healthcare"      # parallel multi-engine search
python3 fetch.py --url "http://....onion/" --links     # fetch any onion page
python3 ask.py --query "..." --mode ransomware --file page.txt
python3 pipeline.py --query "acme.com credential leak" --mode corporate --out report.md
python3 renew.py                                       # new circuit / identity
```

> **Scope.** Xikin is built for lawful OSINT, threat intelligence and security
> research. Accessing dark-web content may be illegal in some jurisdictions
> regardless of intent. Tor is operational security, not legal protection.
> You are responsible for how you use this tool.

---

## Contents

1. [What it does](#what-it-does)
2. [Requirements](#requirements)
3. [Install](#install)
4. [Docker](#docker)
5. [Web platform](#web-platform)
6. [Configuration](#configuration)
7. [The commands](#the-commands)
8. [Investigation flows](#investigation-flows)
9. [Analysis modes](#analysis-modes)
10. [Search engines](#search-engines)
11. [Architecture](#architecture)
12. [Safety](#safety)
13. [Troubleshooting](#troubleshooting)
14. [Using it as an agent skill](#using-it-as-an-agent-skill)
15. [Credits](#credits)

---

## What it does

| Command | What it does |
|---|---|
| `check_tor.py` | Verify Tor is active, show the current exit IP |
| `renew.py` | Rotate the Tor circuit — new exit node, new identity |
| `check_engines.py` | Ping every registered engine, show status + latency |
| `search.py` | Query up to 10 dark-web engines in parallel, deduplicate + corroborate results |
| `fetch.py` | Fetch any `.onion` or clearnet URL through Tor (title, text, links, optional IOCs) |
| `ask.py` | LLM OSINT analysis of scraped content (4 modes) |
| `pipeline.py` | Full pipeline: refine → search → filter → scrape → IOC extraction → analyse → report |
| `iocs.py` | Deterministic IOC extraction with STIX 2.1 / MISP / CSV export |
| `evidence.py` | Verify the tamper-evident sha256 hash chain of every fetch |
| `doctor.py` | Security preflight: leaks, isolation, control port, evidence integrity |
| `python -m xikin.web` | Modern web platform — dashboard, live run timeline, IOC explorer, evidence view |
| **Tools** (web) | Fetch a URL, static-analyse a file (hash/type/entropy/strings/IOC), search indexes and optional VirusTotal lookup |

Everything is also importable as a library:

```python
import xikin

xikin.check_tor()                                # {"tor_active": True, "exit_ip": ...}
xikin.search("lockbit hospital leak")            # [{title, url, engine, score, corroboration}, ...]
xikin.search_detailed("lockbit hospital leak")   # per-engine status + results
xikin.fetch("http://example.onion/")             # {ok, status, title, text, links, sha256}
xikin.extract_iocs({"page": scraped_text})       # {onion_url: [...], email: [...], ...}
xikin.EvidenceLog().verify()                     # {"ok": True, "entries": 42, ...}
xikin.doctor()                                   # security preflight report
xikin.run_pipeline("acme.com leak", mode="corporate")
```

## Requirements

> Using Docker? Skip this section — the image bundles Tor and the Python
dependencies. See [Docker](#docker).

- **Python 3.9+**
- **Tor** running locally — SOCKS5 on `127.0.0.1:9050`, control port on `127.0.0.1:9051`
- Python packages: `requests[socks]`, `beautifulsoup4`, `python-dotenv`, `stem`
- **Optional:** an LLM key (or local Ollama) — only `ask.py` and the analysis
  step of `pipeline.py` need it. `check_tor`, `renew`, `check_engines`, `search`
  and `fetch` are fully offline.

## Install

### Tor

**macOS:**

```bash
brew install tor
cat > /tmp/xikin_torrc << 'EOF'
SocksPort 9050 IsolateSOCKSAuth
ControlPort 9051
CookieAuthentication 1
DataDirectory /tmp/xikin_tor
EOF
tor -f /tmp/xikin_torrc &
```

> `IsolateSOCKSAuth` is what makes per-query circuit isolation real. Without it
> Tor ignores the isolation credentials xikin sends (everything still works,
> `doctor.py` warns you).

**Linux (Debian/Ubuntu):**

```bash
sudo apt install tor
sudo sh -c 'echo "ControlPort 9051" >> /etc/tor/torrc'
sudo sh -c 'echo "CookieAuthentication 1" >> /etc/tor/torrc'
sudo systemctl restart tor
# then set TOR_DATA_DIR=/var/lib/tor in .env
```

Then install Xikin in a virtualenv:

```bash
git clone <your-repo> xikin && cd xikin     # or just: cd into this folder
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env                        # optional: add an LLM key
python3 check_tor.py
```

## Docker

Everything — Tor daemon, xikin, cache and the evidence log — runs inside one
non-root container. No Tor or Python setup on the host, nothing published on
host ports.

### Build

```bash
cp .env.example .env        # optional: add LLM keys
mkdir -p reports
docker build -t xikin:local .
```

### One-shot runs

```bash
docker run --rm xikin:local                          # security preflight (doctor)
docker run --rm xikin:local check_tor.py
docker run --rm xikin:local search.py --query "ransomware leak" --max 10
docker run --rm xikin:local fetch.py --url "http://....onion/" --links --iocs
docker run --rm xikin:local pipeline.py --query "acme.com leak" --scrape 5
```

### With compose (persistent cache/evidence + report folder)

```bash
cp .env.example .env
mkdir -p reports
docker compose build
docker compose run --rm xikin doctor.py
docker compose run --rm xikin pipeline.py --query "acme.com leak" \
  --mode corporate --scrape 6 --out /reports/acme.md
docker compose run --rm xikin evidence.py --verify
```

- `xikin-data` volume — SQLite cache + hash-chained evidence log, survives runs
- `tor-data` volume — Tor state, faster bootstrap after the first run
- `./reports` bind mount — write reports with `--out /reports/...`
- hardening: `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`, `/tmp` on tmpfs
- Tor and its control port stay inside the container; only outbound Tor traffic
  leaves it
- environment comes from `.env` (`env_file`); pass one-off values with `-e KEY=...`

### How the entrypoint works

The image's entrypoint starts Tor, waits for `Bootstrapped 100%`, then runs your
argument — `search.py ...` (short name), `python ...`, `bash` for a shell, or
`tor` to run the daemon in the foreground. With no argument it runs `doctor.py`.
`SocksPort 9050 IsolateSOCKSAuth` is preconfigured, so per-query circuit
isolation works out of the box.


## Web platform

`python -m xikin.web` serves a modern, self-hosted UI around the same pipeline —
single service, no CDN assets, no JavaScript build step.

```bash
export XIKIN_WEB_TOKEN=$(openssl rand -hex 24)   # required beyond localhost
python -m xikin.web
# → http://127.0.0.1:8080
```

With Docker:

```bash
# add XIKIN_WEB_TOKEN=<long random value> to .env first
docker compose up -d web      # published on 127.0.0.1:8080 only
# if 8080 is taken: XIKIN_WEB_PUBLISH_PORT=8081 docker compose up -d web
```

Screens: **Dashboard** (Tor, engine health, evidence chain, recent runs),
**New investigation** (query, mode, engines, scrape depth), **Live run**
(SSE timeline with progress), **Run detail** (results with corroboration, IOC
groups, scraped pages, report, STIX/MISP/CSV export), **Tools** (fetch a URL
through Tor, static file analysis, index search, optional VirusTotal lookup),
**Quick check** on the dashboard (artifact integrity, evidence verification,
top indicators and a live Tor re-check of the run's targets), a **dashboard URL
checker** (status, title, hash and indicator count without leaving the page),
**quick-start investigation form**, aggregate **stats / alerts / indicator
overview / recent evidence** panels,
**Evidence explorer** (hash-chain verification and recent records) and
**Settings** (runtime, storage, cache reset).

**Tools — VirusTotal-style triage, safely:**

- **Fetch URL** — retrieves a page through Tor and shows title, text, links,
  IOCs and the body SHA-256; optional search for the URL across indexes.
- **Analyse file** — hashes (SHA-256/SHA-1/MD5), type detection, entropy,
  printable strings and extracted IOCs. The file is processed **in memory**,
  never executed, uploaded or written to disk; a hash record is appended to the
  evidence chain. Strings that trip the safety filter are withheld.
- **VirusTotal (optional)** — with `VT_API_KEY` set, Xikin looks up the SHA-256
  or URL (clearnet, hash/URL only — the file is never uploaded) and shows
  detections, reputation, names and categories. No key: the option is disabled.

Security posture:

- **RBAC**: `admin` / `analyst` / `viewer` accounts (PBKDF2-SHA256 passwords) plus
  the legacy `XIKIN_WEB_TOKEN` admin bootstrap; signed, HttpOnly,
  SameSite=Strict sessions
- **Alert acknowledgement**: per-user, signature-scoped (an alert resurfaces if
  its state changes or after 24 h)
- **Saved filters** for the investigations list (per user)
- **Dashboard PDF export** (`/dashboard.pdf`)
- **Webhook retries + HMAC signature**: up to 4 attempts (1/4/9 s backoff) and
  `X-Xikin-Signature: sha256=<hex>` over `<timestamp>.<body>` when
  `XIKIN_WEBHOOK_SECRET` is set
- CSRF double-submit on every POST; strict CSP without inline scripts/styles or external assets
- one investigation at a time; run IDs are server-validated UUIDs
- scraped content is never rendered as HTML; secrets are masked in the UI
- URLs are copy-only by design — open `.onion` links in Tor Browser
- refuses to start on a non-loopback host without a token

JSON API: `GET /api/runs/{id}`, `GET /api/runs/{id}/events` (SSE),
`GET /runs/{id}/export/{stix|misp|csv|json}`, `GET /healthz`.


## Configuration

All settings come from environment variables or a `.env` file in this folder
(see `.env.example`):

| Variable | Default | Purpose |
|---|---|---|
| `TOR_SOCKS_HOST` / `TOR_SOCKS_PORT` | `127.0.0.1:9050` | SOCKS5 proxy |
| `TOR_CONTROL_HOST` / `TOR_CONTROL_PORT` | `127.0.0.1:9051` | used by `renew.py` |
| `TOR_CONTROL_PASSWORD` | — | when torrc uses `HashedControlPassword` |
| `TOR_DATA_DIR` | — | DataDirectory path, enables cookie auth |
| `TOR_TIMEOUT` | `45` | read timeout (s) per request |
| `XIKIN_SEARCH_WORKERS` | `8` | parallel engine queries |
| `XIKIN_SCRAPE_WORKERS` | `5` | parallel page fetches |
| `XIKIN_MAX_CHARS` | `8000` | extracted text cap per page |
| `XIKIN_FETCH_CACHE_TTL` | `600` | fetch cache TTL (s) |
| `XIKIN_SEARCH_CACHE_TTL` | `1800` | search cache TTL (s) |
| `XIKIN_DB_PATH` | `~/.xikin/xikin.db` | SQLite cache + engine history |
| `XIKIN_WEB_HOST` / `XIKIN_WEB_PORT` | `127.0.0.1:8080` | web bind address |
| `XIKIN_WEB_TOKEN` | — | required when binding beyond localhost |
| `XIKIN_WEB_RUNS` | `~/.xikin/web/runs` | run metadata/results/events |
| `VT_API_KEY` | — | optional VirusTotal hash/URL enrichment (clearnet) |
| `XIKIN_WATCH_DB` | `~/.xikin/web/watch.db` | watch-job storage |
| `XIKIN_WEBHOOK_URL` | — | JSON webhook for new watch results (clearnet POST) |
| `XIKIN_WEBHOOK_SECRET` | — | HMAC-SHA256 signing key for webhook bodies |
| `XIKIN_STATE_DB` | `~/.xikin/web/state.db` | users, alert acks, saved filters |
| `XIKIN_SESSION_SECRET` | auto-generated | session signing key (stored in state DB) |
| `XIKIN_ISOLATE` | `1` | unique SOCKS credentials per query (needs `IsolateSOCKSAuth`) |
| `XIKIN_EVIDENCE` | `1` | append every fetch to the hash-chained evidence log |
| `XIKIN_EVIDENCE_LOG` | `~/.xikin/evidence.jsonl` | evidence log location |
| `LLM_PROVIDER` | `openai` | `openai \| anthropic \| gemini \| ollama \| llamacpp` |
| `OPENAI_API_KEY` / `OPENAI_MODEL` | — / `gpt-4o-mini` | OpenAI |
| `ANTHROPIC_API_KEY` / `ANTHROPIC_MODEL` | — / `claude-sonnet-4-5` | Anthropic |
| `GEMINI_API_KEY` / `GEMINI_MODEL` | — / `gemini-2.5-flash` | Google Gemini |
| `OLLAMA_BASE_URL` / `OLLAMA_MODEL` | `127.0.0.1:11434` / `llama3.2` | local, no key |

No LLM key? Set `LLM_PROVIDER=ollama` with Ollama running, or just use the
offline fallbacks: the pipeline still refines (stopword-based), filters
(BM25-style scoring) and writes a raw-data report.

## The commands

### `check_tor.py`

```
$ python3 check_tor.py
✓ Tor active
  Exit IP : 185.220.101.20
  Is Tor  : True
```

Exits `1` when Tor is unreachable. Add `--json` for machine output.

### `renew.py`

```
$ python3 renew.py
Rotating Tor circuit...
✓ Identity renewed — new Tor circuit established
  Exit IP : 185.220.101.20 → 45.141.215.9
```

Auth is attempted in order: `TOR_CONTROL_PASSWORD` → automatic (null/cookie) →
cookie file from `TOR_DATA_DIR` / common system paths.

### `check_engines.py`

```
$ python3 check_engines.py
ALIVE  9/12
──────────────────────────────────────────────
  ✓  Ahmia                670ms  ██
  ✓  Tor66                749ms  ██
  ...
DOWN   3/12
  ✗  Onionway         timeout — the hidden service may be offline
```

Flags: `--cached MINUTES` (reuse a recent check), `--engines NAME...`,
`--list`, `--json`.

### `search.py`

```
$ python3 search.py --query "credential dump" --engines Ahmia Tor66 OnionLand --max 30
  #  ENGINE              CR  TITLE                              URL
  1  Ahmia               3   Some market paste index            http://....onion/...
```

`CR` is corroboration: how many independent engines returned the same host (a
relevance bonus in scoring — index spam usually appears on one engine only).
Flags: `--engines`, `--max`, `--workers`, `--no-cache`, `--json`.
Use short keyword queries (3–5 words) — indexes handle keywords far better
than sentences.

### `fetch.py`

```
$ python3 fetch.py --url "http://....onion/" --links
✓ Some hidden service
  Status  : 200
  URL     : http://....onion/
...
```

Flags: `--links`, `--max-chars N`, `--no-cache`, `--json`.
`status: 0` means the service was unreachable/offline.

### `ask.py`

```
$ python3 ask.py --query "LockBit hospital" --mode ransomware --file /tmp/pages.txt
```

Flags: `--mode`, `--content` or `--file`, `--custom "..."`, `--json`.

### `pipeline.py`

```
$ python3 pipeline.py --query "acme.com credentials leak" --mode corporate --out report.md
[1] Verifying Tor…
[2] Checking search engines…
[3] Refining query…
[4] Searching 9 engine(s)…
[5] Filtering to the top 30…
[6] Scraping 10 page(s)…
[7] Running LLM analysis (corporate)…
[8] Report written to /.../report.md
```

Flags: `--mode`, `--max N`, `--scrape N`, `--engines NAME...`, `--custom "..."`,
`--out FILE`, `--clear-cache`, `--json`, `--version`.

The report always ends with a deterministic **IOC appendix** (no LLM involved)
and, when secrets are detected in scraped pages, they are masked.

### `iocs.py` — deterministic IOC extraction

```
$ python3 fetch.py --url "http://....onion" --json | python3 -c "import json,sys;print(json.load(sys.stdin)['text'])" | python3 iocs.py -f -
**Bitcoin addresses** (1)
- `1FyCD8kp9ekiTTgdyhFtZRgzR1QCHV4i84`
**Monero addresses** (1)
- `48FgeW4fUpyjPDGxJdHaA441F5c9szYtLSVWbNv8T3ZXe9ZN3iLUSSdASof2vDQqdbgRYom9aMeQMWPQkr3SPZUJE2uM8fc`
```

Export for your CTI platform:

```bash
python3 pipeline.py --query "acme.com leak" --scrape 8 --out report.md
python3 iocs.py -f scraped_pages.txt --format stix --query "acme.com leak" --out acme.stix.json
python3 iocs.py -f scraped_pages.txt --format misp --out acme.misp.json
python3 iocs.py -f scraped_pages.txt --format csv  --out acme.csv
```

Types extracted: onion URLs/hosts, clearnet URLs, IPv4, emails, BTC/XMR/ETH
wallets, SHA-256/SHA-1/MD5, CVEs, PGP fingerprints, and secrets (AKIA/sk-/ghp_/
xox keys, private-key blocks, `password:` assignments). Secrets are masked in
markdown output; machine formats carry raw values for hunting.

### `evidence.py` — tamper-evident fetch log

```
$ python3 evidence.py --verify
✓ Evidence chain intact — 42 entries
  Last hash : 33f6f6e33227b9d5aef9917488ebcd8c3ac376b6e2517ca4957385d7b3953309
```

Every fetch appends `{ts, url, status, sha256(body), bytes, prev, entry_hash}`.
If anyone edits, deletes or reorders a record, verification fails and names the
broken line — useful when scraped evidence has to hold up later.

### `doctor.py` — security preflight

```
$ python3 doctor.py
✓  tor.socks_port         127.0.0.1:9050 accepts connections
✓  tor.identity           exit IP 23.191.200.107 confirmed as Tor
✓  tor.control_port       0.4.9.14 — 13 circuits built
✓  leak.onion_dns         canary .onion does not resolve locally (remote DNS intact)
✓  leak.proxy_env         no ambient proxy environment variables
✓  privacy.isolation      IsolateSOCKSAuth found in /tmp/xikin_torrc — per-query circuits enforced
✓  storage.cache          SQLite cache writable (/Users/you/.xikin/xikin.db)
✓  forensics.evidence     hash chain intact — 3 entries
!  analysis.llm           no LLM provider configured — offline fallbacks will be used
```

Exits `1` on any failure. Run it once after install and after any Tor config
change.

## Investigation flows

**Credential / corporate exposure**

```bash
python3 pipeline.py --query "acme.com email passwords" --mode corporate \
  --scrape 10 --out acme_leak_report.md
```

**Ransomware intelligence**

```bash
python3 check_engines.py --cached 30
python3 search.py --query "lockbit healthcare" --engines Ahmia Tor66 OnionLand --max 40
python3 fetch.py --url "http://..." --links > /tmp/page.json
python3 ask.py --query "lockbit healthcare" --mode ransomware --file /tmp/page.json
```

**Personal exposure check**

```bash
python3 pipeline.py --query "john.smith@example.com personal data" \
  --mode personal_identity --scrape 8
```

**Manual step-by-step**

```bash
python3 doctor.py
python3 check_tor.py && python3 check_engines.py
python3 search.py --query "hospital ransomware 2026" --engines Ahmia Tor66 --max 40
python3 fetch.py --url "http://..." --links --iocs
python3 ask.py --query "hospital ransomware 2026" --mode threat_intel --content "..."
python3 evidence.py --verify
python3 renew.py
```

## Analysis modes

| Mode | Focus | Report sections |
|---|---|---|
| `threat_intel` (default) | General dark-web OSINT, IoCs, actors | Artifacts · Insights · Next steps |
| `ransomware` | Groups, leak sites, C2, hashes, TTPs, ransoms | Malware indicators · Actor profile · Insights · Next steps |
| `personal_identity` | PII exposure: emails, passwords, IDs, breaches | Artifacts · Sources · Risk assessment · Next steps |
| `corporate` | Leaked creds, code, documents, access brokers | Artifacts · Broker activity · Business impact · Next steps |

## Search engines

10 engines ship out of the box, seeded from the public
[Robin](https://github.com/apurvsinghgautam/robin) catalogue and verified-live
onion addresses:

Ahmia · OnionLand · Amnesia · Torland · Excavator ·
Onionway · Tor66 · OSS · Torgol · TheDeepSearches

Two otherwise popular options are intentionally **not** included because they
cannot be scraped without a real browser: DuckDuckGo's onion `/html/` endpoint
answers HTTP 406 to non-browser clients, and Ahmia's clearnet `/search/` now
serves a "non-JavaScript version not deployed" interstitial. Xikin detects such
interstitials (`looks_js_only`) and marks the engine down instead of reporting
navigation links as results. You can add your own engines through `engines.json`.

Onion addresses rotate, die and get squatted. Two safety rules:

1. Run `check_engines.py` before a big session and use the alive set.
2. Change addresses only from a source you trust (e.g. dark.fail), then put
   them in `engines.json` (copy `engines.example.json`) — same-name entries
   override the built-ins, new names are appended. Never trust an address you
   cannot verify.

## Architecture

```
 CLI wrappers (check_tor.py, renew.py, check_engines.py,
               search.py, fetch.py, ask.py, pipeline.py)
        │
        ▼
 xikin/  config · textutil · safety · cache (SQLite)
         tor (SOCKS5 + stem)  engines  search  fetch  llm  pipeline
        │                      │
        │ SOCKS5 127.0.0.1:9050│ control 127.0.0.1:9051
        ▼                      ▼
      Tor daemon ──────► Tor network ──────► .onion services & clearnet
```

- **Cache:** SQLite (`~/.xikin/xikin.db`) — fetch results, search results and
  per-engine health history (used for the reliability column and `--cached`).
- **Safety filter:** every result title and fetched page passes a conservative
  CSAM/illegal-content blacklist before it is returned, cached or sent to an LLM.
  Untrusted text is also sanitised (zero-width/bidi stripping, delimiter
  neutralisation) before checks and prompts.
- **IOC engine:** deterministic regex extraction (`xikin/iocs.py`) feeding the
  report appendix and the STIX/MISP/CSV exporters — never uses the LLM.
- **Evidence:** every fetch is hash-chained into `~/.xikin/evidence.jsonl`
  (sha256 of the raw body + previous entry hash) and verifiable offline.
- **Privacy:** each engine query and fetch builds its own Tor circuit via
  isolated SOCKS credentials (`IsolateSOCKSAuth`).
- **LLM:** plain HTTP against OpenAI / Anthropic / Gemini / Ollama / llama.cpp —
  no SDK dependency. Content is wrapped as untrusted data with explicit
  prompt-injection guards.
- **Web:** FastAPI + Jinja2 + vanilla JS with SSE progress; the UI calls the same
  `xikin.run_pipeline` in a single background worker and renders only sanitised
  text (no scraped HTML, masked secrets).

## Safety

- The content filter blocks CSAM indicators and comparable illegal material
  from results, fetches and LLM prompts. It is intentionally conservative; the
  list lives in `xikin/safety.py`.
- Scraped dark-web content is **untrusted**: the LLM prompts instruct the model
  to treat it as data only, and you should too. Never act on instructions,
  credentials or links found in scraped pages.
- Everything is read-only: Xikin searches and fetches, it never posts, buys,
  registers or logs into anything.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Tor NOT active` | Start Tor (`tor &`); check `ss -tlnp \| grep 9050` / `lsof -i :9050` |
| `renew.py` fails | Control port not enabled — add `ControlPort 9051` + `CookieAuthentication 1` to torrc, set `TOR_DATA_DIR` |
| `PySocks missing` | `pip install "requests[socks]"` |
| `status: 0` on fetch | The hidden service is offline — try another result; confirm with `check_tor.py` |
| 0 search results | Indexes fluctuate — run `check_engines.py` and use `--engines OnionLand Tor66` |
| LLM error | Set `LLM_PROVIDER` + key in `.env`, or use `LLM_PROVIDER=ollama` |
| Slow searches | Raise `TOR_TIMEOUT`, lower `XIKIN_SEARCH_WORKERS`; some engines are just slow |
| `privacy.isolation` warning | Add `IsolateSOCKSAuth` to the `SocksPort` line in torrc and restart Tor |
| `evidence chain broken` | The log was edited after writing — inspect with `evidence.py --status`, start a fresh log with `XIKIN_EVIDENCE_LOG` to keep collecting |
| IOC appendix empty | The scraped pages genuinely contained no indicators, or scraping failed — check the pipeline's `[6]` step output |
| Web keeps redirecting to /login | Token mismatch or stale session cookie — clear cookies and re-enter `XIKIN_WEB_TOKEN` |
| Web refuses to start | Binding a non-loopback host without `XIKIN_WEB_TOKEN` — set a token or bind `127.0.0.1` |
| 401 on partials/API | Session expired — reload the page and sign in again |

## Using it as an agent skill

Copy this folder into your agent's skills directory (Claude Code / opencode /
OpenClaw-compatible layout):

```bash
cp -r . ~/.config/opencode/skills/xikin     # opencode
# or
cp -r . ~/.claude/skills/xikin              # Claude Code
```

`SKILL.md` describes the commands and the operating rules for the agent.

## Credits

- [Robin](https://github.com/apurvsinghgautam/robin) by @apurvsinghgautam —
  dark-web search engine catalogue and OSINT pipeline patterns (MIT)
- [SICRY / OnionClaw](https://github.com/JacobJandon/Sicry) — command-surface
  inspiration (MIT)
- [Tor Project](https://www.torproject.org/) — the network itself
- [dark.fail](https://dark.fail) — .onion address verification

This is a clean-room implementation: code and naming are original, engine
addresses are public facts sourced from the above projects.

## License

MIT License — see [LICENSE](LICENSE).
