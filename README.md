# CertSearch

A tool for extracting subdomains from Certificate Transparency logs using
crt.sh's PostgreSQL database.

## Requirements

- Python 3.8+
- `psycopg2-binary`

## Installation

### Option 1 — Run with Python

```bash
git clone https://github.com/monteiroosh/certsearch.git
cd certsearch
pip install psycopg2-binary

python3 main.py example.com
```

### Option 2 — Standalone binary

Build a single executable and put it on your PATH:

```bash
pip install pyinstaller psycopg2-binary
pyinstaller --onefile --name certsearch main.py

# add it to /usr/local/bin
sudo cp dist/certsearch /usr/local/bin/certsearch
```

Then run it from anywhere:

```bash
certsearch example.com
```

## Usage

```bash
# one or more domains as arguments
certsearch example.com other.com

# read domains from stdin (one per line)
cat domains.txt | certsearch

```

Results are printed one subdomain per line, deduplicated.

## How it works

CertSearch connects directly to crt.sh's public PostgreSQL instance
(`certwatch`) and queries the `certificate_and_identities` table, matching
commonName (`2.5.4.3`) and `san:dNSName` entries. By default it returns only
non-expired certificates.

### Concurrency

When multiple domains are supplied (via arguments or stdin), they are processed
in parallel with a `ThreadPoolExecutor`. The workload is I/O-bound — almost all
time is spent waiting on the network and the remote database — and psycopg2
releases the GIL during those waits, so threads give a real speedup.

Concurrency is intentionally capped (`MAX_WORKERS = 5`) because crt.sh is a
free, shared service; the limit keeps the tool from overwhelming it. Each
worker opens its own connection (psycopg2 connections are not shared across
threads), and output/deduplication are guarded by a lock so lines never
interleave or duplicate.

### Pagination

Results are fetched in pages (`page_size = 10000`) using `LIMIT/OFFSET`, looping
until a page comes back empty. The inner query uses a stable
`ORDER BY certificate_id` — without a deterministic sort, `LIMIT/OFFSET` can
silently skip or repeat rows between pages, causing missing results with no
error.

### Wildcard subdomains

Wildcard certificate names such as `*.example.com` are normalized by stripping
the leading `*.`, so they collapse to their base domain (`example.com`) and
deduplicate against any exact match.

### Reliability

Each page is retried up to 5 times with exponential backoff, reconnecting on
failure. A per-statement timeout (`statement_timeout`) prevents a slow query
from hanging indefinitely.

## Options

`query_domain()` exposes these parameters (defaults shown):

| Parameter            | Default | Description                                  |
| -------------------- | ------- | -------------------------------------------- |
| `include_subdomains` | `True`  | Match `*.domain` in addition to `domain`     |
| `include_expired`    | `False` | Include expired certificates                 |
| `page_size`          | `10000` | Rows fetched per page                        |
| `timeout_sec`        | `15`    | Connection and statement timeout             |
| `max_retries`        | `5`     | Retry attempts per page                      |
