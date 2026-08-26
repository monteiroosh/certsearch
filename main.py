import psycopg2
import sys
import time
import logging
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)

CONN_STR = ("postgresql://guest@crt.sh:5432/certwatch"
            "?sslmode=disable&application_name=certsearch")

QUERY_STR = """
WITH myconstants (include_expired, include_subdomains) AS (
    VALUES (%s::bool, %s::bool)
),
ci AS (
    SELECT
        digest(sub.CERTIFICATE, 'sha256') sha256,
        min(sub.CERTIFICATE_ID) ID,
        min(sub.ISSUER_CA_ID) ISSUER_CA_ID,
        array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES
    FROM (
        SELECT *
        FROM certificate_and_identities cai, myconstants
        WHERE plainto_tsquery('certwatch', %s) @@ identities(cai.CERTIFICATE)
            AND (
                (NOT myconstants.include_subdomains AND cai.NAME_VALUE ILIKE (%s))
                OR
                (myconstants.include_subdomains AND (cai.NAME_VALUE ILIKE (%s) OR cai.NAME_VALUE ILIKE ('%%.' || %s)))
            )
            AND (
                cai.NAME_TYPE = '2.5.4.3'      -- commonName
                OR cai.NAME_TYPE = 'san:dNSName'
            )
            AND (
                myconstants.include_expired
                OR (
                    coalesce(x509_notAfter(cai.CERTIFICATE), 'infinity'::timestamp)
                        >= date_trunc('year', now() AT TIME ZONE 'UTC')
                    AND x509_notAfter(cai.CERTIFICATE) >= now() AT TIME ZONE 'UTC'
                )
            )
        LIMIT %s OFFSET %s
    ) sub
    GROUP BY sub.CERTIFICATE
)
SELECT array_to_string(ci.NAME_VALUES, chr(10)) NAME_VALUE
FROM ci;
"""

def _connect(timeout_sec):
    conn = psycopg2.connect(CONN_STR, connect_timeout=timeout_sec)
    conn.autocommit = True
    cursor = conn.cursor()
    cursor.execute(f"SET statement_timeout TO {timeout_sec * 1000};")
    return conn, cursor


def query_domain(domain, include_subdomains=True, include_expired=False,
                 page_size=15000, timeout_sec=15, max_retries=5):

    base_delay = 0.1
    results = set()
    offset = 0
    conn = cursor = None

    try:
        while True:
            params = (include_expired, include_subdomains,
                      domain, domain, domain, domain, page_size, offset)

            rows = None
            last_err = None
            for attempt in range(1, max_retries + 1):
                try:
                    if conn is None:
                        conn, cursor = _connect(timeout_sec)
                    cursor.execute(QUERY_STR, params)
                    rows = cursor.fetchall()
                    break
                except psycopg2.Error as e:
                    last_err = e
                    log.info(f"page offset={offset} attempt {attempt} failed: {e}")
                    # descarta a conexao (possivelmente morta); o proximo attempt reconecta
                    try:
                        if conn is not None:
                            conn.close()
                    except Exception:
                        pass
                    conn = cursor = None
                    if attempt < max_retries:
                        time.sleep(base_delay * (2 ** (attempt - 1)))
            else:
                raise last_err

            if not rows:
                break

            for row in rows:
                if row[0]:
                    for name in row[0].split("\n"):
                        if name.startswith("*."):
                            name = name[2:]
                        results.add(name)

            offset += page_size
    finally:
        if conn is not None:
            conn.close()

    return results


def read_domains(args):
    if args.domains:
        return [d.strip() for d in args.domains if d.strip()]
    if not sys.stdin.isatty():
        return [line.strip() for line in sys.stdin if line.strip()]
    return []


def args_parse():
    parser = argparse.ArgumentParser(
        prog="certsearch",
        description="Extract subdomains from CT Logs via crt.sh PostgresSQL database")
    parser.add_argument("domains", nargs="*",
                        help="domain(s) to search (or pipe one per line via stdin)")
    parser.add_argument("--include-expired", action="store_true", default=False,
                        help="include expired certificates (default: only valid ones)")
    parser.add_argument("--no-subdomains", dest="include_subdomains",
                        action="store_false", default=True,
                        help="match only the exact domain, not its subdomains")
    parser.add_argument("--workers", type=int, default=5,
                        help="max concurrent connections to crt.sh (default: 5)")
    parser.add_argument("--output", help="output file (default: stdout)", default=None)
    return parser.parse_args()


if __name__ == "__main__":
    args = args_parse()
    domains = read_domains(args)
    if not domains:
        print("use -h for help", file=sys.stderr)
        sys.exit(1)

    seen = set()
    print_lock = threading.Lock()
    out = open(args.output, "w") if args.output else sys.stdout

    def worker(domain):
        try:
            names = query_domain(domain,
                                 include_subdomains=args.include_subdomains,
                                 include_expired=args.include_expired)
        except psycopg2.Error as e:
            log.info(f"error querying {domain}: {e}")
            return

        with print_lock:
            for n in sorted(names):
                if n not in seen:
                    seen.add(n)
                    out.write(n + "\n")
                    out.flush()

    workers = min(args.workers, len(domains))
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(worker, d) for d in domains]
            for f in as_completed(futures):
                f.result()
    except KeyboardInterrupt:
        sys.exit(1)
    finally:
        if args.output:
            out.close()