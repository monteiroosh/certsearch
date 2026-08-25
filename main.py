import psycopg2
import sys
import time
import logging
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
        ORDER BY cai.CERTIFICATE_ID
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
                 page_size=10000, timeout_sec=15, max_retries=5):

    conn, cursor = _connect(timeout_sec)
    base_delay = 0.1
    results = set()
    offset = 0

    try:
        while True:
            params = (include_expired, include_subdomains,
                      domain, domain, domain, domain, page_size, offset)

            rows = None
            last_err = None
            for attempt in range(1, max_retries + 1):
                try:
                    cursor.execute(QUERY_STR, params)
                    rows = cursor.fetchall()
                    break
                except psycopg2.Error as e:
                    last_err = e
                    log.info(f"page offset={offset} attempt {attempt} failed: {e}")
                    if attempt < max_retries:
                        time.sleep(base_delay * (2 ** (attempt - 1)))
                        try:
                            conn.close()
                        except Exception:
                            pass
                        conn, cursor = _connect(timeout_sec)
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
        conn.close()

    return results


def read_domains(argv):
    if len(argv) > 1:
        return [d.strip() for d in argv[1:] if d.strip()]
    if not sys.stdin.isatty():
        return [line.strip() for line in sys.stdin if line.strip()]
    return []


MAX_WORKERS = 5 


if __name__ == "__main__":
    domains = read_domains(sys.argv)
    if not domains:
        print("use: certsearch <domain1> <domain2> ...")
        print("     cat dominios.txt | certsearch")
        sys.exit(1)

    seen = set()
    print_lock = threading.Lock()

    def worker(domain):
        try:
            names = query_domain(domain)
        except psycopg2.Error as e:
            log.info(f"error querying {domain}: {e}")
            return
        
        with print_lock:
            for n in sorted(names):
                if n not in seen:
                    seen.add(n)
                    print(n, flush=True)

    workers = min(MAX_WORKERS, len(domains))
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(worker, d) for d in domains]
            for f in as_completed(futures):
                f.result()
    except KeyboardInterrupt:
        sys.exit(1)
