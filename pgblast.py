#!/usr/bin/env python3
"""
pgblast — PostgreSQL Security Scanner
Purpose: Credential bruteforce + post-auth recon + privesc checks for authorized pentests.
Usage:   python3 pgblast.py --hosts hosts.txt --users users.txt --passwords passwords.txt [options]
"""

import argparse
import json
import sys
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    sys.exit("[!] psycopg2 not found. Run: pip install psycopg2-binary")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    severity: str   # CRITICAL / HIGH / MEDIUM / INFO
    title: str
    detail: str


@dataclass
class HostResult:
    host: str
    port: int
    open: bool = False
    credentials: list = field(default_factory=list)   # list of (user, pass) that worked
    recon: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)      # list of Finding
    enumeration: dict = field(default_factory=dict)   # (user, pass) -> db enumeration tree


# ---------------------------------------------------------------------------
# Recon queries
# ---------------------------------------------------------------------------

RECON_QUERIES = {
    "version":         "SELECT version();",
    "current_user":    "SELECT current_user;",
    "session_user":    "SELECT session_user;",
    "is_superuser":    "SELECT usesuper FROM pg_user WHERE usename = current_user;",
    "databases":       "SELECT datname FROM pg_database ORDER BY datname;",
    "schemas":         "SELECT schema_name FROM information_schema.schemata ORDER BY schema_name;",
    "roles":           "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin FROM pg_roles ORDER BY rolname;",
    "extensions":      "SELECT extname, extversion FROM pg_extension ORDER BY extname;",
    "config_file":     "SHOW config_file;",
    "hba_file":        "SHOW hba_file;",
    "data_directory":  "SHOW data_directory;",
    "ssl":             "SHOW ssl;",
    "log_connections": "SHOW log_connections;",
    "log_hostname":    "SHOW log_hostname;",
    "listen_addresses":"SHOW listen_addresses;",
}


# ---------------------------------------------------------------------------
# Privilege escalation checks
# ---------------------------------------------------------------------------

PRIVESC_CHECKS = [
    {
        "id": "SUPER_USER",
        "title": "Session has superuser privileges",
        "severity": "CRITICAL",
        "query": "SELECT usesuper FROM pg_user WHERE usename = current_user;",
        "vulnerable": lambda rows: rows and rows[0][0] is True,
        "detail": "This account is a PostgreSQL superuser — full DB and OS-level access possible.",
    },
    {
        "id": "PG_SHADOW_READABLE",
        "title": "pg_shadow (password hashes) readable",
        "severity": "CRITICAL",
        "query": "SELECT usename, passwd FROM pg_shadow LIMIT 1;",
        "vulnerable": lambda rows: rows is not None,
        "detail": "Can read pg_shadow — password hashes exposed. Offline cracking possible.",
    },
    {
        "id": "COPY_PROGRAM",
        "title": "COPY TO/FROM PROGRAM (OS command execution) available",
        "severity": "CRITICAL",
        "query": "COPY (SELECT 1) TO PROGRAM 'id';",
        "vulnerable": lambda rows: rows is not None,
        "detail": "COPY TO PROGRAM executes OS commands as the postgres OS user.",
    },
    {
        "id": "PG_READ_SERVER_FILES",
        "title": "pg_read_server_files role or superuser file read",
        "severity": "HIGH",
        "query": "SELECT pg_read_file('/etc/hostname');",
        "vulnerable": lambda rows: rows is not None,
        "detail": "Can read arbitrary server-side files via pg_read_file().",
    },
    {
        "id": "PG_EXECUTE_SERVER_PROGRAM",
        "title": "pg_execute_server_program privilege",
        "severity": "HIGH",
        "query": "SELECT pg_catalog.pg_has_role(current_user, 'pg_execute_server_program', 'USAGE');",
        "vulnerable": lambda rows: rows and rows[0][0] is True,
        "detail": "Role allows executing server-side programs via COPY PROGRAM.",
    },
    {
        "id": "PG_WRITE_SERVER_FILES",
        "title": "pg_write_server_files privilege (arbitrary file write)",
        "severity": "HIGH",
        "query": "SELECT pg_catalog.pg_has_role(current_user, 'pg_write_server_files', 'USAGE');",
        "vulnerable": lambda rows: rows and rows[0][0] is True,
        "detail": "Role allows writing arbitrary files on the server.",
    },
    {
        "id": "CREATEROLE",
        "title": "CREATEROLE privilege (role escalation)",
        "severity": "HIGH",
        "query": "SELECT rolcreaterole FROM pg_roles WHERE rolname = current_user;",
        "vulnerable": lambda rows: rows and rows[0][0] is True,
        "detail": "Can create roles including granting membership in existing high-privilege roles.",
    },
    {
        "id": "CREATEDB",
        "title": "CREATEDB privilege",
        "severity": "MEDIUM",
        "query": "SELECT rolcreatedb FROM pg_roles WHERE rolname = current_user;",
        "vulnerable": lambda rows: rows and rows[0][0] is True,
        "detail": "Can create databases — may expose data or enable lateral movement.",
    },
    {
        "id": "SECURITY_DEFINER_FUNCS",
        "title": "SECURITY DEFINER functions accessible to current user",
        "severity": "MEDIUM",
        "query": (
            "SELECT routine_name, routine_schema "
            "FROM information_schema.routines "
            "WHERE security_type = 'DEFINER' "
            "AND routine_schema NOT IN ('pg_catalog','information_schema') "
            "LIMIT 20;"
        ),
        "vulnerable": lambda rows: rows and len(rows) > 0,
        "detail": "SECURITY DEFINER functions run with the owner's privileges — potential escalation if misconfigured.",
    },
    {
        "id": "EXTENSION_CREATE",
        "title": "Can CREATE EXTENSION (potential for untrusted extension load)",
        "severity": "MEDIUM",
        "query": "SELECT has_database_privilege(current_database(), 'CREATE');",
        "vulnerable": lambda rows: rows and rows[0][0] is True,
        "detail": "CREATE privilege on database may allow loading extensions depending on superuser config.",
    },
    {
        "id": "LARGE_OBJECT_READ",
        "title": "Large Object file read (lo_export)",
        "severity": "HIGH",
        "query": "SELECT lo_import('/etc/hostname') AS oid;",
        "vulnerable": lambda rows: rows is not None,
        "detail": "lo_import reads server-side files into large objects — potential data exfil path.",
    },
]


# ---------------------------------------------------------------------------
# Core scanner logic
# ---------------------------------------------------------------------------

def is_port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def try_login(host: str, port: int, user: str, password: str, timeout: float):
    """Returns psycopg2 connection on success, None on failure."""
    try:
        conn = psycopg2.connect(
            host=host, port=port, user=user, password=password,
            dbname="postgres", connect_timeout=int(timeout),
            sslmode="prefer",
        )
        conn.set_session(readonly=False, autocommit=True)
        return conn
    except psycopg2.OperationalError:
        return None


def run_query(conn, sql: str):
    """Run a query, return rows or None on error."""
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            try:
                return cur.fetchall()
            except psycopg2.ProgrammingError:
                return []
    except Exception:
        return None


def collect_recon(conn: "psycopg2.connection") -> dict:
    data = {}
    for key, sql in RECON_QUERIES.items():
        rows = run_query(conn, sql)
        if rows is not None:
            data[key] = [list(r) for r in rows]
    return data


def check_privesc(conn: "psycopg2.connection") -> list:
    findings = []
    for check in PRIVESC_CHECKS:
        rows = run_query(conn, check["query"])
        try:
            vulnerable = check["vulnerable"](rows)
        except Exception:
            vulnerable = False
        if vulnerable:
            findings.append(Finding(
                severity=check["severity"],
                title=check["title"],
                detail=check["detail"],
            ))
    return findings


# ---------------------------------------------------------------------------
# Database / table enumeration
# ---------------------------------------------------------------------------

# Databases the current user can actually CONNECT to (excludes templates)
_SQL_CONNECTABLE_DBS = """
SELECT datname
FROM pg_database
WHERE has_database_privilege(current_user, datname, 'CONNECT')
  AND datname NOT IN ('template0', 'template1')
ORDER BY datname;
"""

# Schemas in the current database the user has USAGE on, excluding system schemas
_SQL_ACCESSIBLE_SCHEMAS = """
SELECT schema_name
FROM information_schema.schemata
WHERE has_schema_privilege(current_user, schema_name, 'USAGE')
  AND schema_name NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
ORDER BY schema_name;
"""

# Tables and views in accessible schemas where the user holds at least SELECT
_SQL_ACCESSIBLE_TABLES = """
SELECT
    t.table_schema,
    t.table_name,
    t.table_type,
    array_to_string(
        ARRAY(
            SELECT privilege_type
            FROM information_schema.role_table_grants g
            WHERE g.table_schema = t.table_schema
              AND g.table_name   = t.table_name
              AND g.grantee IN (current_user, 'PUBLIC')
        ), ', '
    ) AS privileges
FROM information_schema.tables t
WHERE t.table_schema NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
  AND has_table_privilege(
        current_user,
        quote_ident(t.table_schema) || '.' || quote_ident(t.table_name),
        'SELECT'
      )
ORDER BY t.table_schema, t.table_name;
"""


def enumerate_access(
    host: str, port: int, user: str, password: str, timeout: float
) -> dict:
    """
    Returns a nested dict describing every database/schema/table the credential
    can reach:

        {
          "mydb": {
            "public": [
              {"table": "users", "type": "BASE TABLE", "privileges": "SELECT, INSERT"},
              ...
            ]
          },
          ...
        }
    """
    # Connect to the default 'postgres' DB to discover which DBs are accessible
    conn = try_login(host, port, user, password, timeout)
    if conn is None:
        return {}

    db_rows = run_query(conn, _SQL_CONNECTABLE_DBS)
    conn.close()

    if not db_rows:
        return {}

    tree = {}

    for (dbname,) in db_rows:
        # Open a fresh connection to each accessible database
        try:
            db_conn = psycopg2.connect(
                host=host, port=port, user=user, password=password,
                dbname=dbname, connect_timeout=int(timeout),
                sslmode="prefer",
            )
            db_conn.set_session(readonly=True, autocommit=True)
        except psycopg2.OperationalError:
            tree[dbname] = {"_error": "connect failed"}
            continue

        schema_rows  = run_query(db_conn, _SQL_ACCESSIBLE_SCHEMAS)
        table_rows   = run_query(db_conn, _SQL_ACCESSIBLE_TABLES)
        db_conn.close()

        schemas = {r[0] for r in (schema_rows or [])}
        db_tree: dict = {s: [] for s in sorted(schemas)}

        for row in (table_rows or []):
            schema, tname, ttype, privs = row
            if schema not in db_tree:
                db_tree[schema] = []
            db_tree[schema].append({
                "table":      tname,
                "type":       ttype,
                "privileges": privs or "",
            })

        tree[dbname] = db_tree

    return tree


def scan_host(host: str, port: int, credentials: list, timeout: float,
              enumerate: bool = False) -> HostResult:
    result = HostResult(host=host, port=port)

    if not is_port_open(host, port, timeout):
        return result

    result.open = True
    tested_dbs = set()

    for user, password in credentials:
        conn = try_login(host, port, user, password, timeout)
        if conn is None:
            continue

        result.credentials.append((user, password))
        cred_key = (user, password)

        # Only do full recon once per unique working credential set
        if cred_key not in tested_dbs:
            tested_dbs.add(cred_key)
            result.recon[(user, password)] = collect_recon(conn)
            result.findings.extend(check_privesc(conn))
            if enumerate:
                result.enumeration[(user, password)] = enumerate_access(
                    host, port, user, password, timeout
                )

        conn.close()

    return result


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
SEV_COLOR = {
    "CRITICAL": "\033[91m",  # red
    "HIGH":     "\033[93m",  # yellow
    "MEDIUM":   "\033[94m",  # blue
    "INFO":     "\033[97m",  # white
}
RESET = "\033[0m"


def color(sev: str, text: str) -> str:
    return f"{SEV_COLOR.get(sev, '')}{text}{RESET}"


def print_result(result: HostResult, verbose: bool):
    target = f"{result.host}:{result.port}"

    if not result.open:
        if verbose:
            print(f"  [-] {target}  port closed / filtered")
        return

    if not result.credentials:
        print(f"  [ ] {target}  open — no valid credentials found")
        return

    print(f"\n{'='*70}")
    print(f"  [+] {target}  COMPROMISED")
    print(f"{'='*70}")

    for user, passwd in result.credentials:
        print(f"      Credential: {user} / {passwd}")

    # Recon summary
    for (user, passwd), recon in result.recon.items():
        print(f"\n  --- Recon ({user}) ---")
        if "version" in recon and recon["version"]:
            print(f"    Version       : {recon['version'][0][0][:80]}")
        if "current_user" in recon:
            print(f"    Current user  : {recon['current_user'][0][0] if recon['current_user'] else 'n/a'}")
        if "is_superuser" in recon:
            su = recon["is_superuser"][0][0] if recon["is_superuser"] else False
            print(f"    Superuser     : {color('CRITICAL', 'YES') if su else 'no'}")
        if "databases" in recon:
            dbs = ", ".join(r[0] for r in recon["databases"])
            print(f"    Databases     : {dbs}")
        if "extensions" in recon:
            exts = ", ".join(r[0] for r in recon["extensions"]) or "none"
            print(f"    Extensions    : {exts}")
        if "ssl" in recon:
            ssl_on = recon["ssl"][0][0] if recon["ssl"] else "unknown"
            print(f"    SSL           : {ssl_on}")
        if "listen_addresses" in recon:
            la = recon["listen_addresses"][0][0] if recon["listen_addresses"] else "unknown"
            print(f"    Listen addr   : {la}")

    # Enumeration
    if result.enumeration:
        for (user, passwd), tree in result.enumeration.items():
            print(f"\n  --- DB/Table Enumeration ({user}) ---")
            if not tree:
                print("    (no accessible databases)")
                continue
            for dbname, schemas in tree.items():
                if "_error" in schemas:
                    print(f"    [{dbname}]  <connect failed>")
                    continue
                total_tables = sum(len(v) for v in schemas.values())
                print(f"    [{dbname}]  {total_tables} accessible table(s)")
                for schema, tables in schemas.items():
                    if not tables:
                        continue
                    print(f"      schema: {schema}")
                    for t in tables:
                        ttype = "view" if t["type"] == "VIEW" else "table"
                        privs = f"  [{t['privileges']}]" if t["privileges"] else ""
                        print(f"        {ttype}  {t['table']}{privs}")

    # Findings
    if result.findings:
        sorted_findings = sorted(result.findings, key=lambda f: SEV_ORDER.get(f.severity, 99))
        print(f"\n  --- Privilege Escalation / Security Findings ---")
        for f in sorted_findings:
            print(f"    {color(f.severity, f'[{f.severity}]')} {f.title}")
            if verbose:
                print(f"           {f.detail}")
    else:
        print("\n  No privesc vectors found for tested credentials.")


def save_json(results: list, path: str):
    output = []
    for r in results:
        output.append({
            "host": r.host,
            "port": r.port,
            "open": r.open,
            "credentials": [{"user": u, "pass": p} for u, p in r.credentials],
            "recon": {
                f"{u}@{p}": v for (u, p), v in r.recon.items()
            },
            "enumeration": {
                f"{u}@{p}": v for (u, p), v in r.enumeration.items()
            },
            "findings": [
                {"severity": f.severity, "title": f.title, "detail": f.detail}
                for f in r.findings
            ],
        })
    with open(path, "w") as fh:
        json.dump(output, fh, indent=2, default=str)
    print(f"\n[*] JSON report saved to: {path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="pgblast — PostgreSQL security scanner for authorized pentests.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("--hosts",     required=True,
                   help="File with one host per line.\n"
                        "Port formats supported:\n"
                        "  192.168.1.10              → use --ports default\n"
                        "  192.168.1.10:5432         → single port override\n"
                        "  192.168.1.10:5432,5433    → multiple ports for this host")
    p.add_argument("--users",     required=True,
                   help="File with one username per line")
    p.add_argument("--passwords", required=True,
                   help="File with one password per line (use empty line for blank password)")
    p.add_argument("--ports",     default="5432",
                   help="Default port(s) when host has no port specified.\n"
                        "Comma-separated for multiple: 5432,5433 (default: 5432)")
    p.add_argument("--threads",   type=int, default=10,
                   help="Concurrent threads (default: 10)")
    p.add_argument("--timeout",   type=float, default=5,
                   help="Connection timeout in seconds (default: 5)")
    p.add_argument("--output",    default=None,
                   help="Optional JSON output file path")
    p.add_argument("--verbose",   action="store_true",
                   help="Show finding details and closed hosts")
    p.add_argument("--enumerate", action="store_true",
                   help="After login, enumerate all accessible databases, schemas,\n"
                        "and tables for each valid credential (slower)")
    return p.parse_args()


def parse_ports(port_str: str) -> list:
    """Parse a comma-separated port string into a list of ints."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if part:
            ports.append(int(part))
    return ports


def load_hosts(path: str, default_ports: list) -> list:
    """
    Returns a flat list of (host, port) tuples.
    Each host line may specify one or more ports after a colon (comma-separated).
    Lines with no port use default_ports, expanding into one entry per port.
    """
    targets = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            h, port_part = line.rsplit(":", 1)
            ports = parse_ports(port_part)
        else:
            h = line
            ports = default_ports
        for port in ports:
            targets.append((h.strip(), port))
    return targets


def load_wordlist(path: str) -> list:
    """Return non-empty, non-comment lines from a file. Empty line → empty string."""
    words = []
    for line in Path(path).read_text().splitlines():
        if line.startswith("#"):
            continue
        words.append(line.rstrip("\n"))   # preserve intentional empty lines
    return words


def build_credentials(users: list, passwords: list) -> list:
    """Cartesian product of users × passwords."""
    return [(u, p) for u in users for p in passwords]


def main():
    args = parse_args()

    default_ports = parse_ports(args.ports)
    targets       = load_hosts(args.hosts, default_ports)
    users         = load_wordlist(args.users)
    passwords     = load_wordlist(args.passwords)
    creds         = build_credentials(users, passwords)

    # Deduplicate targets while preserving order
    seen = set()
    unique_targets = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique_targets.append(t)
    targets = unique_targets

    print(f"[*] pgblast — PostgreSQL Security Scanner")
    print(f"[*] Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Targets   : {len(targets)} host:port pair(s)")
    print(f"[*] Users     : {len(users)}")
    print(f"[*] Passwords : {len(passwords)}")
    print(f"[*] Combos    : {len(creds)}")
    print(f"[*] Threads   : {args.threads}")
    print(f"[*] Timeout   : {args.timeout}s")
    print(f"[*] Enumerate : {'yes' if args.enumerate else 'no'}\n")

    results = []

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(scan_host, host, port, creds, args.timeout, args.enumerate): (host, port)
            for host, port in targets
        }
        for future in as_completed(futures):
            host, port = futures[future]
            try:
                result = future.result()
                results.append(result)
                print_result(result, args.verbose)
            except Exception as exc:
                print(f"  [!] {host}:{port} — unexpected error: {exc}")

    # Summary
    compromised = [r for r in results if r.credentials]
    open_hosts  = [r for r in results if r.open]

    # Collect all critical findings across all results
    critical_hits = []  # list of (host, port, user, Finding)
    for r in results:
        for f in r.findings:
            if f.severity == "CRITICAL":
                cred_user = r.credentials[0][0] if r.credentials else "unknown"
                critical_hits.append((r.host, r.port, cred_user, f))

    print(f"\n{'='*70}")
    print(f"  SUMMARY")
    print(f"{'='*70}")
    print(f"    Targets scanned  : {len(results)}")
    print(f"    Port open        : {len(open_hosts)}")
    print(f"    Credentials hit  : {len(compromised)}")
    print(f"    Critical findings: {len(critical_hits)}")

    if critical_hits:
        print(f"\n{'='*70}")
        print(f"  {color('CRITICAL', 'CRITICAL FINDINGS')}")
        print(f"{'='*70}")
        for host, port, user, f in critical_hits:
            print(f"  {host}:{port}  ({user})")
            print(f"    {color('CRITICAL', f'[CRITICAL]')} {f.title}")
            print(f"    {f.detail}")
            print()

    if args.output:
        save_json(results, args.output)

    print(f"\n[*] Done: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()
