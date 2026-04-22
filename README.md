# pgblast

PostgreSQL security scanner for penetration testing. Performs credential bruteforcing, post-auth reconnaissance, privilege escalation checks, and database/table enumeration.

## Requirements

```bash
pip install psycopg2-binary
```

## Usage

```bash
python3 pg_scanner.py --hosts hosts.txt --users users.txt --passwords passwords.txt [options]
```

### Arguments

| Argument | Required | Description |
|---|---|---|
| `--hosts` | yes | File with target hosts (see format below) |
| `--users` | yes | File with one username per line |
| `--passwords` | yes | File with one password per line |
| `--ports` | no | Default port(s) when host has none specified. Comma-separated (default: `5432`) |
| `--threads` | no | Concurrent threads (default: `10`) |
| `--timeout` | no | Connection timeout in seconds (default: `5`) |
| `--enumerate` | no | Enumerate accessible databases, schemas, and tables per credential |
| `--output` | no | Save full results to a JSON file |
| `--verbose` | no | Show privesc finding details and closed hosts |

### Host file format

```
192.168.1.10              # uses --ports default
192.168.1.11:5432         # single port override
192.168.1.12:5432,5433    # multiple ports for this host
```

### Credential files

**users.txt**
```
postgres
admin
dbuser
```

**passwords.txt**
```
postgres
password
admin
123456
                          # empty line = blank password
```

Credentials are tested as a cartesian product — every username against every password.

## Examples

Basic scan:
```bash
python3 pg_scanner.py --hosts hosts.txt --users users.txt --passwords passwords.txt
```

Multiple default ports with verbose output:
```bash
python3 pg_scanner.py --hosts hosts.txt --users users.txt --passwords passwords.txt \
  --ports 5432,5433 --verbose
```

Full audit with enumeration and JSON report:
```bash
python3 pg_scanner.py --hosts hosts.txt --users users.txt --passwords passwords.txt \
  --enumerate --output report.json --verbose
```

## What it checks

### Reconnaissance (runs on every successful login)
- Server version
- Current user and superuser status
- All databases, schemas, extensions
- SSL status, listen address, config file paths

### Privilege escalation vectors

| Severity | Check |
|---|---|
| CRITICAL | Superuser session |
| CRITICAL | `pg_shadow` readable — password hashes exposed |
| CRITICAL | `COPY TO/FROM PROGRAM` — OS command execution |
| HIGH | `pg_read_file()` — arbitrary server-side file read |
| HIGH | `pg_execute_server_program` role |
| HIGH | `pg_write_server_files` role — arbitrary file write |
| HIGH | `lo_import` / `lo_export` — large object file read/write |
| HIGH | `CREATEROLE` privilege — role escalation |
| MEDIUM | `CREATEDB` privilege |
| MEDIUM | `SECURITY DEFINER` functions accessible |
| MEDIUM | `CREATE` privilege on database — extension loading |

### Database enumeration (`--enumerate`)
Connects to each accessible database and maps:
- Databases the user can `CONNECT` to
- Schemas the user has `USAGE` on
- Tables and views the user has `SELECT` on, with full privilege list

## Output

Findings are printed inline per host during the scan. At the end, all **CRITICAL** findings are consolidated into a single block for quick review. Use `--output report.json` for a full machine-readable report.

## Disclaimer

For authorized penetration testing and security audits only. Do not use against systems you do not have explicit permission to test.
