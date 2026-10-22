# VulnScan

A network scanner that runs real protocol checks instead of guessing from banners. It maps targets, fingerprints services on open ports, and reports confirmed weaknesses with severity, CVSS, and evidence.

Built with Java 21 (virtual threads), Picocli, and an SPI plugin system.

[![CI](https://github.com/HimanshuJha-2005/vulnscan/actions/workflows/ci.yml/badge.svg)](https://github.com/HimanshuJha-2005/vulnscan/actions/workflows/ci.yml)

## What it does

- Parses single IPs, CIDR blocks, ranges, hostnames, and target files.
- Scans ports concurrently on virtual threads, with configurable timeouts and thread limits.
- Fingerprints 13 service types: HTTP servers (Apache, nginx, IIS), SSH, FTP, MySQL, PostgreSQL, Redis, MongoDB, RDP, and SMB.
- Runs 10 checks that speak the protocol: SSH negotiation, TLS handshake, HTTP responses, RDP negotiation, Redis and MongoDB commands, FTP login.
- Writes table, JSON, CSV, SARIF, or JSON Lines output.
- Persists scan state in SQLite so an interrupted scan can resume by ID.
- Loads additional checks from JARs at `~/.vulnscan/checks/`.

## Checks

| ID | Severity | CVSS | What it looks for |
|---|---|---|---|
| CVE-2021-44228 | Critical | 10.0 | Log4Shell version disclosure; with `--active`, a JNDI callback |
| CVE-2019-0708 | Critical | 9.8 | RDP negotiation that still permits legacy security (no NLA) |
| DEFAULT-CREDS | High | 7.5 | FTP default credentials accepted (`--active` only) |
| REDIS-UNAUTH | High | 7.5 | Redis reachable without authentication |
| MONGO-OPEN | High | 7.5 | MongoDB reachable without authentication |
| SSL-TLS-WEAK | Medium | 5.9 | TLS 1.0/1.1 or CBC/RC4/3DES cipher suites accepted |
| SSH-WEAK-ALGO | Medium | 5.3 | Weak key exchange, host key, cipher, or MAC algorithms offered |
| ANON-FTP | Medium | 5.3 | Anonymous FTP login accepted |
| HTTP-SEC-HEADERS | Low | 3.7 | Missing CSP, frame protection, HSTS (HTTPS), and related headers |
| DIR-LISTING | Low | 3.7 | Directory listing enabled on the document root |

Two checks are intrusive and stay off unless `--active` is passed: default-credential attempts and the JNDI callback probe. Active mode sends exactly one callback payload per target and never exploits, uploads, or persists.

Findings are indicators, not proof of exploitability. BlueKeep reporting means the host still allows RDP security without NLA, not that the patch level is known. Log4Shell detection without a callback is based on disclosed versions and class indicators.

## Requirements

- Java 21
- Maven 3.9+ (build only)

## Build and run

```bash
git clone https://github.com/HimanshuJha-2005/vulnscan.git
cd vulnscan
mvn package

java -jar target/vulnscan.jar scan 192.168.1.100
java -jar target/vulnscan.jar scan 192.168.1.0/24 -p 80,443,8080-8090 -f json -o results.json
java -jar target/vulnscan.jar list-checks
```

Scan only systems you own or have written permission to test.

## Usage

```
vulnscan scan [options] <target>
```

| Option | Description |
|---|---|
| `-p, --ports` | Port specification: `80,443`, `1-1000`, `top100`, `top1000`, `all` |
| `-P, --profile` | `quick`, `full`, `stealth`, `custom` |
| `-t, --threads` | Maximum concurrent connections (default 1000) |
| `-T, --timeout` | Connection timeout in milliseconds (default 3000) |
| `-f, --format` | `table`, `json`, `csv`, `sarif`, `json-lines` |
| `-o, --output` | Output file (default stdout) |
| `-iL, --input-file` | Target file, one target per line |
| `--checks` / `--exclude-checks` | Select or skip check IDs |
| `--resume <scan-id>` | Continue a stored scan, skipping completed hosts |
| `--no-ping`, `--no-banner-grab`, `--no-progress` | Disable discovery, banners, progress output |
| `--active` | Enable intrusive checks (authorised systems only) |

Exit codes: `0` no findings, `1` findings, `2` critical findings. Diagnostics go to stderr, so `-f json > results.json` produces valid JSON.

Profiles and defaults live in `~/.vulnscan/config.yaml`; scan state lives in `~/.vulnscan/scans.db`. Both are created on first use.

```bash
vulnscan config list
vulnscan config get scanner.defaultPorts
vulnscan config set scanner.defaultPorts top100
vulnscan config profiles --add "web,80,443,8080,1000,Web ports only"
vulnscan config profiles --remove stealth
```

## Output

JSON and JSON Lines contain the full result set, including service fingerprints, findings, and evidence. SARIF is intended for GitHub code scanning and other SARIF consumers. The table format is for terminal use.

```bash
java -jar target/vulnscan.jar scan 10.0.0.0/24 -f sarif -o results.sarif
```

## Architecture

```
TargetParser -> PortScanner (virtual threads) -> ServiceDetector (13 probes)
                                                     |
                                              CheckRegistry (10 checks + SPI)
                                                     |
                                          OutputFormatter (table/JSON/CSV/SARIF)
```

- `scanner/` contains target parsing, port scanning, and service detection.
- `check/builtin/` holds the ten built-in checks, one class per check.
- `check/net/` holds protocol clients (SSH, HTTP, TLS, FTP, RDP).
- `orchestrator/` coordinates discovery, detection, checks, persistence, and output.
- `output/` contains the formatters; `persistence/` contains the SQLite state store.

Checks receive a `ServiceFingerprint` with the target host and detected service metadata. Adding a check means implementing `VulnerabilityCheck` and registering it through `META-INF/services`; see [EXTENDING.md](EXTENDING.md).

## Tests

```bash
mvn test          # 107 unit and loopback integration tests
mvn verify        # build plus tests
mvn spotbugs:check checkstyle:check
```

The test suite runs protocol fixtures on loopback (fake SSH, HTTP, TLS, FTP, and RDP servers), so it does not need Docker or external network access. CI runs `mvn verify` on Java 21 and then SpotBugs and Checkstyle.

## Limitations

- Unauthenticated scanning only. It does not log into applications or inspect patch levels.
- TLS detection covers TLS 1.0/1.1 and a fixed list of legacy ciphers; it is not a full cipher inventory.
- Log4Shell confirmation needs `--active` and a callback address reachable from the target.
- Service detection and checks cover the listed protocols only. Unknown services are reported by banner but not audited.

## License

Apache License 2.0. See [LICENSE](LICENSE).

More detail: [ARCHITECTURE.md](ARCHITECTURE.md) and [EXTENDING.md](EXTENDING.md).
