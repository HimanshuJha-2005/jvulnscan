# VulnScan

High-performance network vulnerability scanner with plugin architecture. Built with Java 21 virtual threads and modern backend engineering practices.

[![CI](https://github.com/HimanshuJha-2005/vulnscan/actions/workflows/ci.yml/badge.svg)](https://github.com/HimanshuJha-2005/vulnscan/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.org/projects/jdk/21/)
[![Native](https://img.shields.io/badge/GraalVM-Native%20Image-green.svg)](https://graalvm.org/)

## Features

- **Virtual Threads** — High-concurrency port scanning on Java 21 virtual threads (one lightweight thread per connection, no pool tuning)
- **Plugin Architecture** — SPI-based vulnerability checks, drop-in JAR extensions via `~/.vulnscan/checks/`
- **Multi-format Output** — JSON, CSV, SARIF (GitHub Code Scanning), terminal table, JSON Lines; diagnostics go to stderr so `-f json > results.json` pipes cleanly
- **Scan Profiles** — quick, full, stealth, custom with persistent YAML config (`~/.vulnscan/config.yaml`)
- **Resume Capability** — SQLite-backed scan state (`~/.vulnscan/scans.db`); `--resume <scan-id>` skips already-completed hosts
- **GraalVM-ready** — Native-image Maven profile included (`mvn -Pnative package`)
- **Detection Coverage** — 13 service probes (HTTP/Apache/Nginx/IIS, SSH, FTP/vsftpd, MySQL, PostgreSQL, Redis, MongoDB, RDP, SMB) + 10 built-in vulnerability checks

## Quick Start

### Prerequisites
- Java 21+ (Temurin/OpenJDK recommended)
- Maven 3.9+

### Build
```bash
git clone https://github.com/HimanshuJha-2005/vulnscan.git
cd vulnscan
mvn package
```

### Run
```bash
# Scan a single target
java -jar target/vulnscan.jar scan 192.168.1.100

# Scan CIDR range with custom ports
java -jar target/vulnscan.jar scan 192.168.1.0/24 -p 80,443,8080-9000 -f json -o results.json

# Quick scan profile
java -jar target/vulnscan.jar scan 10.0.0.0/8 -P quick

# List available vulnerability checks
java -jar target/vulnscan.jar list-checks

# Resume interrupted scan (skips already-completed hosts)
java -jar target/vulnscan.jar scan 192.168.1.0/24 --resume <scan-id>
```

Exit codes: `0` = no findings, `1` = findings present, `2` = critical findings present — CI-friendly for quality gates.

## Command Reference

```
vulnscan [global options] <command> [command options]

Global Options:
  -v, --verbose          Increase verbosity (repeatable)
  --help                 Show help
  --version              Show version

Commands:
  scan                   Scan targets for vulnerabilities
  list-checks            List available vulnerability checks
  config                 Manage scanner configuration

Scan Options:
  -p, --ports            Port specification (default: top1000)
                         Examples: 80,443 | 1-1000 | top100 | top1000 | all
  -t, --threads          Max concurrent virtual threads (default: 1000)
  -T, --timeout          Connection timeout ms (default: 3000)
  -f, --format           Output format: json, csv, sarif, table, json-lines (default: table)
  -o, --output           Output file (default: stdout)
  -P, --profile          Scan profile: quick, full, stealth, custom (default: full)
  -iL, --input-file      Read targets from file (one per line, supports CIDR/ranges)
  --checks               Comma-separated check IDs to run (default: all)
  --exclude-checks       Comma-separated check IDs to skip
  --resume               Resume previous scan by ID (skips already-completed hosts)
  --no-ping              Skip host discovery
  --no-banner-grab       Disable banner grabbing on open ports
  --no-progress          Disable progress bar
  --active               Enable intrusive checks (default-credential attempts,
                         JNDI payload injection). Authorised systems only.

Config Subcommands:
  config get <key>              Get configuration value
  config set <key> <value>      Set configuration value
  config list                   List all configuration
  config profiles --add ...     Add scan profile
  config profiles --remove ...  Remove scan profile
  config reset --force          Reset to defaults

List-Checks Options:
  -c, --category          Filter by category (web, database, network, auth, config, rce, crypto, misconfiguration, info-leak)
  --show-disabled         Include disabled checks
  --format                Output format: table, json, csv (default: table)
```

## Target Specification

| Format | Example | Description |
|--------|---------|-------------|
| Single IP | `192.168.1.100` | Single host |
| CIDR | `192.168.1.0/24` | Network range (254 hosts) |
| Range | `192.168.1.1-50` | Last octet range |
| Hostname | `example.com` | DNS resolution (all A records) |
| File | `-iL targets.txt` | One target per line, `#` comments |

## Built-in Vulnerability Checks

| Check ID | CVE | Protocol | Severity | CVSS | Description |
|----------|-----|----------|----------|------|-------------|
| CVE-2021-44228 | CVE-2021-44228 | HTTP | CRITICAL | 10.0 | Log4Shell: version disclosure, plus opt-in JNDI callback proof |
| CVE-2019-0708 | CVE-2019-0708 | RDP | CRITICAL | 9.8 | BlueKeep exposure: RDP still allows legacy security (no NLA) |
| ANON-FTP | — | FTP | MEDIUM | 5.3 | Anonymous FTP login enabled |
| DEFAULT-CREDS | — | FTP | HIGH | 7.5 | Default credentials accepted (opt-in, `--active`) |
| REDIS-UNAUTH | — | Redis | HIGH | 7.5 | Redis unauthorized access |
| MONGO-OPEN | — | MongoDB | HIGH | 7.5 | MongoDB unauthenticated access |
| SSL-TLS-WEAK | — | TLS | MEDIUM | 5.9 | TLS 1.0/1.1 or legacy cipher suites accepted |
| SSH-WEAK-ALGO | — | SSH | MEDIUM | 5.3 | SSH offers weak kex/host-key/cipher/MAC algorithms |
| HTTP-SEC-HEADERS | — | HTTP | LOW | 3.7 | Missing security headers |
| DIR-LISTING | — | HTTP | LOW | 3.7 | Directory listing enabled |

Checks inspect live services rather than guessing from banners: SSH
algorithms come from a real KEXINIT exchange, TLS from a ClientHello /
ServerHello exchange, HTTP checks from a single redirect-free GET, BlueKeep
from the RDP negotiation response, and Log4Shell from either a disclosed
version or an opt-in callback. Default-credential attempts and payload
injection stay disabled unless `--active` is passed.


## Output Formats

### JSON (Default for automation)
```json
{
  "scanId": "uuid",
  "target": "192.168.1.0/24",
  "startTime": "2026-01-15T10:30:00Z",
  "findings": [...]
}
```

### SARIF (GitHub Code Scanning)
```bash
vulnscan scan 192.168.1.0/24 -f sarif -o results.sarif
# Upload to GitHub: github/codeql-action/upload-sarif@v3
```

### CSV (Spreadsheet analysis)
```bash
vulnscan scan 192.168.1.0/24 -f csv -o results.csv
```

### Table (Human-readable)
```
╔═══════════════════════════════════════════════════════════════════════════════════════════════╗
║  VulnScan Results                                                                              ║
╠═══════════════════════════════════════════════════════════════════════════════════════════════╣
║  Scan ID:  a1b2c3d4-e5f6-7890-abcd-ef1234567890                                                ║
║  Target:   192.168.1.0/24                                                                       ║
║  Profile:  full                                                                                 ║
║  Hosts:    254  Open Ports: 12  Findings: 3  Critical: 1  High: 2                              ║
╠══════════════════════════════════════════════════════════════════════════════════════════════╣
║  HOST            PORT             SEV      CVSS FINDING                                        ║
╠────────────────────────────────────────────────────────────────────────────────────────────────╣
║  192.168.1.10    N/A               CRITICAL 10.0 Log4Shell RCE                                  ║
║  192.168.1.25    N/A               HIGH     7.5  Redis Unauthorized Access                      ║
╚═══════════════════════════════════════════════════════════════════════════════════════════════╝
```

## Configuration

Configuration file: `~/.vulnscan/config.yaml`

```yaml
scanner:
  defaultPorts: "top1000"
  defaultThreads: 1000
  defaultTimeout: 3000
  bannerGrab: true

profiles:
  quick:
    ports: "top100"
    threads: 500
    timeout: 1000
    description: "Fast scan of top 100 ports"
  full:
    ports: "top1000"
    threads: 1000
    timeout: 3000
    description: "Comprehensive scan of top 1000 ports"
  stealth:
    ports: "22,80,443,3389"
    threads: 50
    timeout: 10000
    description: "Slow stealth scan of critical ports"
  all:
    ports: "all"
    threads: 2000
    timeout: 5000
    description: "Full port range scan (1-65535)"

checks:
  enabled: ["*"]
  disabled: []
```

### Config CLI
```bash
# List all config
vulnscan config list

# Get/set values
vulnscan config get scanner.defaultPorts
vulnscan config set scanner.defaultPorts top100

# Manage profiles
vulnscan config profiles --add "web,80,443,8080,1000,Web ports only"
vulnscan config profiles --remove stealth

# Reset to defaults
vulnscan config reset --force
```

## Extending

### Custom Vulnerability Check (SPI Plugin)

```java
public class MyCustomCheck implements VulnerabilityCheck {
    @Override
    public CheckMetadata metadata() {
        return CheckMetadata.builder()
            .id("MY-CUSTOM-001")
            .name("My Custom Check")
            .severity(Severity.HIGH)
            .cvss(7.5)
            .affectedProducts(List.of("MyProduct"))
            .build();
    }

    @Override
    public Optional<Finding> execute(ServiceFingerprint fingerprint) {
        // Detection logic
        return Optional.empty();
    }
}
```

Register via `META-INF/services/com.himanshu.vulnscan.check.VulnerabilityCheck`.

Build JAR → Drop in `~/.vulnscan/checks/` → Auto-loaded.

See [EXTENDING.md](EXTENDING.md) for complete guide.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
                        ScanOrchestrator (Pipeline)
└─────────────────────────────────────────────────────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
┌───────────────┐           ┌─────────────────┐           ┌─────────────────┐
│ TargetParser  │           │  PortScanner    │           │ ServiceDetector │
│ (CIDR, range, │──────────▶│ (Virtual Threads)│────────▶│ (12 Probes)     │
│  hostname)    │           │                 │           │                 │
└───────────────┘           └─────────────────┘           └─────────────────┘
                                                                       │
                                                                       ▼
                                                          ┌─────────────────────┐
                                                          │  CheckRegistry      │
                                                          │  (10 Built-in +    │
                                                          │   SPI Plugins)      │
                                                          └─────────────────────┘
                                                                       │
                                                                       ▼
                                                          ┌─────────────────────┐
                                                          │  OutputFormatter    │
                                                          │ (JSON/CSV/SARIF/    │
                                                          │  Table/JSON-Lines)  │
                                                          └─────────────────────┘
```

## Testing

```bash
# Unit tests (107 tests, all green)
mvn test

# Full verify including integration tests (requires Docker for Testcontainers)
mvn verify

# Static analysis (non-blocking; CI runs these separately)
mvn spotbugs:check checkstyle:check

# Dependency vulnerability scan (manual; requires NVD API key, see NVD_API_KEY env)
mvn dependency-check:check
```

## CI

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs on every push/PR:

1. **Build & Test** — `mvn verify` (compile + 52 unit tests)
2. **Static Analysis** — SpotBugs + Checkstyle (non-blocking)

A GraalVM native-image profile is included (`mvn -Pnative package`, requires GraalVM 21+).

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — System architecture, data flow, thread model
- [EXTENDING.md](EXTENDING.md) — Writing custom checks, probes, output formats

## Author

[Himanshu Jha](https://github.com/HimanshuJha-2005) — Backend Engineer