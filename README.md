# CIDAG — Cloud Identity Attack Graph & Multi-Domain Security Scanner

**Find privilege escalation paths in cloud IAM and scan cloud + network for real
vulnerabilities — an enterprise-grade, offline-first security scanner.**

CIDAG maps cloud identities, policies, and trust relationships into a directed
graph and automatically discovers multi-step attack paths to admin. On top of
that it runs **modular scanners** for S3, EC2/Security Groups, RDS, CloudTrail,
network services, and **real CVEs** (via the NVD mirror + AWS Inspector/Security Hub).

```
ci-deployer → CIDeployerPolicy → iam:PassRole → admin-role → Action:* → ADMIN
```

## Why

Compliance scanners (Prowler, ScoutSuite) list **isolated misconfigurations**.
Exploit frameworks (Pacu) require **manual chaining**. CIDAG automatically
discovers **how** a low-privilege identity reaches full account compromise **and**
surfaces the real CVEs and misconfigs across your cloud and network — in one
offline-first tool with a unified report.

## Features

- **IAM attack graph** — 10 escalation rules (PassRole chains, self-attachment,
  boundary manipulation, access-key theft), shortest paths to admin, blast radius,
  deny-aware evaluation
- **S3 scanner** — public ACL/policy, missing encryption, logging, versioning,
  MFA-delete, public-access-block, insecure transport (S3-001…S3-010)
- **EC2 / RDS / CloudTrail scanner** — internet-open SSH/RDP/DB ports, all-traffic
  SGs, unencrypted EBS, IMDSv1, public/unencrypted RDS, short backups, CloudTrail
  misconfigs (EC2-*/RDS-*/CT-*)
- **Network scanner** — authorized asyncio port scan + banner grab + service
  fingerprinting (scope-guard enforced; private targets need `--allow-private`)
- **CVE correlation engine** — fingerprints detected services and matches them
  against the **full NVD** (API 2.0 + local SQLite mirror). `cidag nvd sync`
  builds an offline mirror; every scan then works offline. Includes curated seed
  rules (Log4Shell-era classics) for a cold cache.
- **AWS-native CVE imports** — pull real CVE findings from **Inspector v2** and
  **Security Hub** (read-only)
- **External tool imports** — ingest existing **nmap XML**, **nuclei JSON**, and
  **Prowler JSON** so an engagement can mix CIDAG with tools you already run
- **Unified findings schema** — one `Finding` (severity/module/check/target/CVE/
  remediation) powers the CLI, reports, and future GUI
- **Offline-first** — works on built-in mock data; no cloud account or network needed

## Install

```bash
git clone https://github.com/ShabanIkram/cidag
cd cidag
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .                   # optional: installs `cidag` command
```

## Usage

```bash
# --- IAM attack graph (original behavior) ---
cidag scan                          # mock account; human-readable findings
cidag scan --json                   # machine-readable
cidag graph / cidag paths / cidag blast --identity <name>

# --- Modular scanning ---
cidag scan --modules iam,s3,ec2            # IAM + S3 + EC2/RDS/CloudTrail
cidag scan --modules iam,s3,ec2,net \
           --targets 10.0.0.0/24          # add an authorized network scan
cidag scan --modules s3 --profile prod     # live AWS (read-only)

# Network scan needs an explicit authorized CIDR; private ranges need the flag:
cidag scan --modules net --targets 203.0.113.0/24           # public range
cidag scan --modules net --targets 10.0.0.0/24 --allow-private --ports 22,80,443

# --- CVE correlation (every CVE, via NVD) ---
cidag nvd sync --days 120          # build/refresh the offline NVD mirror
cidag nvd count                    # how many CVEs are cached locally
cidag scan --modules net --targets ...   # detected services -> real CVEs
cidag scan --modules net ... --no-nvd    # offline: curated seed CVEs only

# --- Import external tool output ---
cidag scan --modules import --import-path scan.xml  --import-format nmap
cidag scan --modules import --import-path out.json  --import-format nuclei
cidag scan --modules import --import-path prowler.json --import-format prowler

# --- AWS-native CVE imports (read-only) ---
cidag scan --modules inspector --profile prod
cidag scan --modules sechub    --profile prod

# --- Reports (unified across modules) ---
cidag report --modules iam,s3,ec2 --format md  -o report.md
cidag report --modules iam,s3,ec2 --format csv -o findings.csv
```

Without installing, prefix commands with `python -m cidag.cli.main`.

### Network authorization model

Network scanning is dual-use, so CIDAG makes authorization explicit and enforced:

- `--targets <CIDR>` declares the **authorized allowlist** (repeatable). The net
  scanner expands these to hosts and **refuses to probe anything outside them**.
- Private/loopback addresses are **always denied** unless `--allow-private` is set.
- Scans that would expand beyond `--max-hosts` (default 1024) are refused so a
  fat-fingered `/8` can't trigger a mass scan.
- Scan only ranges you own or have written permission to test.

### Minimum AWS permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow",
     "Action": [
       "iam:List*", "iam:Get*", "sts:GetCallerIdentity",
       "s3:ListAllMyBuckets", "s3:Get*", "s3control:GetPublicAccessBlock",
       "ec2:Describe*", "rds:Describe*", "cloudtrail:Describe*", "cloudtrail:GetTrail",
       "inspector2:ListFindings", "securityhub:GetFindings"
     ],
     "Resource": "*"}
  ]
}
```

## Scanner modules

| Module | What it does | Source |
|--------|--------------|--------|
| `iam` | Attack-graph escalation rules + paths | mock / AWS IAM |
| `s3` | Bucket config checks (S3-001…S3-010) | mock / AWS S3 |
| `ec2` | SG / EBS / IMDS / RDS / CloudTrail (EC2-*, RDS-*, CT-*) | mock / AWS |
| `net` | Port scan + banner + CVE correlation | live (authorized) |
| `cve` | NVD service→CVE correlation (used by `net`) | NVD mirror |
| `inspector` | Import CVEs from AWS Inspector v2 | AWS API |
| `sechub` | Import findings from AWS Security Hub | AWS API |
| `import` | Ingest nmap / nuclei / Prowler output | file |

## CVE coverage ("every CVE")

CIDAG does **not** hardcode CVEs — that's impossible (290k+ and growing). Instead:

1. **NVD mirror** — `cidag nvd sync` pulls the full/rolling NVD into a local
   SQLite cache via API 2.0; queries are cached so re-scans never re-hit the API.
   Detected services are fingerprinted → CPE → matched against NVD live or offline.
2. **AWS Inspector / Security Hub** — import real CVEs AWS already found in your
   workloads.
3. **nuclei / nmap / Prowler imports** — fold in CVEs from tools you already run.
4. **Curated seed rules** — a handful of famous CVEs (Log4Shell, ProFTPD, vsftpd
   backdoor…) so the engine is useful on a cold cache with no network.

Set an `NVD_API_KEY` (free from NVD) to raise the rate limit from 5→50 req/30s.

## Detection Rules (IAM)

| ID | Name | Severity |
|----|------|----------|
| — | Wildcard `Action: *` | CRITICAL |
| — | Wildcard `svc:*` on `*` | HIGH |
| ESC-01 | PassRole + EC2 RunInstances | CRITICAL |
| ESC-02 | PassRole + Lambda code update | CRITICAL |
| ESC-03 | PassRole + CloudFormation stack | CRITICAL |
| ESC-04 | iam:CreatePolicyVersion (self-escalation) | CRITICAL |
| ESC-05 | iam:AttachUserPolicy / AttachRolePolicy | CRITICAL |
| ESC-06 | iam:PutUserPolicy / PutRolePolicy | CRITICAL |
| ESC-07 | iam:CreateAccessKey | HIGH |
| ESC-08 | iam:SetDefaultPolicyVersion | HIGH |
| ESC-09 | Permission boundary manipulation | HIGH |
| ESC-10 | iam:AddUserToGroup | HIGH |
| — | Graph attack path to admin | HIGH |

## Architecture

```
Collectors (mock / AWS: IAM + S3 + EC2 + RDS + CloudTrail)
        ↓
Normalizer (effective permissions — Deny precedence, wildcards)
        ↓
Graph builder (NetworkX DiGraph)
        ↓
Analysis engine (escalation rules + path finding + blast radius)
        +
Scanner registry (s3 / ec2 / net / inspector / sechub / import) → unified Finding
        ↓
CVE engine (NVD mirror + CPE matching + seed rules)
        ↓
CLI + Reports (md / json / csv)  [GUI planned]
```

## Project Structure

```
cidag/
├── core/            # unified Finding, scanner registry, ScanContext, scope guard
├── cve/             # NVD client + SQLite mirror, CPE matching, correlation engine
├── collectors/      # mock + AWS data collection
├── normalizer/      # policy evaluator
├── graph/           # NetworkX graph construction
├── analysis/        # escalation rules + attack path engine
├── scanners/
│   ├── s3/          # S3 config checks + collector
│   ├── ec2/         # SG/EBS/IMDS/RDS/CloudTrail checks + collector
│   ├── network/     # authorized port scan + banner grab
│   └── imports/     # Inspector, Security Hub, nmap, nuclei, Prowler
├── reports/         # markdown / json / csv exporters
├── cli/             # command-line interface
└── data/            # mock inventories for offline use
tests/               # pytest suite (offline, no AWS required)
```

## Testing

```bash
pip install -r requirements-dev.txt
pytest -q
pytest --cov=cidag          # coverage report
```

All tests run offline against bundled mocks — no AWS credentials or network needed.

## Roadmap

- [ ] Graphical interface (FastAPI + Cytoscape.js)
- [ ] Azure / GCP collectors
- [ ] Permission boundaries & SCP evaluation
- [ ] Attack-path diffing (new risks after every change)
- [ ] Attack simulation mode (prove chains, collect evidence)
- [ ] nuclei live bridge (auto-detect binary)

## Disclaimer

CIDAG is for **authorized security testing only**. Scan only accounts, networks,
and ranges you own or have explicit written permission to assess. Misuse may
violate laws (CFAA, Computer Misuse Act, and equivalents). The network scanner
enforces an explicit allowlist for this reason.

## License

MIT
