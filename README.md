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

- **IAM attack graph** — 13 escalation rules (PassRole chains, trust hijack,
  login-profile takeover, self-attachment, boundary manipulation, access-key
  theft, Glue endpoints), shortest paths to admin, blast radius, deny-aware
  evaluation
- **Azure / GCP collectors** — Azure RBAC role assignments and GCP project IAM
  bindings normalize into the same attack graph and policy engine (read-only;
  optional SDK extras)
- **IAM policy risk analysis** — Cloudsplaining-style least-privilege lens:
  wildcard-admin policies, privilege-escalation primitives, data-exfiltration
  capability, public trust principals (POL-001…POL-004)
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
- **nuclei live bridge** — auto-detects the `nuclei` binary and runs it against
  the same scope-guarded `--targets` as `net` (redirects and Interactsh disabled)
- **Multi-account scanning** — `--all-accounts` enumerates AWS Organizations,
  assumes a role per member account, and tags every finding with its account
- **Compliance mappings** — every check is mapped (best-effort) to CIS AWS
  Foundations and PCI DSS v4.0 controls, with per-framework report filtering
- **Permission boundaries & SCP evaluation** — AWS permissions boundaries and
  Organizations SCPs gate escalation rules, wildcard-admin detection, and
  PassRole edges, so guardrail-blocked actions are not reported as exploitable
- **Unified findings schema** — one `Finding` (severity/module/check/target/CVE/
  account/compliance/remediation) powers the CLI, reports, and graph renderers
- **CI-ready outputs** — Markdown / JSON / CSV / **SARIF 2.1.0** (GitHub code
  scanning) plus `cidag diff` to track new, fixed, and severity-changed findings
  between any two reports
- **Authorized exploitation engine (opt-in)** — execute the escalation CIDAG
  proved, with an explicit account authorization gate, IAM policy-simulator
  preflight, verification, automatic rollback, hashed-only canary impact proof,
  and matching detections (ESC-* on AWS, AZ-01/GCP-01 on Azure/GCP)
- **Pacu orchestration bridge** — run allowlisted read-only Pacu modules inside
  an existing Pacu session; CIDAG never imports Pacu keys, shell-interpolates, or
  accepts arbitrary modules
- **Offline-first** — works on built-in mock data; no cloud account or network needed

## Install

```bash
git clone https://github.com/ShabanIkram/cidag
cd cidag
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .                   # optional: installs `cidag` command
pip install -e ".[azure]"          # Azure live collection
pip install -e ".[gcp]"            # GCP live collection
# Pacu bridge (optional, only if you already run Pacu):
# pipx install git+https://github.com/RhinoSecurityLabs/pacu
```

Live cloud access is read-only:

- **AWS** — the credential chain (`AWS_PROFILE` / `--profile`); IAM/S3/EC2 read
  APIs, plus `organizations:ListPoliciesForTarget` / `DescribePolicy` and
  `iam:GetPolicy`/`GetPolicyVersion` when SCPs and boundaries exist (optional —
  scans continue without them)
- **Azure** — `Reader` at subscription scope; `DefaultAzureCredential`
  (`AZURE_SUBSCRIPTION_ID` or `--subscription-id`, defaults to first enabled)
- **GCP** — `resourcemanager.projects.getIamPolicy` + `iam.roles.get`;
  `GOOGLE_CLOUD_PROJECT` / `--project`, Application Default Credentials

Azure principal display names are resolved from RBAC only (object IDs), and
Azure/GCP have no role-trust edges; AWS-only modules (`s3`, `ec2`, `inspector`,
`sechub`) are rejected under `--cloud azure|gcp`.

## Usage

```bash
# --- IAM attack graph (original behavior) ---
cidag scan                          # mock account; human-readable findings
cidag scan --json                   # machine-readable
cidag graph / cidag paths / cidag blast --identity <name>

# --- Visual outputs ---
cidag graph --format svg -o graph.svg        # visual attack graph (open in any browser)
cidag graph --format mermaid                 # mermaid flowchart (README / mermaid.live)
cidag graph --format dot                     # graphviz source (render elsewhere)
cidag paths --format mermaid                 # escalation chains as a flowchart

# --- Multi-cloud IAM ---
cidag scan --cloud azure --modules iam,policy   # offline Azure RBAC mock
cidag scan --cloud gcp   --modules iam,policy   # offline GCP IAM mock
cidag scan --cloud azure --live --subscription-id <sub>
cidag scan --cloud gcp   --live --project <project-id>
cidag graph --cloud gcp --format svg -o gcp.svg

# --- Modular scanning ---
cidag scan --modules iam,s3,ec2            # IAM + S3 + EC2/RDS/CloudTrail
cidag scan --modules iam,s3,ec2,policy     # + policy least-privilege analysis
cidag scan --modules iam,s3,ec2,net \
           --targets 10.0.0.0/24          # add an authorized network scan
cidag scan --modules s3 --profile prod     # live AWS (read-only)
cidag scan --modules nuclei --targets 10.0.0.0/24 --allow-private
                                           # run local nuclei (auto-detected)

# --- Multi-account (AWS Organizations) ---
cidag scan --live --all-accounts --modules iam,s3,ec2
cidag scan --live --all-accounts --account-id 111122223333 --role-name AuditRole

# --- Authorized exploitation (opt-in; sandbox accounts only) ---
cidag exploit list
cidag exploit plan ESC-05 --authorize-exploitation 123456789012
cidag exploit run  ESC-05 --authorize-exploitation 123456789012 --canary auto
cidag exploit run  ESC-11 --authorize-exploitation 123456789012 \
                   --target-role sandbox-admin --keep
cidag exploit report .cidag/engagements/<run>/manifest.json
cidag exploit detections -o detections.md
cidag exploit cleanup .cidag/engagements/<run>/manifest.json \
                   --authorize-exploitation 123456789012
cidag exploit pacu --authorize-exploitation 123456789012 \
                   --pacu-session demo --module iam__enum_permissions
cidag exploit demo -o cidag-demo.md

# --- Azure / GCP authorized execution (rollback only) ---
cidag exploit run AZ-01 --cloud azure --subscription-id <sub-id> \
                   --authorize-exploitation <sub-id>
cidag exploit run GCP-01 --cloud gcp --project <project-id> \
                   --authorize-exploitation <project-id> \
                   --member user:analyst@example.com

# --- Reports and CI ---
cidag report -m iam,s3,ec2 --format md   -o report.md
cidag report -m iam,s3,ec2 --format sarif -o cidag.sarif   # GitHub code scanning
cidag report -m iam,s3,ec2 --compliance cis -o cis.md      # CIS-only view
cidag diff --before old.json --after new.json               # new/fixed/changed

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

### Authorized exploitation model

`cidag exploit` is the only mutating surface and every run requires
`--authorize-exploitation <account-id|subscription-id|project-id>`.
Before a single mutation:

1. The caller identity must resolve to that exact account, subscription, or
   project (AWS STS, Azure token claims, or the supplied GCP member).
2. On AWS, IAM `SimulatePrincipalPolicy` must show every required action
   allowed (override a missing decision with `--accept-unknown`, never a deny).
   Azure/GCP have no equivalent simulator, so preflight is marked skipped and
   read-only post-execution verification is mandatory.
3. In a TTY, the operator types `EXECUTE <account-id>`; unattended runs need
   `--yes-i-have-written-authorization`.
4. One technique runs, read-only verification proves the result, an optional
   canary is created/read/deleted (AWS), and rollback restores the account by
   default. `--keep` and post-run cleanup are AWS-only; Azure/GCP always roll
   back automatically.

Every run writes `.cidag/engagements/<timestamp>-<account>/` with a redacted
`audit.jsonl`, cleanup `manifest.json`, and evidence. Secrets are never written;
the canary stores only a SHA-256 digest. `--keep` leaves artifacts in place and
`cidag exploit cleanup <manifest>` applies the allowlisted restoration ops.
The engine does **not** install persistence, harvest credentials, exfiltrate
data, or add evasion. Use dedicated sandbox credentials and written authorization.

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
| `policy` | Policy least-privilege / exposure analysis (POL-001…POL-004) | mock / AWS IAM |
| `s3` | Bucket config checks (S3-001…S3-010) | mock / AWS S3 |
| `ec2` | SG / EBS / IMDS / RDS / CloudTrail (EC2-*, RDS-*, CT-*) | mock / AWS |
| `net` | Port scan + banner + CVE correlation | live (authorized) |
| `nuclei` | Live nuclei run (binary auto-detected) | live (authorized) |
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
| AZ-01 | Azure roleAssignments/write (Owner grant) | CRITICAL |
| GCP-01 | GCP resourcemanager.projects.setIamPolicy (Owner grant) | CRITICAL |
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
Scanner registry (s3 / ec2 / net / policy / nuclei / inspector / sechub / import)
        → unified Finding (with account + CIS/PCI compliance tags)
        ↓
CVE engine (NVD mirror + CPE matching + seed rules)
        ↓
CLI + Reports (md / json / csv / sarif) + graph renderers (svg / mermaid / dot)
        +
Execution layer (opt-in): authorization gate → simulator preflight →
technique → verify → canary → rollback/audit → detection + evidence pack
```

## Project Structure

```
cidag/
├── core/            # unified Finding, scanner registry, ScanContext, scope guard
├── cve/             # NVD client + SQLite mirror, CPE matching, correlation engine
├── collectors/      # mock + AWS / Azure RBAC / GCP IAM, Organizations/assume-role
├── normalizer/      # policy evaluator
├── graph/           # NetworkX graph construction + svg / mermaid / dot renderers
├── analysis/        # escalation rules + attack path engine
├── scanners/
│   ├── s3/          # S3 config checks + collector
│   ├── ec2/         # SG/EBS/IMDS/RDS/CloudTrail checks + collector
│   ├── network/     # authorized port scan + banner grab
│   ├── policy/      # IAM policy least-privilege / exposure analysis
│   └── imports/     # Inspector, Security Hub, nmap/nuclei/Prowler + nuclei bridge
├── normalizer/      # deny/boundary/SCP-aware effective-permission evaluator
├── execution/       # opt-in escalation: guard, techniques, runner, canary,
│                    # audit/cleanup, Pacu bridge, detections, evidence reports
├── reports/         # markdown / json / csv / sarif exporters + compliance maps
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

All tests run offline against bundled mocks — no cloud credentials or network needed.

## Roadmap

- [x] Authorized escalation execution with simulator preflight, canary proof,
      rollback, audit manifest, and matching detection content
- [x] Azure / GCP authorized execution parity (AZ-01 Owner grant, GCP-01 roles/owner)
- [ ] Multi-step chain execution (currently one technique per authorized run)
- [ ] Azure deny assignments / GCP organization policy constraints
- [ ] UDP and service-detection scan modes
- [ ] Expanded offline CVE seed coverage (beyond classic backdoored builds)

## Disclaimer

CIDAG is for **authorized security testing only**. Scan only accounts, networks,
and ranges you own or have explicit written permission to assess. Misuse may
violate laws (CFAA, Computer Misuse Act, and equivalents). The network scanner
enforces an explicit allowlist and the execution engine requires an explicit
account id, identity check, simulator preflight, and confirmation for this reason.

## License

MIT
