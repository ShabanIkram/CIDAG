# CIDAG — Cloud Identity Attack Graph

**Find privilege escalation paths in cloud IAM — like BloodHound, for the cloud.**

CIDAG maps cloud identities, policies, and trust relationships into a directed
graph, then automatically discovers multi-step attack paths that low-privilege
principals can use to reach full administrative access.

```
ci-deployer → CIDeployerPolicy → iam:PassRole → admin-role → Action:* → ADMIN
```

## Why

Compliance scanners (Prowler, ScoutSuite) list **isolated misconfigurations**.
Exploit frameworks (Pacu) require **manual chaining**. CIDAG automatically
discovers and visualizes **how** a low-privilege identity reaches full account
compromise — and exports it as a pentest-ready report.

## Features

- **Wildcard detection** — `Action: *` and `svc:*` on `Resource: *`
- **10 escalation rules** — PassRole chains, self-policy attachment,
  boundary manipulation, access-key theft (Rhino Security method set)
- **Graph attack paths** — shortest assume/pass chains to admin (BFS)
- **Blast radius** — everything a compromised identity can reach
- **Deny-aware evaluation** — no false positives from blocked actions
- **Reports** — Markdown / JSON / CSV with remediation notes
- **Offline-first** — works on built-in mock data; no cloud account needed

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
# Scan the built-in mock environment (no AWS needed)
cidag scan                          # human-readable findings
cidag scan --json                   # machine-readable output

# Explore the graph
cidag graph                         # print all edges (label --rel--> label)

# Attack paths & blast radius
cidag paths                         # paths from each identity to admin
cidag blast --identity lambda-exec-role

# Reports
cidag report -o report.md           # pentest-ready Markdown
cidag report --format csv -o findings.csv
cidag report --format json -o findings.json

# Real AWS account (read-only IAM permissions required)
cidag scan --profile prod --save data/prod.json
cidag scan -i data/prod.json        # re-analyze saved inventory offline
```

Without installing, prefix commands with `python -m cidag.cli.main` from the repo root.

### Example output

```
============================================================
  CIDAG v1.0  (account 123456789012)
============================================================
  Nodes: 12  Edges: 19  Admins: 1
  Findings: 4
------------------------------------------------------------

 [1] CRITICAL - ESC-02
    Identity: ci-deployer
    Reason: PassRole + Lambda code update
    Fix:  Remove iam:PassRole on privileged roles; restrict lambda code APIs

 [2] CRITICAL - WILDCARD_POLICY
    Identity: admin-role
    Reason: Policy grants Action '*' (full admin potential)

 [3] HIGH - ATTACK_PATH
    Identity: ci-deployer
    Chain: ci-deployer -> admin-role

 [4] HIGH - ATTACK_PATH
    Identity: lambda-exec-role
    Chain: lambda-exec-role -> admin-role
```

### Minimum AWS permissions for scanning

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow",
     "Action": ["iam:List*", "iam:Get*", "sts:GetCallerIdentity"],
     "Resource": "*"}
  ]
}
```

## Detection Rules

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
Collectors (mock / AWS)
        ↓
Normalizer (effective permissions — Deny precedence, wildcards)
        ↓
Graph builder (NetworkX DiGraph)
        ↓
Analysis (escalation rules + path finding + blast radius)
        ↓
CLI + Reports (md / json / csv)
```

## Project Structure

```
cidag/
├── collectors/     # mock + AWS data collection
├── normalizer/     # policy evaluator
├── graph/          # NetworkX graph construction
├── analysis/       # escalation rules + attack path engine
├── reports/        # markdown / json / csv exporters
├── cli/            # command-line interface
└── data/           # mock inventory for offline use
tests/              # pytest suite (offline, no AWS required)
```

## Testing

```bash
pip install -r requirements-dev.txt
pytest -q
pytest --cov=cidag          # coverage report
```

All tests run offline against the bundled mock account — no AWS credentials needed.

## Roadmap

- [ ] Graphical interface (FastAPI + Cytoscape.js)
- [ ] Azure / GCP collectors
- [ ] Permission boundaries & SCP evaluation
- [ ] Attack-path diffing (new risks after every change)
- [ ] Attack simulation mode (prove chains, collect evidence)

## Disclaimer

CIDAG is for **authorized security testing only**. Scan only accounts you own
or have explicit written permission to assess. Misuse may violate laws
(CFAA, Computer Misuse Act, and equivalents).

## License

MIT
