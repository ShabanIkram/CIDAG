# CIDAG — Complete Test Inventory (234 passing tests)

This document lists every test in the CIDAG test suite, grouped by module.
For each test it explains **why the test exists** (what risk/behaviour it protects)
and **what its purpose is** (what assertion it makes). All 234 tests pass offline
against bundled mock data — no cloud account or network access is required.

---

## 1. `test_analysis.py` — IAM escalation rule engine

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 1 | `test_wildcard_finding` | Wildcard `Action: *` is the single most common IAM misconfiguration and the foundation of many escalation paths. | Verifies the evaluator flags any identity with `Action: *` on `Resource: *` as a CRITICAL wildcard-admin finding. |
| 2 | `test_passrole_escalation_detected` | `iam:PassRole` combined with a compute/serverless service is the canonical AWS privilege-escalation chain (ESC-01/02/03). | Confirms the engine emits an ESC finding when an identity has both `PassRole` and `RunInstances`/`CreateFunction`/`CreateStack`. |
| 3 | `test_attack_path_found` | A single escalation permission is not enough — defenders need to see the full hop chain from non-admin to admin. | Verifies the graph builder produces a path finding (ATTACK_PATH) from a non-admin identity to an admin role via trust/attach edges. |
| 4 | `test_deny_suppresses_escalation` | Deny statements must always win over Allow statements per AWS IAM semantics. | Confirms that adding a `Deny iam:PassRole` statement removes the corresponding ESC findings for that identity. |
| 5 | `test_blast_radius` | After proving an escalation, the operator needs to know every resource the escalated identity can reach. | Verifies `blast_radius` returns all downstream nodes reachable from an escalated identity. |
| 6 | `test_can_pass_has_no_self_loop` | A self-referential `can-pass` edge would create meaningless cycles in the graph. | Confirms the engine never adds a `can-pass` edge from an identity to itself. |
| 7 | `test_update_assume_role_policy_escalation` | ESC-11 (trust-policy hijack) is a high-impact escalation that only shows up when role trust edges are analysed. | Verifies `iam:UpdateAssumeRolePolicy` on a role fires the ESC-11 finding. |
| 8 | `test_login_profile_escalation` | ESC-12 (console login profile) lets an attacker take over a user account without needing a password reset. | Confirms `iam:CreateLoginProfile`/`UpdateLoginProfile` fires the ESC-12 finding. |
| 9 | `test_glue_dev_endpoint_escalation` | Glue dev endpoints run arbitrary code and can assume roles — a less obvious but real escalation path (ESC-13). | Verifies `glue:CreateDevEndpoint` fires the ESC-13 finding. |
| 10 | `test_esc_rules_do_not_fire_without_permission` | False positives erode trust in the tool. | Confirms that an identity lacking the required IAM action does NOT trigger the corresponding ESC finding. |

---

## 2. `test_boundaries_scps.py` — Permission boundaries & SCP-aware evaluation

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 11 | `test_boundary_blocks_escalation` | AWS permissions boundaries cap the maximum effective permissions; an identity behind a restrictive boundary cannot escalate even if it has `PassRole`/`CreatePolicyVersion`. | Confirms the evaluator honours the boundary document and suppresses ESC findings. |
| 12 | `test_boundary_permitting_action_keeps_escalation` | A boundary that explicitly allows the escalation action must NOT block the finding. | Verifies a permissive boundary keeps the ESC finding alive. |
| 13 | `test_scp_deny_blocks_escalation` | Organizations SCPs apply at the account level and can block escalation actions even if the identity's own policy allows them. | Confirms a `Deny` SCP suppresses the corresponding ESC finding. |
| 14 | `test_deny_only_scp_keeps_admin` | An SCP with only `Deny` statements does not remove admin status — the admin check must still see the wildcard. | Verifies wildcard-admin detection is unaffected by deny-only SCPs. |
| 15 | `test_restrictive_scp_allowlist_removes_admin` | A service-control policy that restricts to an allow-list effectively removes admin status. | Confirms the evaluator downgrades admin status when an SCP allow-list caps permissions. |
| 16 | `test_boundary_suppresses_wildcard_admin` | A boundary that removes `*` should prevent the wildcard-admin finding. | Verifies wildcard detection is boundary-aware. |
| 17 | `test_unresolvable_boundary_denies` | If the boundary policy document cannot be fetched, the safe default is to deny the escalation. | Confirms an unresolvable boundary causes the engine to suppress (not permit) the finding. |
| 18 | `test_inline_boundary_document_supported` | Some inventory sources embed the boundary document inline rather than by ARN. | Verifies the evaluator works with an inline boundary document. |
| 19 | `test_boundary_blocks_passrole_edge` | The `can-pass` graph edge should also respect the boundary. | Confirms PassRole edges are suppressed when the boundary blocks the action. |
| 20 | `test_collector_captures_boundary_policy` | The collector must record the boundary ARN on the identity so the evaluator can use it. | Verifies the AWS collector extracts and stores the permissions boundary. |
| 21 | `test_collector_walks_scp_ancestry` | SCPs are attached at the OU/account level; the collector must walk the ancestry to find them. | Verifies the collector walks the OU tree to collect applicable SCPs. |

---

## 3. `test_builder.py` — Graph construction

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 22 | `test_graph_builds` | The graph is the core data structure; if it fails to build, everything downstream breaks. | Verifies `build_graph` produces a valid NetworkX DiGraph from inventory. |
| 23 | `test_attached_to_edge_exists` | Attached policies create effective permissions; the graph must represent this edge. | Confirms `attached-to` edges exist between identities and their policies. |
| 24 | `test_can_assume_edge_exists` | Role trust relationships create `can-assume` edges that are essential for ESC-11 detection. | Confirms `can-assume` edges are present for trust-policy principals. |
| 25 | `test_summary` | The summary drives the CLI's top-line output; incorrect counts mislead operators. | Verifies node/edge/admin counts in `graph_summary` are accurate. |

---

## 4. `test_cli.py` — Command-line interface

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 26 | `test_scan_json` | JSON output is the CI/automation interface; it must be well-formed. | Verifies `cidag scan --json` emits parseable JSON with findings. |
| 27 | `test_paths_runs` | The `paths` command is the primary operator-facing escalation view. | Confirms `cidag paths` runs without error and prints escalation chains. |
| 28 | `test_blast_runs` | Blast radius is the second operator-facing view. | Confirms `cidag blast` runs and lists reachable resources. |
| 29 | `test_report_md` | Markdown reports are the human-readable deliverable. | Verifies `cidag report --format md` produces a non-empty markdown file. |
| 30 | `test_live_without_credentials_aborts` | A live scan with dead credentials must fail fast rather than emit fabricated "absent" findings. | Confirms `--live` without valid credentials returns a non-zero exit. |
| 31 | `test_live_bad_profile_aborts` | A mistyped profile must not silently fall back to the default credential chain. | Confirms `--profile nonexistent` aborts. |
| 32 | `test_live_collector_failure_aborts` | Collector errors must propagate as failures, not empty results. | Confirms collector exceptions are surfaced as a non-zero exit. |

---

## 5. `test_cloud_collectors.py` — Azure / GCP collectors

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 33 | `test_azure_normalize_role_defs_and_assignments` | Azure RBAC must be normalized into the same AWS-style inventory shape so the existing graph/analysis works unchanged. | Verifies Azure role definitions and assignments are correctly normalized. |
| 34 | `test_gcp_normalize_bindings_and_roles` | GCP IAM bindings must be normalized similarly. | Verifies GCP bindings and roles are correctly normalized. |
| 35 | `test_mock_collector_selects_cloud_file` | Offline mode must load the correct bundled mock per cloud. | Confirms `MockCollector(cloud="azure")` and `cloud="gcp"` load the right inventory. |
| 36 | `test_azure_scan_offline_policy_findings` | The policy scanner must produce findings from the Azure mock inventory. | Verifies Azure offline scan emits POL-001/POL-002 findings. |
| 37 | `test_gcp_scan_offline_policy_findings` | Same for GCP. | Verifies GCP offline scan emits POL-001/002/003 findings. |
| 38 | `test_graph_renders_azure_inventory` | The graph renderer must handle Azure inventories. | Confirms `cidag graph --cloud azure` produces valid output. |
| 39 | `test_aws_only_module_rejected_for_azure` | AWS-only modules (s3, ec2) must not silently run against Azure. | Verifies `--cloud azure --modules s3` is rejected. |
| 40 | `test_cloud_mock_report` | Reports must work for Azure/GCP inventories. | Confirms `cidag report --cloud gcp` produces a valid report. |
| 41 | `test_cloud_service_principals_get_escalation_findings` | Azure service principals and GCP service accounts can escalate — not just IAM users/roles. | Verifies AZ-01 and GCP-01 findings are generated for cloud service principals. |

---

## 6. `test_compliance.py` — Compliance tagging & filtering

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 42 | `test_tags_for_known_controls` | Findings must map to CIS/PCI control IDs for compliance reporting. | Verifies known check IDs are tagged with the correct control mappings. |
| 43 | `test_tags_for_escalation_and_cve` | ESC findings and CVE findings also need compliance tags. | Confirms ESC and CVE findings receive appropriate control tags. |
| 44 | `test_unknown_check_has_no_tags` | Unknown checks must not fabricate compliance mappings. | Verifies unknown check IDs get no tags. |
| 45 | `test_attach_and_summary` | The compliance summary drives the `--compliance` report header. | Confirms `attach_compliance` and summary counts are correct. |
| 46 | `test_filter_by_framework` | Operators need framework-specific views (CIS-only, PCI-only). | Verifies `filter_compliance` returns only findings for the requested framework. |
| 47 | `test_sarif_export_includes_compliance` | SARIF exports must carry compliance tags for GitHub code scanning. | Confirms the SARIF export includes compliance metadata. |
| 48 | `test_report_markdown_has_compliance_section` | The markdown report should show a compliance section when compliance data is present. | Verifies the report includes a compliance section. |
| 49 | `test_report_can_filter_by_framework` | `cidag report --compliance cis` must filter correctly. | Confirms framework filtering works end-to-end in the report. |

---

## 7. `test_cve.py` — CVE correlation engine

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 50 | `test_parse_version` | Version parsing is the foundation of CPE matching. | Verifies `parse_version` correctly splits and orders version components. |
| 51 | `test_version_lt` | Version comparison must handle multi-component versions (e.g. 1.2.3 < 1.2.10). | Verifies `version_lt` returns correct results. |
| 52 | `test_version_lte` | Same for `<=`. | Verifies `version_lte`. |
| 53 | `test_cpe_string_escaping` | CPE strings require special escaping for special characters. | Verifies escaping of `:`, `?`, `*`, `\` in CPE URIs. |
| 54 | `test_match_cpe_wildcards` | CPE wildcards (`*`) must match any value. | Verifies wildcard matching in CPE comparisons. |
| 55 | `test_seed_rules_fire_on_vulnerable_version` | Seed rules are the offline fallback when no NVD mirror is available. | Verifies a seed rule fires on a known-vulnerable version. |
| 56 | `test_seed_rules_ignore_patched_version` | Seed rules must not fire on patched versions. | Confirms patched versions do not trigger seed rules. |
| 57 | `test_seed_ignores_versionless_service` | Versionless services cannot be reliably matched. | Verifies the engine skips versionless service entries. |
| 58 | `test_engine_correlate_seeds_offline` | The CVE engine must work fully offline using seed data. | Verifies offline CVE correlation produces correct findings. |
| 59 | `test_cve_severity_mapping` | CVE severities must map to CIDAG severity levels. | Verifies the CVSS-to-severity mapping. |
| 60 | `test_no_nvd_never_touches_network` | The engine must never make network calls when `--no-nvd` is set. | Verifies no network access occurs in offline mode. |
| 61 | `test_seed_rules_respect_affected_from` | Some CVEs only affect versions from a certain release onward. | Verifies `affected_from` boundaries are honoured. |
| 62 | `test_vsftpd_seed_only_exact_backdoored_version` | The classic vsftpd 2.3.4 backdoor should only match the exact vulnerable version. | Verifies the vsftpd seed rule is version-exact. |

---

## 8. `test_ec2_checks.py` — EC2 / RDS / CloudTrail security checks

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 63 | `test_sg_ssh_world_open` | SSH open to `0.0.0.0/0` is a critical finding. | Verifies the SG check flags SSH open to the world. |
| 64 | `test_sg_rdp_world_open` | RDP open to `0.0.0.0/0` is a critical finding. | Verifies the SG check flags RDP open to the world. |
| 65 | `test_sg_ssh_only_reports_one_not_both` | An SG with only SSH open should not also report RDP. | Verifies the check does not double-report. |
| 66 | `test_sg_private_cidr_no_finding` | Private CIDRs are not world-open. | Verifies no finding is emitted for private CIDR sources. |
| 67 | `test_sg_all_traffic` | `0.0.0.0/0` on all ports is the worst-case misconfiguration. | Verifies the all-traffic check fires. |
| 68 | `test_sg_high_port_mysql` | MySQL (3306) open to the world is a common misconfiguration. | Verifies the high-port check fires for MySQL. |
| 69 | `test_unencrypted_ebs` | Unencrypted EBS volumes expose data at rest. | Verifies the EBS encryption check. |
| 70 | `test_imdsv1` | IMDSv1 is vulnerable to SSRF-based credential theft. | Verifies the IMDS version check. |
| 71 | `test_rds_checks` | RDS instances must be checked for public access and encryption. | Verifies RDS security checks. |
| 72 | `test_cloudtrail_none` | No CloudTrail means no audit trail — a critical finding. | Verifies the CloudTrail-absent check. |
| 73 | `test_cloudtrail_bad_trail` | A misconfigured trail (e.g. single-region, log validation off) is a finding. | Verifies the CloudTrail misconfiguration check. |
| 74 | `test_cloudtrail_good_trail` | A properly configured trail should not produce findings. | Verifies no false positive for a good trail. |

---

## 9. `test_evaluator.py` — Effective permission evaluator

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 75 | `test_action_exact_match` | Exact action matching is the baseline evaluator behaviour. | Verifies `iam:GetUser` matches `iam:GetUser`. |
| 76 | `test_action_star_matches_everything` | `Action: *` must match every action. | Verifies wildcard matching. |
| 77 | `test_action_service_wildcard` | `s3:*` must match all S3 actions but not EC2 actions. | Verifies service-level wildcard matching. |
| 78 | `test_action_prefix_wildcard` | `s3:Get*` must match `s3:GetObject` but not `s3:PutObject`. | Verifies prefix wildcard matching. |
| 79 | `test_resource_exact_and_star` | Resource matching must handle exact ARNs and `*`. | Verifies resource matching. |
| 80 | `test_resource_glob` | Resource ARNs often use wildcards (`arn:aws:s3:::*`). | Verifies resource glob matching. |
| 81 | `test_admin_detected` | Admin detection is the foundation of escalation analysis. | Verifies `Action: *` on `Resource: *` is detected as admin. |
| 82 | `test_readonly_not_admin` | Read-only permissions must not be classified as admin. | Verifies read-only identities are not admin. |
| 83 | `test_default_deny` | Unmatched actions must default to deny. | Verifies default-deny semantics. |
| 84 | `test_deny_beats_allow` | Deny statements override Allow statements. | Verifies Deny precedence. |

---

## 10. `test_execution_engine.py` — Authorized exploitation engine

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 85 | `test_canonical_arn_and_role_name` | Assumed-role session ARNs must be converted to the underlying IAM role ARN for correct policy simulation. | Verifies `canonical_iam_arn` handles STS assumed-role ARNs. |
| 86 | `test_guard_refuses_without_explicit_authorization` | The authorization gate must refuse mutation if no account is explicitly authorized. | Verifies `GuardError` is raised when `authorized_accounts` is empty. |
| 87 | `test_guard_refuses_account_mismatch` | Caller account must match the authorized account. | Verifies account mismatch is rejected. |
| 88 | `test_guard_wraps_credential_errors` | Credential failures must be surfaced as GuardError, not raw botocore exceptions. | Verifies credential errors are wrapped. |
| 89 | `test_guard_confirmation_phrase` | The TTY confirmation phrase must match exactly. | Verifies the confirmation phrase check. |
| 90 | `test_guard_refuses_non_tty` | Non-interactive runs must not silently proceed. | Verifies non-TTY refusal. |
| 91 | `test_guard_simulation_denied_and_unknown` | IAM policy simulation must be checked before mutation. | Verifies denied/unknown simulation results are handled correctly. |
| 92 | `test_redaction_of_secret_fields_and_text` | Secrets must never be written to audit logs or manifests. | Verifies `redact` and `redact_text` scrub secret-bearing fields. |
| 93 | `test_run_requires_scan_evidence` | Every run must be backed by a scan finding (or `--allow-unproven`). | Verifies the run refuses without evidence. |
| 94 | `test_run_uses_matching_report_finding` | The matching finding must be used to bind the run to the scan. | Verifies the matching finding is correctly identified. |
| 95 | `test_run_refuses_report_without_matching_principal` | A report for a different principal must not authorize this run. | Verifies principal mismatch is rejected. |
| 96 | `test_load_sarif_report_and_match` | SARIF is the CI/CD interchange format; findings must load from it. | Verifies SARIF loading and finding matching. |
| 97 | `test_plan_only_entries_are_listed_and_runnable_only_as_plans` | Plan-only entries must be listed but not executable. | Verifies plan-only listing and run refusal. |
| 98 | `test_plan_is_read_only` | Planning must never make mutating API calls. | Verifies the plan uses only read-only APIs. |
| 99 | `test_plan_uses_principal_specific_preflight` | Preflight simulation must target the caller's principal. | Verifies the principal ARN is used in simulation. |
| 100 | `test_esc11_plan_uses_full_role_arn_as_resource` | ESC-11 resource must be the full role ARN, not just the name. | Verifies resource ARN correctness. |
| 101 | `test_esc05_refuses_when_policy_already_attached` | Re-running ESC-05 on an already-attached policy must not duplicate. | Verifies idempotency refusal. |
| 102 | `test_esc10_refuses_existing_group_membership` | Re-running ESC-10 on an existing member must not duplicate. | Verifies idempotency refusal. |
| 103 | `test_keep_refused_for_credential_issuing_techniques` | `--keep` for credential-issuing techniques would leave secrets exposed. | Verifies the refusal. |
| 104 | `test_esc05_attaches_verifies_and_rolls_back` | The full ESC-05 lifecycle: attach → verify → rollback. | Verifies attach, verification, and rollback. |
| 105 | `test_esc05_verification_failure_rolls_back` | Verification failure must trigger rollback. | Verifies rollback on verification failure. |
| 106 | `test_esc04_creates_sets_and_restores_version` | ESC-04 lifecycle: create version → set default → restore. | Verifies the full ESC-04 lifecycle. |
| 107 | `test_esc07_secret_never_persisted` | ESC-07 issues an access key; the secret must never be written to disk. | Verifies secret redaction. |
| 108 | `test_esc11_trust_hijack_restores_original_policy` | ESC-11 must restore the original trust policy on rollback. | Verifies trust policy restoration. |
| 109 | `test_esc02_lambda_probe_creates_invokes_and_deletes` | ESC-02 lifecycle: create function → invoke → delete. | Verifies the full ESC-02 lifecycle. |
| 110 | `test_esc06_put_inline_policy_and_rollback` | ESC-06 lifecycle: put inline policy → delete on rollback. | Verifies the full ESC-06 lifecycle. |
| 111 | `test_esc08_sets_default_and_restores_it` | ESC-08 lifecycle: set default → restore. | Verifies the full ESC-08 lifecycle. |
| 112 | `test_esc09_removes_boundary_and_restores_it` | ESC-09 lifecycle: remove boundary → restore. | Verifies the full ESC-09 lifecycle. |
| 113 | `test_esc09_requires_a_boundary_or_explicit_replacement` | ESC-09 must require a replacement boundary or explicit confirmation. | Verifies the requirement. |
| 114 | `test_esc10_adds_group_and_removes_itself` | ESC-10 lifecycle: add to group → remove on rollback. | Verifies the full ESC-10 lifecycle. |
| 115 | `test_esc12_creates_login_profile_and_deletes_it` | ESC-12 lifecycle: create login profile → delete on rollback. | Verifies the full ESC-12 lifecycle. |
| 116 | `test_keep_leaves_artifact_and_cleanup_manifest_restores` | `--keep` must leave artifacts and the cleanup manifest must restore them. | Verifies keep + cleanup. |
| 117 | `test_cleanup_applies_in_reverse_order` | Cleanup must reverse the order of operations. | Verifies reverse-order cleanup. |
| 118 | `test_cleanup_encodes_trust_policy_document` | Trust policy documents must be correctly encoded in cleanup operations. | Verifies JSON encoding. |
| 119 | `test_report_and_demo_mask_accounts` | Reports and demo outputs must mask account IDs. | Verifies account masking. |
| 120 | `test_audit_log_redacts_and_writes` | Audit logs must be written and redacted. | Verifies audit log creation and redaction. |
| 121 | `test_detections_cover_every_technique` | Every technique must have matching detection content. | Verifies detection coverage. |
| 122 | `test_plan_read_error_becomes_exploit_error` | Read errors during planning must be wrapped as ExploitError. | Verifies error wrapping. |
| 123 | `test_rollback_failure_is_reported_not_hidden` | Rollback failures must be surfaced, not silently swallowed. | Verifies rollback failure reporting. |
| 124 | `test_canary_is_read_back_and_deleted` | Canary impact proof must be read back and then deleted. | Verifies canary lifecycle. |
| 125 | `test_canary_auto_falls_back_to_s3` | `--canary auto` must fall back to S3 if Secrets Manager is unavailable. | Verifies auto-fallback. |
| 126 | `test_pacu_whoami_parse_and_module_allowlist` | Pacu bridge must parse `whoami` and enforce the module allowlist. | Verifies Pacu bridge safety. |
| 127 | `test_pacu_account_mismatch_refused` | Pacu account must match the authorized account. | Verifies account check. |
| 128 | `test_pacu_missing_binary_refused` | Missing Pacu binary must be refused. | Verifies binary check. |
| 129 | `test_azure_owner_assignment_runs_and_rolls_back` | AZ-01 full lifecycle: assign Owner → verify → rollback. | Verifies the full AZ-01 lifecycle. |
| 130 | `test_azure_technique_rejected_on_aws_session` | AZ-01 must not run on an AWS session. | Verifies provider rejection. |
| 131 | `test_gcp_owner_binding_runs_and_restores_policy` | GCP-01 full lifecycle: grant roles/owner → verify → restore. | Verifies the full GCP-01 lifecycle. |
| 132 | `test_gcp_keep_is_refused` | `--keep` must be refused for GCP sessions. | Verifies keep refusal. |
| 133 | `test_azure_scope_cannot_leave_authorized_subscription` | AZ-01 scope must stay within the authorized subscription. | Verifies scope containment. |
| 134 | `test_chain_plan_is_read_only` | Chain planning must not mutate anything. | Verifies chain plan is read-only. |
| 135 | `test_chain_run_executes_steps_and_rolls_back_in_reverse` | Chain execution must roll back in reverse order. | Verifies reverse rollback. |
| 136 | `test_chain_failure_midway_rolls_back_completed_steps` | Mid-chain failure must roll back completed steps. | Verifies mid-chain rollback. |
| 137 | `test_chain_rejects_duplicates_and_plan_only_steps` | Chain must reject duplicates and plan-only steps. | Verifies chain validation. |
| 138 | `test_chain_report_lists_steps_and_detections` | Chain report must list steps and detections. | Verifies chain report rendering. |

---

## 11. `test_finding.py` — Finding schema

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 139 | `test_finding_from_dict_roundtrip` | Findings must survive serialization/deserialization without loss. | Verifies dict round-trip. |
| 140 | `test_finding_stable_id` | Finding IDs must be stable across runs for diff tracking. | Verifies ID stability. |
| 141 | `test_finding_to_dict_serialisable` | Finding dicts must be JSON-serialisable. | Verifies serializability. |
| 142 | `test_severity_ordering` | Severity ordering drives sorting and filtering. | Verifies severity ordering. |
| 143 | `test_severity_parse_string_and_int` | Severity must parse from strings and integers. | Verifies severity parsing. |

---

## 12. `test_guardrails.py` — Azure deny assignments / GCP organization policies

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 144 | `test_azure_deny_assignment_normalizes_to_guardrail` | Guardrails only work if deny assignments keep their principals, scope, and NotActions. | Verifies Azure deny assignments normalize into the `guardrails` inventory shape. |
| 145 | `test_azure_deny_assignment_without_permissions_is_dropped` | A deny assignment with no permissions denies nothing and must not become an empty, misleading guardrail. | Verifies permission-less deny assignments are dropped. |
| 146 | `test_azure_deny_assignment_suppresses_az01` | Reporting an escalation the tenant has already blocked is a false positive. | Verifies AZ-01 fires without the guardrail and is suppressed with it. |
| 147 | `test_azure_deny_assignment_exclusion_keeps_az01` | Azure's `excludePrincipals` exempts a principal from the deny; losing that would under-report. | Verifies an excluded principal keeps its escalation finding. |
| 148 | `test_azure_deny_assignment_not_actions_carve_out` | `NotActions` subtracts from the deny; ignoring it would over-suppress findings. | Verifies carved-out actions stay allowed while the rest stay denied. |
| 149 | `test_azure_deny_assignment_scoped_to_named_principals` | A guardrail must not leak onto identities it does not name. | Verifies only the named principal loses the action and AZ-01. |
| 150 | `test_azure_deny_assignment_applies_data_actions` | Data-plane denials (`DataActions`) matter as much as control-plane ones. | Verifies data actions collapse into the deny statement. |
| 151 | `test_azure_deny_assignment_collection_degrades_to_warning` | A principal without `denyAssignments/read` must still get a full RBAC scan. | Verifies missing permission warns and returns `[]` like SCP collection. |
| 152 | `test_gcp_org_policy_enforced_rule_becomes_guardrail` | Only enforced rules restrict anything; list rules restrict values, not actions. | Verifies enforced boolean rules map to a resource-wide deny guardrail. |
| 153 | `test_gcp_org_policy_blocks_key_creation_only` | Over-suppressing would hide real escalation paths. | Verifies key creation is denied while setIamPolicy and admin status survive. |
| 154 | `test_gcp_custom_constraint_maps_resource_and_method` | Custom constraints name a resource type and method, not an IAM permission. | Verifies the resource/method pair maps to the right denied permission. |
| 155 | `test_gcp_allow_custom_constraint_is_not_expressed` | An ALLOW constraint is a CEL-gated allow-list CIDAG cannot evaluate per action. | Verifies ALLOW constraints are recorded but deny nothing. |
| 156 | `test_gcp_unmapped_constraint_recorded_without_statements` | Constraints CIDAG cannot map must still be visible in the inventory. | Verifies unmapped constraints are recorded with no statements. |
| 157 | `test_gcp_org_policy_collection_is_best_effort` | A principal without `orgpolicy.policies.list` must still get a full IAM scan. | Verifies missing SDK/permission warns and returns an empty result. |
| 158 | `test_guardrail_statement_never_grants` | Guardrails are deny-only; an Allow effect must not widen permissions. | Verifies a guardrail cannot grant an action the identity lacks. |
| 159 | `test_guardrail_without_principals_applies_to_everyone` | GCP org policies bind resources, so they gate every identity. | Verifies a missing `principals` key means "all identities". |
| 160 | `test_guardrail_without_matching_principals_touches_nobody` | A guardrail naming an absent principal must not suppress anything. | Verifies non-matching principals leave permissions intact. |
| 161 | `test_inventory_without_guardrails_key_is_unchanged` | AWS inventories predate the field; the evaluator must not regress them. | Verifies a missing `guardrails` key behaves as "no guardrails". |
| 162 | `test_guardrail_blocks_passrole_edge_and_escalation` | Guardrails must gate graph edges, not just rule matching. | Verifies a denied `iam:PassRole` removes the can-pass edge, ESC-02, and ATTACK_PATH. |
| 163 | `test_guardrail_suppresses_wildcard_admin_finding` | A wildcard blocked by a guardrail is not effective admin. | Verifies `is_admin()` and wildcard findings respect guardrails. |
| 164 | `test_mock_azure_deny_assignment_suppresses_platform_admin` | The bundled mock must exercise guardrail suppression end to end. | Verifies the Azure mock drops AZ-01 only for `platform-admins`. |
| 165 | `test_mock_gcp_org_policy_blocks_service_account_key_creation` | The bundled mock must exercise GCP guardrails end to end. | Verifies the GCP mock blocks key creation without touching escalation. |

---

## 13. `test_imports.py` — External tool import parsers

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 166 | `test_parse_nmap_xml` | Nmap XML is the most common network scan import format. | Verifies Nmap XML parsing. |
| 167 | `test_parse_nuclei_json` | Nuclei JSON is the most common web vulnerability import format. | Verifies Nuclei JSON parsing. |
| 168 | `test_parse_prowler_json` | Prowler JSON is a common AWS security audit import format. | Verifies Prowler JSON parsing. |
| 169 | `test_inspector_mapper_extracts_cve` | AWS Inspector findings must be mapped to CIDAG findings with CVE IDs. | Verifies Inspector mapping. |
| 170 | `test_sechub_mapper_cve_and_severity` | AWS Security Hub findings must be mapped with CVE and severity. | Verifies Security Hub mapping. |
| 171 | `test_sechub_severity_normalized_fallback` | Security Hub severities must be normalized even when the mapping is incomplete. | Verifies severity normalization fallback. |
| 172 | `test_import_scanner_unknown_format` | Unknown import formats must be rejected. | Verifies format rejection. |

---

## 14. `test_network_scope.py` — Network scanner scope guard

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 173 | `test_expand_cidr_to_hosts` | CIDR expansion is the foundation of network scanning. | Verifies correct host expansion. |
| 174 | `test_expand_refuses_oversized_range` | Oversized ranges must be refused to prevent accidental scans. | Verifies range size limit. |
| 175 | `test_expand_single_ip` | Single IPs must be handled correctly. | Verifies single-IP expansion. |
| 176 | `test_expand_skips_private_without_flag` | Private IPs must not be scanned without `--allow-private`. | Verifies private IP refusal. |
| 177 | `test_scan_host_bounds_concurrency_per_probe` | Concurrency must be bounded to avoid overwhelming targets. | Verifies concurrency bounds. |
| 178 | `test_scanner_enforces_scope_before_scan` | Scope enforcement must happen before any network I/O. | Verifies pre-scan scope check. |
| 179 | `test_scanner_refuses_out_of_scope_private` | Out-of-scope private IPs must be refused. | Verifies out-of-scope refusal. |
| 180 | `test_scanner_skips_without_targets` | No targets means no scan. | Verifies no-target behaviour. |

---

## 15. `test_nuclei_live.py` — Nuclei bridge

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 181 | `test_nuclei_requires_targets` | Nuclei must not run without targets. | Verifies target requirement. |
| 182 | `test_private_target_blocked_by_scope` | Private targets must be blocked by the scope guard. | Verifies scope enforcement. |
| 183 | `test_nuclei_binary_missing_skips` | Missing Nuclei binary must be skipped, not crash. | Verifies graceful skip. |
| 184 | `test_subprocess_failure_returns_empty` | Subprocess failures must return empty results, not crash. | Verifies graceful failure. |
| 185 | `test_live_bridge_parses_findings` | The bridge must parse Nuclei findings into CIDAG findings. | Verifies finding parsing. |

---

## 16. `test_org.py` — AWS Organizations multi-account scanning

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 186 | `test_all_accounts_requires_live` | `--all-accounts` must require `--live`. | Verifies the requirement. |
| 187 | `test_account_id_filter` | `--account-id` must filter the account list. | Verifies filtering. |
| 188 | `test_all_accounts_tags_every_finding` | Findings from multi-account scans must be tagged with the account ID. | Verifies account tagging. |
| 189 | `test_assume_role_failure_aborts` | Role assumption failure must abort, not silently skip. | Verifies abort on failure. |
| 190 | `test_list_accounts_failure_aborts` | Account listing failure must abort. | Verifies abort on failure. |

---

## 17. `test_policy_checks.py` — IAM policy least-privilege checks

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 191 | `test_wildcard_admin_policy` | Wildcard admin is the most critical policy misconfiguration. | Verifies the wildcard-admin check. |
| 192 | `test_wildcard_admin_suppresses_secondary_findings` | If wildcard admin is already flagged, secondary findings are redundant. | Verifies suppression. |
| 193 | `test_privilege_escalation_policy` | Policies with escalation actions must be flagged. | Verifies the escalation check. |
| 194 | `test_data_exfil_policy` | Policies with data-exfiltration actions must be flagged. | Verifies the exfil check. |
| 195 | `test_service_wildcard_counts_as_exfil` | Service-level wildcards (`s3:*`) count as potential exfil. | Verifies service-wildcard classification. |
| 196 | `test_deny_statements_ignored` | Deny statements must not trigger Allow-based findings. | Verifies deny handling. |
| 197 | `test_scoped_policy_has_no_findings` | Least-privilege policies must not produce findings. | Verifies no false positives. |
| 198 | `test_condition_removes_exfil_finding` | Conditions that restrict actions should remove the exfil finding. | Verifies condition handling. |
| 199 | `test_wildcard_trust_principal` | Wildcard trust principals (`Principal: *`) are a critical finding. | Verifies trust-principal check. |

---

## 18. `test_s3_checks.py` — S3 bucket security checks

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 200 | `test_public_acl` | Public ACLs are a common S3 misconfiguration. | Verifies the public-ACL check. |
| 201 | `test_private_acl_no_finding` | Private ACLs must not produce findings. | Verifies no false positive. |
| 202 | `test_public_policy_wildcard` | Public bucket policies must be flagged. | Verifies the public-policy check. |
| 203 | `test_no_encryption` | Unencrypted buckets must be flagged. | Verifies the encryption check. |
| 204 | `test_encrypted_no_finding` | Encrypted buckets must not produce findings. | Verifies no false positive. |
| 205 | `test_insecure_transport_detects_tls_deny` | Bucket policies that deny TLS must be flagged. | Verifies the transport check. |
| 206 | `test_mfa_delete_and_versioning` | MFA delete and versioning are security-relevant bucket settings. | Verifies the MFA-delete/versioning check. |
| 207 | `test_pab_incomplete_and_complete` | Public access block configuration must be checked. | Verifies the PAB check. |
| 208 | `test_policy_public_flag_from_collector` | The collector must extract the public flag. | Verifies collector extraction. |
| 209 | `test_scanner_runs_over_inventory` | The S3 scanner must run over the full inventory. | Verifies scanner integration. |

---

## 19. `test_sarif_diff.py` — SARIF export and diff

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 210 | `test_sarif_structure` | SARIF must conform to the 2.1.0 schema. | Verifies SARIF structure. |
| 211 | `test_cli_report_sarif` | `cidag report --format sarif` must produce valid SARIF. | Verifies CLI SARIF export. |
| 212 | `test_diff_json_format` | `cidag diff --format json` must produce parseable JSON. | Verifies diff JSON format. |
| 213 | `test_diff_text_new_and_fixed` | The text diff must show new and fixed findings. | Verifies diff text output. |
| 214 | `test_diff_severity_change` | Severity changes must be tracked. | Verifies severity-change tracking. |
| 215 | `test_diff_falls_back_to_module_check_target_key` | The diff must fall back to a composite key when no stable ID is available. | Verifies key fallback. |

---

## 20. `test_scope.py` — Scope guard

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 216 | `test_public_ip_in_public_cidr_in_scope` | Public IPs in public CIDRs are in scope. | Verifies in-scope detection. |
| 217 | `test_private_denied_without_allow_private_even_if_listed` | Private IPs require explicit `--allow-private`. | Verifies private IP refusal. |
| 218 | `test_private_allowed_with_allow_private` | `--allow-private` must permit private IPs. | Verifies allow-private behaviour. |
| 219 | `test_out_of_scope_raises` | Out-of-scope IPs must raise an error. | Verifies out-of-scope refusal. |
| 220 | `test_multiple_networks` | Multiple CIDRs must be supported. | Verifies multi-CIDR support. |
| 221 | `test_account_allowlist` | Account allowlist must restrict scanning. | Verifies account filtering. |
| 222 | `test_empty_scope_denies_everything` | Empty scope must deny everything. | Verifies empty-scope denial. |
| 223 | `test_invalid_ip_not_in_scope` | Invalid IPs must not be in scope. | Verifies invalid-IP handling. |

---

## 21. `test_viz.py` — Graph visualization

| # | Test | Why this test exists | Purpose |
|---|------|---------------------|---------|
| 224 | `test_svg_valid_xml_with_all_labels` | SVG output must be valid XML with all node labels present. | Verifies SVG validity. |
| 225 | `test_svg_highlights_admin_nodes` | Admin nodes must be visually distinct. | Verifies admin highlighting. |
| 226 | `test_svg_handles_cycles` | Graph cycles must not crash the SVG renderer. | Verifies cycle handling. |
| 227 | `test_dot_output` | DOT (Graphviz) output must be valid. | Verifies DOT output. |
| 228 | `test_mermaid_lists_nodes_and_edges` | Mermaid output must list all nodes and edges. | Verifies Mermaid output. |
| 229 | `test_mermaid_escapes_quotes` | Mermaid labels with quotes must be escaped. | Verifies quote escaping. |
| 230 | `test_cli_graph_svg_to_file` | `cidag graph --format svg -o file` must write a file. | Verifies CLI SVG output. |
| 231 | `test_cli_graph_mermaid_stdout` | `cidag graph --format mermaid` must print to stdout. | Verifies CLI Mermaid output. |
| 232 | `test_cli_graph_text_default_unchanged` | Default graph output must remain text. | Verifies default format. |
| 233 | `test_cli_paths_mermaid` | `cidag paths --format mermaid` must produce Mermaid output. | Verifies CLI paths Mermaid. |
| 234 | `test_paths_mermaid_merges_shared_targets` | Paths with shared targets must be merged in Mermaid output. | Verifies target merging. |

---

## Summary

| Module | Tests | Focus |
|--------|-------|-------|
| `test_analysis.py` | 10 | IAM escalation rule engine |
| `test_boundaries_scps.py` | 11 | Permission boundaries & SCP-aware evaluation |
| `test_builder.py` | 4 | Graph construction |
| `test_cli.py` | 7 | Command-line interface |
| `test_cloud_collectors.py` | 9 | Azure / GCP collectors |
| `test_compliance.py` | 8 | Compliance tagging & filtering |
| `test_cve.py` | 13 | CVE correlation engine |
| `test_ec2_checks.py` | 12 | EC2 / RDS / CloudTrail security checks |
| `test_evaluator.py` | 10 | Effective permission evaluator |
| `test_execution_engine.py` | 54 | Authorized exploitation engine |
| `test_finding.py` | 5 | Finding schema |
| `test_guardrails.py` | 22 | Azure deny assignments / GCP organization policies |
| `test_imports.py` | 7 | External tool import parsers |
| `test_network_scope.py` | 8 | Network scanner scope guard |
| `test_nuclei_live.py` | 5 | Nuclei bridge |
| `test_org.py` | 5 | AWS Organizations multi-account scanning |
| `test_policy_checks.py` | 9 | IAM policy least-privilege checks |
| `test_s3_checks.py` | 10 | S3 bucket security checks |
| `test_sarif_diff.py` | 6 | SARIF export and diff |
| `test_scope.py` | 8 | Scope guard |
| `test_viz.py` | 11 | Graph visualization |
| **Total** | **234** | |
