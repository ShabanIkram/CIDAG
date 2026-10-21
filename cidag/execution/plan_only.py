"""Techniques CIDAG can plan but deliberately does not execute.

These are high-impact compute/stack primitives. CIDAG proves the finding and
prints a manual, reviewable plan; execution stays with a human operator.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PlanOnlyTechnique:
    id: str
    name: str
    description: str
    preflight: tuple[str, ...]
    required: tuple[str, ...]
    reason: str
    steps: tuple[str, ...]
    cleanup: str
    events: tuple[str, ...]
    event_source: str
    mitre: tuple[str, ...]


PLAN_ONLY: dict[str, PlanOnlyTechnique] = {
    "ESC-01": PlanOnlyTechnique(
        "ESC-01", "PassRole + EC2 RunInstances",
        "Launch an EC2 instance with a privileged instance profile.",
        ("iam:PassRole", "ec2:RunInstances"), ("pass_role",),
        "Launching compute with a privileged instance profile is high-impact "
        "and environment-specific; CIDAG plans the action for a human.",
        (
            "Select a sandbox AMI, subnet, and security group with no inbound "
            "access.",
            "Run: aws ec2 run-instances --image-id <ami> "
            "--instance-type t3.micro --iam-instance-profile "
            "Name=<instance-profile-for-admin-role> --user-data file://probe.sh",
            "Read the role identity from IMDSv2 or SSM, then terminate the "
            "instance and delete created resources.",
        ),
        "Terminate the instance; delete any temporary security group, key pair, "
        "or instance profile.",
        ("RunInstances",), "ec2.amazonaws.com",
        ("T1078.004 Valid Accounts: Cloud Accounts",),
    ),
    "ESC-03": PlanOnlyTechnique(
        "ESC-03", "PassRole + CloudFormation stack",
        "Create a CloudFormation stack that runs under a privileged role.",
        ("iam:PassRole", "cloudformation:CreateStack"), ("pass_role",),
        "Stack templates are arbitrary infrastructure-as-code; CIDAG does not "
        "generate or execute customer templates.",
        (
            "Review a minimal template that creates only a probe resource and "
            "returns its identity.",
            "Run: aws cloudformation create-stack --stack-name cidag-probe "
            "--template-body file://probe.yaml --capabilities CAPABILITY_IAM "
            "--role-arn <admin-role-arn>",
            "Inspect stack events and the probe output, then delete the stack.",
        ),
        "Delete the stack and any retained resources; verify no exports remain.",
        ("CreateStack", "UpdateStack"), "cloudformation.amazonaws.com",
        ("T1078.004 Valid Accounts: Cloud Accounts",),
    ),
    "ESC-13": PlanOnlyTechnique(
        "ESC-13", "Glue dev endpoint (RCE + role credentials)",
        "Create a Glue development endpoint backed by a privileged role.",
        ("glue:CreateDevEndpoint",), (),
        "A Glue dev endpoint exposes an SSH/RCE surface and requires key and "
        "network setup; CIDAG plans it instead of automating remote code.",
        (
            "Create a dev endpoint with the target role and a temporary public "
            "key: aws glue create-dev-endpoint --endpoint-name cidag-probe "
            "--role-arn <role-arn> --public-key file://probe.pub",
            "Connect with the matching private key and confirm the role "
            "identity; do not copy customer data.",
            "Delete the endpoint and the temporary key pair.",
        ),
        "Delete the dev endpoint and the temporary SSH key.",
        ("CreateDevEndpoint",), "glue.amazonaws.com",
        ("T1078.004 Valid Accounts: Cloud Accounts",),
    ),
}


def plan_payload(technique: PlanOnlyTechnique) -> dict:
    return {
        "technique": technique.id,
        "name": technique.name,
        "description": technique.description,
        "executable": False,
        "status": "plan-only",
        "reason": technique.reason,
        "preflight": {"status": "manual", "actions": list(technique.preflight)},
        "required": list(technique.required),
        "steps": list(technique.steps),
        "cleanup": technique.cleanup,
    }
