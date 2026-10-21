"""Blue-team detection content for each executable escalation technique."""
from __future__ import annotations

import json

from .plan_only import PLAN_ONLY
from .techniques import TECHNIQUES

_MITRE = {
    "ESC-01": ["T1078.004 Valid Accounts: Cloud Accounts"],
    "ESC-02": ["T1078.004 Valid Accounts: Cloud Accounts", "T1648 Serverless Execution"],
    "ESC-03": ["T1078.004 Valid Accounts: Cloud Accounts"],
    "ESC-04": ["T1098 Account Manipulation", "T1078.004 Valid Accounts: Cloud Accounts"],
    "ESC-05": ["T1098 Account Manipulation", "T1078.004 Valid Accounts: Cloud Accounts"],
    "ESC-06": ["T1098 Account Manipulation", "T1078.004 Valid Accounts: Cloud Accounts"],
    "ESC-07": ["T1098.001 Additional Cloud Credentials", "T1078.004 Valid Accounts: Cloud Accounts"],
    "ESC-08": ["T1098 Account Manipulation", "T1078.004 Valid Accounts: Cloud Accounts"],
    "ESC-09": ["T1098 Account Manipulation", "T1562.008 Impair Defenses: Disable Cloud Logs"],
    "ESC-10": ["T1098 Account Manipulation", "T1078.004 Valid Accounts: Cloud Accounts"],
    "ESC-11": ["T1098 Account Manipulation", "T1078.004 Valid Accounts: Cloud Accounts"],
    "ESC-12": ["T1098.001 Additional Cloud Credentials", "T1078.004 Valid Accounts: Cloud Accounts"],
    "ESC-13": ["T1078.004 Valid Accounts: Cloud Accounts"],
}

_TITLES = {
    "ESC-01": "EC2 instance launched with a privileged instance profile",
    "ESC-02": "Temporary Lambda created under a privileged role",
    "ESC-03": "CloudFormation stack created with a privileged role",
    "ESC-04": "IAM policy version made administrator-equivalent",
    "ESC-05": "Administrator managed policy attached to a principal",
    "ESC-06": "Administrator inline policy attached to a principal",
    "ESC-07": "IAM access key created for an existing principal",
    "ESC-08": "IAM policy default version switched to a privileged version",
    "ESC-09": "IAM permissions boundary removed or replaced",
    "ESC-10": "IAM user added to a privileged group",
    "ESC-11": "IAM role trust policy modified to trust a new principal",
    "ESC-12": "IAM console login profile created",
    "ESC-13": "Glue development endpoint created with a privileged role",
}

_SOURCE = {
    "ESC-01": "ec2.amazonaws.com",
    "ESC-02": "lambda.amazonaws.com",
    "ESC-03": "cloudformation.amazonaws.com",
    "ESC-09": "iam.amazonaws.com",
    "ESC-13": "glue.amazonaws.com",
}
_SOURCE.update({k: "iam.amazonaws.com" for k in TECHNIQUES
                if k.startswith("ESC-") and k not in _SOURCE})


def _sigma(events: list[str], title: str, technique: str, source: str) -> str:
    selection = "\n".join(f"            - {e}" for e in events)
    return (
        "title: CIDAG - " + title + "\n"
        "id: cidag-" + title.lower().replace(" ", "-")[:40] + "\n"
        "status: experimental\n"
        "description: Detects an IAM/Lambda action sequence associated with a "
        "CIDAG authorized escalation technique.\n"
        "logsource:\n"
        "    product: aws\n"
        "    service: cloudtrail\n"
        "detection:\n"
        "    selection:\n"
        f"        eventSource: {source}\n"
        "        eventName:\n"
        + selection + "\n"
        "    condition: selection\n"
        "falsepositives:\n"
        "    - Break-glass or automation using the same API sequence\n"
        "level: high\n"
        "tags:\n"
        + "".join(f"    - attack.{t.split()[0].lower()}\n"
                  for t in _MITRE.get(technique, []))
    )


def _insights(events: list[str], source: str) -> str:
    names = ", ".join(f'"{e}"' for e in events)
    return (
        'fields @timestamp, eventName, userIdentity.arn, sourceIPAddress, '
        'requestParameters, errorCode\n'
        f'| filter eventSource = "{source}" and eventName in [{names}]\n'
        "| sort @timestamp desc\n"
        "| limit 100"
    )


def _eventbridge(events: list[str], source: str) -> dict:
    return {
        "source": ["aws." + source.split(".")[0]],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {"eventSource": [source], "eventName": events},
    }


_CLOUD = {
    "AZ-01": {
        "provider": "azure",
        "title": "Azure Owner role assigned to a principal",
        "source": "azure.activity",
        "events": ["Microsoft.Authorization/roleAssignments/write"],
        "query": (
            "AzureActivity\n"
            '| where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/'
            'ROLEASSIGNMENTS/WRITE"\n'
            "| where ActivityStatusValue =~ \"Success\"\n"
            "| project TimeGenerated, Caller, CallerIpAddress, "
            "OperationNameValue, ResourceId, Properties\n"
            "| order by TimeGenerated desc"),
        "query_language": "Azure Activity Log (KQL)",
        "mitre": ["T1098 Account Manipulation",
                  "T1078.004 Valid Accounts: Cloud Accounts"],
        "response": (
            "Compare the assignment against the engagement manifest. If "
            "unexpected, delete the role assignment with az role assignment "
            "delete and review all actions taken by that principal."),
    },
    "GCP-01": {
        "provider": "gcp",
        "title": "GCP roles/owner granted via setIamPolicy",
        "source": "gcp.audit",
        "events": ["SetIamPolicy"],
        "query": (
            'protoPayload.methodName="SetIamPolicy"\n'
            'protoPayload.serviceName="cloudresourcemanager.googleapis.com"\n'
            'protoPayload.resourceName:"projects/PROJECT_ID"'),
        "query_language": "Cloud Logging query",
        "mitre": ["T1098 Account Manipulation",
                  "T1078.004 Valid Accounts: Cloud Accounts"],
        "response": (
            "Compare the policy delta against the engagement manifest. If "
            "unexpected, restore the previous IAM policy and investigate the "
            "caller's other project-level changes."),
    },
}


def detection_for(technique_id: str) -> dict:
    key = str(technique_id).upper()
    if key in _CLOUD:
        cloud = _CLOUD[key]
        return {
            "technique": key,
            "provider": cloud["provider"],
            "title": cloud["title"],
            "events": list(cloud["events"]),
            "event_source": cloud["source"],
            "sigma": None,
            "insights": cloud["query"],
            "query_language": cloud["query_language"],
            "eventbridge": None,
            "mitre": cloud["mitre"],
            "response": cloud["response"],
        }
    if key in PLAN_ONLY:
        plan = PLAN_ONLY[key]
        all_events = list(plan.events)
        source = plan.event_source
        sigma_events = list(plan.events)
    elif key in TECHNIQUES:
        all_events = [a.split(":", 1)[1] for a in TECHNIQUES[key].preflight]
        source = _SOURCE[key]
        prefix = source.split(".")[0] + ":"
        sigma_events = [a.split(":", 1)[1] for a in TECHNIQUES[key].preflight
                        if a.startswith(prefix)]
    else:
        raise KeyError(technique_id)
    return {
        "technique": key,
        "title": _TITLES[key],
        "events": all_events,
        "event_source": source,
        "provider": "aws",
        "sigma": _sigma(sigma_events, _TITLES[key], key, source),
        "insights": _insights(sigma_events, source),
        "query_language": "CloudWatch Logs Insights",
        "eventbridge": _eventbridge(sigma_events, source),
        "mitre": _MITRE[key],
        "response": (
            "Confirm the caller against the engagement manifest; if unexpected, "
            "revoke the new credential/policy/trust, restore the previous "
            "document from CloudTrail, and rotate exposed secrets."),
    }


def all_detections() -> list[dict]:
    return [detection_for(t) for t in sorted(set(TECHNIQUES) | set(PLAN_ONLY))]


def render_markdown(detections: list[dict] | None = None) -> str:
    detections = detections or all_detections()
    lines = ["# CIDAG Detection Content", "",
             "Each technique CIDAG can execute has matching cloud audit "
             "detection content, including Sigma rules for AWS.", ""]
    for d in detections:
        events_label = ("CloudTrail events" if d["provider"] == "aws"
                        else "Cloud audit events")
        lines += [f"## {d['technique']} - {d['title']}", "",
                  f"**{events_label}:** {', '.join(d['events'])}", "",
                  f"**MITRE ATT&CK:** {', '.join(d['mitre'])}", ""]
        if d.get("sigma"):
            lines += ["### Sigma", "```yaml", d["sigma"], "```", ""]
        lines += [f"### {d['query_language']}", "```", d["insights"], "```", ""]
        if d.get("eventbridge"):
            lines += ["### EventBridge pattern", "```json",
                      json.dumps(d["eventbridge"], indent=2), "```", ""]
        lines += [f"**Response:** {d['response']}", ""]
    return "\n".join(lines)
