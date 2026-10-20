# Each rule = groups of actions; identity must match ONE action per group.
# Rules with requires_privileged_passrole also need PassRole targeting an ADMIN role.

ESCALATION_RULES = [
    {"id": "ESC-01", "name": "PassRole + EC2 RunInstances",
     "requires": [["iam:PassRole"], ["ec2:RunInstances"]],
     "requires_privileged_passrole": True, "severity": "CRITICAL",
     "remediation": "Remove iam:PassRole on privileged roles; restrict ec2:RunInstances"},

    {"id": "ESC-02", "name": "PassRole + Lambda code update",
     "requires": [["iam:PassRole"], ["lambda:CreateFunction", "lambda:UpdateFunctionCode"]],
     "requires_privileged_passrole": True, "severity": "CRITICAL",
     "remediation": "Remove iam:PassRole on privileged roles; restrict lambda code APIs"},

    {"id": "ESC-03", "name": "PassRole + CloudFormation stack",
     "requires": [["iam:PassRole"], ["cloudformation:CreateStack"]],
     "requires_privileged_passrole": True, "severity": "CRITICAL",
     "remediation": "Remove iam:PassRole on privileged roles; restrict cloudformation:Create*"},

    {"id": "ESC-04", "name": "CreatePolicyVersion self-escalation",
     "requires": [["iam:CreatePolicyVersion"]],
     "severity": "CRITICAL",
     "remediation": "Remove iam:CreatePolicyVersion or scope to specific non-admin policies"},

    {"id": "ESC-05", "name": "Attach managed policy (self-escalation)",
     "requires": [["iam:AttachUserPolicy", "iam:AttachRolePolicy"]],
     "severity": "CRITICAL",
     "remediation": "Remove iam:Attach*Policy or restrict with a permission boundary"},

    {"id": "ESC-06", "name": "Put inline policy (self-escalation)",
     "requires": [["iam:PutUserPolicy", "iam:PutRolePolicy"]],
     "severity": "CRITICAL",
     "remediation": "Remove iam:Put*Policy or restrict with a permission boundary"},

    {"id": "ESC-07", "name": "Create access key on principal",
     "requires": [["iam:CreateAccessKey"]],
     "severity": "HIGH",
     "remediation": "Restrict iam:CreateAccessKey to self only"},

    {"id": "ESC-08", "name": "Rollback policy version",
     "requires": [["iam:SetDefaultPolicyVersion"]],
     "severity": "HIGH",
     "remediation": "Remove iam:SetDefaultPolicyVersion"},

    {"id": "ESC-09", "name": "Permission boundary manipulation",
     "requires": [["iam:PutUserPermissionsBoundary", "iam:DeleteUserPermissionsBoundary",
                   "iam:PutRolePermissionsBoundary", "iam:DeleteRolePermissionsBoundary"]],
     "severity": "HIGH",
     "remediation": "Remove boundary-management permissions"},

    {"id": "ESC-10", "name": "Add user to privileged group",
     "requires": [["iam:AddUserToGroup"]],
     "severity": "HIGH",
     "remediation": "Restrict iam:AddUserToGroup to specific groups"},

    {"id": "ESC-11", "name": "UpdateAssumeRolePolicy (hijack role trust)",
     "requires": [["iam:UpdateAssumeRolePolicy"]],
     "severity": "CRITICAL",
     "remediation": "Remove iam:UpdateAssumeRolePolicy; require review for trust changes"},

    {"id": "ESC-12", "name": "Login profile reset (password takeover)",
     "requires": [["iam:UpdateLoginProfile", "iam:CreateLoginProfile"]],
     "severity": "HIGH",
     "remediation": "Restrict iam:*LoginProfile to self-service flows only"},

    {"id": "ESC-13", "name": "Glue dev endpoint (RCE + role credentials)",
     "requires": [["glue:CreateDevEndpoint"]],
     "severity": "HIGH",
     "remediation": "Remove glue:CreateDevEndpoint or confine to a sandbox account"},
]