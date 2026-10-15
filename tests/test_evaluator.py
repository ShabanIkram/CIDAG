from cidag.normalizer.evaluator import (
    action_matches, resource_matches, compute_effective,
)


def test_action_exact_match():
    assert action_matches("s3:GetObject", "s3:GetObject")


def test_action_star_matches_everything():
    assert action_matches("*", "s3:GetObject")
    assert action_matches("*", "iam:PassRole")


def test_action_service_wildcard():
    assert action_matches("s3:*", "s3:GetObject")
    assert not action_matches("s3:*", "ec2:RunInstances")


def test_action_prefix_wildcard():
    assert action_matches("s3:Get*", "s3:GetObject")
    assert not action_matches("s3:Get*", "s3:PutObject")


def test_resource_exact_and_star():
    assert resource_matches("*", "arn:aws:s3:::any")
    assert resource_matches("arn:aws:s3:::bkt", "arn:aws:s3:::bkt")


def test_resource_glob():
    assert resource_matches("arn:aws:s3:::bkt/*", "arn:aws:s3:::bkt/obj.txt")


def test_admin_detected(inventory):
    perms = compute_effective(inventory)
    admin = next(ep for ep in perms.values() if ep.label == "admin-role")
    assert admin.is_admin()


def test_readonly_not_admin(inventory):
    perms = compute_effective(inventory)
    ro = next(ep for ep in perms.values() if ep.label == "readonly-auditor")
    assert not ro.is_admin()
    assert ro.allowed("s3:GetObject")
    assert not ro.allowed("s3:PutObject")


def test_default_deny():
    inv = {"identities": [{"type": "user", "name": "x",
                           "arn": "arn:x", "attached_policies": []}],
           "policies": []}
    perms = compute_effective(inv)
    assert not perms["arn:x"].allowed("s3:GetObject")


def test_deny_beats_allow():
    inv = {
        "identities": [{"type": "user", "name": "x", "arn": "arn:x",
                        "attached_policies": ["arn:p"]}],
        "policies": [{"arn": "arn:p", "name": "p", "statements": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"},
        ]}],
    }
    perms = compute_effective(inv)
    ep = perms["arn:x"]
    assert ep.allowed("ec2:RunInstances")
    assert not ep.allowed("s3:GetObject")