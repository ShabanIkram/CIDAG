"""Live EC2/RDS/CloudTrail collector (read-only)."""
from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError


def collect_ec2(session) -> dict:
    ec2 = session.client("ec2")
    out: dict = {"security_groups": [], "instances": [], "volumes": []}

    # Security groups (all regions handled by caller; here single session region)
    try:
        for sg in ec2.describe_security_groups().get("SecurityGroups", []):
            def _rules(raw):
                rules = []
                for r in raw:
                    rules.append({
                        "protocol": r.get("IpProtocol"),
                        "from_port": r.get("FromPort"),
                        "to_port": r.get("ToPort"),
                        "cidrs": [p.get("CidrIp") for p in r.get("IpRanges", []) if p.get("CidrIp")],
                        "ipv6": [p.get("CidrIpv6") for p in r.get("Ipv6Ranges", []) if p.get("CidrIpv6")],
                    })
                return rules
            out["security_groups"].append({
                "group_id": sg.get("GroupId"),
                "group_name": sg.get("GroupName"),
                "description": sg.get("Description"),
                "ingress": _rules(sg.get("IpPermissions", [])),
                "egress": _rules(sg.get("IpPermissionsEgress", [])),
            })
    except (ClientError, BotoCoreError) as e:
        print(f"[!] ec2 security_groups: {e}")

    # Instances (IMDS options)
    try:
        for res in ec2.describe_instances().get("Reservations", []):
            for inst in res.get("Instances", []):
                md = inst.get("MetadataOptions", {})
                out["instances"].append({
                    "instance_id": inst.get("InstanceId"),
                    "public_ip": inst.get("PublicIpAddress"),
                    "private_ip": inst.get("PrivateIpAddress"),
                    "imds_v2": md.get("HttpTokens") == "required",
                    "security_groups": [g.get("GroupId") for g in inst.get("SecurityGroups", [])],
                })
    except (ClientError, BotoCoreError) as e:
        print(f"[!] ec2 instances: {e}")

    # EBS volumes
    try:
        for vol in ec2.describe_volumes().get("Volumes", []):
            out["volumes"].append({
                "volume_id": vol.get("VolumeId"),
                "encrypted": bool(vol.get("Encrypted")),
                "state": vol.get("State"),
            })
    except (ClientError, BotoCoreError) as e:
        print(f"[!] ec2 volumes: {e}")

    return out


def collect_rds(session) -> list[dict]:
    rds = session.client("rds")
    out = []
    try:
        for db in rds.describe_db_instances().get("DBInstances", []):
            out.append({
                "db_instance_identifier": db.get("DBInstanceIdentifier"),
                "publicly_accessible": bool(db.get("PubliclyAccessible")),
                "storage_encrypted": bool(db.get("StorageEncrypted")),
                "backup_retention_period": db.get("BackupRetentionPeriod", 0),
                "multi_az": bool(db.get("MultiAZ")),
            })
    except (ClientError, BotoCoreError) as e:
        print(f"[!] rds: {e}")
    return out


def collect_cloudtrail(session) -> list[dict]:
    ct = session.client("cloudtrail")
    out = []
    try:
        for t in ct.describe_trails().get("trailList", []):
            name = t.get("Name")
            is_logging = True
            try:
                is_logging = ct.get_trail(Name=name).get("IsLogging", True)
            except (ClientError, BotoCoreError):
                pass
            out.append({
                "name": name,
                "is_multi_region": bool(t.get("IsMultiRegionTrail")),
                "log_file_validation_enabled": bool(t.get("LogFileValidationEnabled")),
                "kms_key_id": t.get("KmsKeyId"),
                "is_logging": is_logging,
            })
    except (ClientError, BotoCoreError) as e:
        print(f"[!] cloudtrail: {e}")
    return out
