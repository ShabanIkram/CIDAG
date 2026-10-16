from cidag.core.finding import Severity
from cidag.scanners.ec2 import checks


def test_sg_ssh_world_open():
    sg = {"group_id": "sg-1", "group_name": "g",
          "ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                       "cidrs": ["0.0.0.0/0"], "ipv6": []}]}
    f = checks.SG_CHECK(sg)
    assert f and f[0].check_id == "EC2-001" and f[0].severity is Severity.CRITICAL


def test_sg_rdp_world_open():
    sg = {"group_id": "sg-1", "ingress": [{"protocol": "tcp", "from_port": 3389,
                                           "to_port": 3389, "cidrs": ["0.0.0.0/0"], "ipv6": []}]}
    f = checks.SG_CHECK(sg)
    assert f and f[0].check_id == "EC2-002"


def test_sg_ssh_only_reports_one_not_both():
    # regression: a single open port must not fan out to every critical port
    sg = {"group_id": "sg-1", "ingress": [{"protocol": "tcp", "from_port": 22,
                                           "to_port": 22, "cidrs": ["0.0.0.0/0"], "ipv6": []}]}
    f = checks.SG_CHECK(sg)
    assert len(f) == 1 and f[0].check_id == "EC2-001"


def test_sg_private_cidr_no_finding():
    sg = {"group_id": "sg-1", "ingress": [{"protocol": "tcp", "from_port": 22,
                                           "to_port": 22, "cidrs": ["10.0.0.0/8"], "ipv6": []}]}
    assert checks.SG_CHECK(sg) == []


def test_sg_all_traffic():
    sg = {"group_id": "sg-1", "ingress": [{"protocol": "-1", "from_port": None,
                                           "to_port": None, "cidrs": ["0.0.0.0/0"], "ipv6": []}]}
    f = checks.SG_CHECK(sg)
    assert f and f[0].check_id == "EC2-004"


def test_sg_high_port_mysql():
    sg = {"group_id": "sg-1", "ingress": [{"protocol": "tcp", "from_port": 3306,
                                           "to_port": 3306, "cidrs": ["0.0.0.0/0"], "ipv6": []}]}
    f = checks.SG_CHECK(sg)
    assert f and f[0].check_id == "EC2-003" and f[0].severity is Severity.HIGH


def test_unencrypted_ebs():
    assert checks.check_unencrypted_ebs({"volume_id": "v", "encrypted": False})
    assert checks.check_unencrypted_ebs({"volume_id": "v", "encrypted": True}) == []


def test_imdsv1():
    assert checks.check_imdsv1({"instance_id": "i", "imds_v2": False})
    assert checks.check_imdsv1({"instance_id": "i", "imds_v2": True}) == []


def test_rds_checks():
    db = {"db_instance_identifier": "d", "publicly_accessible": True,
          "storage_encrypted": False, "backup_retention_period": 1}
    assert checks.check_rds_public(db)
    assert checks.check_rds_unencrypted(db)
    assert checks.check_rds_backup(db)


def test_cloudtrail_none():
    f = checks.check_cloudtrail([])
    assert f and f[0].check_id == "CT-001"


def test_cloudtrail_bad_trail():
    trails = [{"name": "t", "is_multi_region": False,
               "log_file_validation_enabled": False, "kms_key_id": None}]
    f = checks.check_cloudtrail(trails)
    ids = {x.check_id for x in f}
    assert {"CT-002", "CT-003", "CT-004"} <= ids


def test_cloudtrail_good_trail():
    trails = [{"name": "t", "is_multi_region": True,
               "log_file_validation_enabled": True, "kms_key_id": "arn:aws:kms:..."}]
    assert checks.check_cloudtrail(trails) == []
