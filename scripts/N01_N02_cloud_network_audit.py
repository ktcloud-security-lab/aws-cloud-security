#!/usr/bin/env python3
"""AWS VPC Security Group read-only checks: N-01 public ingress and N-02 admin-port exposure.

Usage:
    python3 network_security_check.py --demo
    python3 network_security_check.py --vpc-id vpc-xxxxxxxxxxxxxxxxx

The script does not create, modify, or delete AWS resources.
"""

import argparse
import csv
from collections import Counter
from datetime import datetime
from pathlib import Path
import sys

REGION = "ap-northeast-2"

# After the team confirms which internet-facing rules are intentional, add them here.
# Example (replace the group ID with your real ALB security group ID):
# APPROVED_PUBLIC_RULES = {
#     "sg-0123456789abcdef0": {("tcp", 80, 80), ("tcp", 443, 443)},
# }
APPROVED_PUBLIC_RULES = {}

PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}
FIELDS = ["check_id", "status", "sg_name", "sg_id", "vpc_id", "details"]


def protocol_name(value):
    value = str(value).lower()
    return {"-1": "all", "6": "tcp", "17": "udp"}.get(value, value)


def public_cidr(rule):
    cidr = rule.get("CidrIpv4") or rule.get("CidrIpv6")
    return cidr if cidr in PUBLIC_CIDRS else None


def port_range(rule):
    protocol = protocol_name(rule.get("IpProtocol", ""))
    if protocol == "all":
        return "all"
    start, end = rule.get("FromPort"), rule.get("ToPort")
    if start is None or end is None:
        return "unspecified"
    return str(start) if start == end else f"{start}-{end}"


def evidence(rule):
    rule_id = rule.get("SecurityGroupRuleId", "unknown-rule")
    protocol = protocol_name(rule.get("IpProtocol", ""))
    return f"{rule_id} [{protocol}/{port_range(rule)} from {public_cidr(rule)}]"


def approved_public_rule(sg_id, rule):
    """Exact protocol and port range must be explicitly approved for this SG."""
    allowed = APPROVED_PUBLIC_RULES.get(sg_id, set())
    protocol = protocol_name(rule.get("IpProtocol", ""))
    return (protocol, rule.get("FromPort"), rule.get("ToPort")) in allowed


def exposes_port(rule, port, protocol):
    """Whether a single ingress SG rule permits the specified transport and port."""
    if not public_cidr(rule):
        return False
    actual_protocol = protocol_name(rule.get("IpProtocol", ""))
    if actual_protocol == "all":
        return True
    if actual_protocol != protocol:
        return False
    start, end = rule.get("FromPort"), rule.get("ToPort")
    return start is not None and end is not None and start <= port <= end


def scan_group(sg, rules):
    sg_id = sg["GroupId"]
    basic = {"sg_name": sg.get("GroupName", ""), "sg_id": sg_id, "vpc_id": sg.get("VpcId", "")}

    # Inspect only ingress (IsEgress=False); the default outbound any/any is out of scope.
    public_rules = [r for r in rules if not r.get("IsEgress", False) and public_cidr(r)]

    if not public_rules:
        n01_status, n01_detail = "PASS", "전체 공개 인바운드 규칙 없음"
    else:
        unapproved = [r for r in public_rules if not approved_public_rule(sg_id, r)]
        overly_broad = [r for r in unapproved if protocol_name(r.get("IpProtocol", "")) == "all"]
        if not unapproved:
            n01_status, n01_detail = "PASS", "전체 공개 규칙이 모두 승인 목록과 일치"
        elif overly_broad or sg_id in APPROVED_PUBLIC_RULES:
            n01_status = "FAIL"
            n01_detail = "미승인 전체 공개 규칙: " + "; ".join(evidence(r) for r in unapproved)
        else:
            n01_status = "REVIEW"
            n01_detail = "전체 공개 규칙 발견(승인 여부 확인 필요): " + "; ".join(evidence(r) for r in unapproved)

    admin_findings = []
    for r in public_rules:
        exposed = []
        if exposes_port(r, 22, "tcp"):
            exposed.append("SSH TCP/22")
        if exposes_port(r, 3389, "tcp") or exposes_port(r, 3389, "udp"):
            exposed.append("RDP 3389")
        if exposed:
            admin_findings.append(f"{', '.join(exposed)}: {evidence(r)}")

    n02_status = "FAIL" if admin_findings else "PASS"
    n02_detail = "; ".join(admin_findings) if admin_findings else "관리 포트 22/3389 전체 공개 규칙 없음"
    return [
        {"check_id": "N-01", "status": n01_status, **basic, "details": n01_detail},
        {"check_id": "N-02", "status": n02_status, **basic, "details": n02_detail},
    ]


def get_aws_data(vpc_id):
    try:
        import boto3
    except ImportError:
        raise RuntimeError("boto3가 설치되어 있지 않습니다. 'python3 -m pip install boto3' 실행")

    client = boto3.client("ec2", region_name=REGION)
    group_kwargs = {}
    if vpc_id:
        group_kwargs["Filters"] = [{"Name": "vpc-id", "Values": [vpc_id]}]
    groups = []
    for page in client.get_paginator("describe_security_groups").paginate(**group_kwargs):
        groups.extend(page.get("SecurityGroups", []))

    rules_by_group = {sg["GroupId"]: [] for sg in groups}
    for sg in groups:
        pages = client.get_paginator("describe_security_group_rules").paginate(
            Filters=[{"Name": "group-id", "Values": [sg["GroupId"]]}]
        )
        for page in pages:
            rules_by_group[sg["GroupId"]].extend(page.get("SecurityGroupRules", []))
    return groups, rules_by_group


def get_demo_data():
    groups = [
        {"GroupId": "sg-demo-alb", "GroupName": "demo-alb", "VpcId": "vpc-demo"},
        {"GroupId": "sg-demo-db", "GroupName": "demo-db", "VpcId": "vpc-demo"},
        {"GroupId": "sg-demo-risk", "GroupName": "demo-risk", "VpcId": "vpc-demo"},
    ]
    rules = {
        "sg-demo-alb": [{"GroupId": "sg-demo-alb", "SecurityGroupRuleId": "sgr-demo-1", "IsEgress": False, "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIpv4": "0.0.0.0/0"}],
        "sg-demo-db": [{"GroupId": "sg-demo-db", "SecurityGroupRuleId": "sgr-demo-2", "IsEgress": False, "IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306, "CidrIpv4": "10.0.11.0/24"}],
        "sg-demo-risk": [{"GroupId": "sg-demo-risk", "SecurityGroupRuleId": "sgr-demo-3", "IsEgress": False, "IpProtocol": "-1", "CidrIpv4": "0.0.0.0/0"}],
    }
    return groups, rules


def main():
    parser = argparse.ArgumentParser(description="N-01/N-02 AWS 보안 그룹 자동점검 (읽기 전용)")
    parser.add_argument("--vpc-id", default="", help="프로젝트 VPC ID. 미지정 시 서울 리전 모든 VPC의 보안 그룹 점검")
    parser.add_argument("--demo", action="store_true", help="AWS 접속 없이 예제 데이터로 검사")
    args = parser.parse_args()

    try:
        groups, rules_by_group = get_demo_data() if args.demo else get_aws_data(args.vpc_id)
    except Exception as exc:
        print(f"점검 실패: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if not groups:
        print("점검할 보안 그룹이 없습니다. 리전과 VPC ID를 확인해 주세요.")
        return 0

    rows = []
    print(f"\n네트워크 보안 자동점검 (N-01, N-02) / 리전: {REGION}")
    for sg in groups:
        rows.extend(scan_group(sg, rules_by_group.get(sg["GroupId"], [])))
    for row in rows:
        print(f"[{row['check_id']}] {row['status']:<6} {row['sg_name']} ({row['sg_id']})")
        if row["status"] != "PASS":
            print("  - " + row["details"])

    print("\n결과 집계")
    for check_id in ("N-01", "N-02"):
        counts = Counter(r["status"] for r in rows if r["check_id"] == check_id)
        print(f"{check_id}: PASS {counts['PASS']} / REVIEW {counts['REVIEW']} / FAIL {counts['FAIL']}")

    folder = Path("reports")
    folder.mkdir(exist_ok=True)
    filename = folder / f"network_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with filename.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nCSV 저장 완료: {filename}")
    print("※ SG 규칙 기반 설정 점검이며, 실제 인터넷 연결 가능성을 증명하는 것은 아닙니다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
