"""Read-only N-03 / N-04 security group configuration audit. Python 3.10+."""
import argparse
import csv
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path


def proto(value):
    return {'6': 'tcp', '17': 'udp', '1': 'icmp', '58': 'icmpv6'}.get(str(value), str(value))


def source(rule):
    for key in ('CidrIpv4', 'CidrIpv6', 'PrefixListId'):
        if rule.get(key):
            return key, rule[key]
    group = rule.get('ReferencedGroupInfo', {})
    return ('SecurityGroup', group['GroupId']) if group.get('GroupId') else ('Unknown', '')


def allowed_source(rule, policy):
    kind, value = source(rule)
    if kind == 'SecurityGroup':
        return value in policy.get('security_groups', [])
    if kind in ('CidrIpv4', 'CidrIpv6'):
        network = ipaddress.ip_network(value)
        return any(network.version == approved.version and network.subnet_of(approved)
                   for approved in map(ipaddress.ip_network, policy.get('cidrs', [])))
    # Prefix-list entries can change independently: never silently approve them.
    return None


def ports_approved(rule, approvals):
    protocol = proto(rule['IpProtocol'])
    if protocol == '-1':
        return False
    if protocol not in ('tcp', 'udp'):
        return None
    low, high = rule.get('FromPort'), rule.get('ToPort')
    if low is None or high is None:
        return None
    cursor = low
    for start, end in sorted((p['from'], p['to']) for p in approvals if proto(p['protocol']) == protocol):
        if end < cursor:
            continue
        if start > cursor:
            return False
        cursor = max(cursor, end + 1)
        if cursor > high:
            return True
    return False


def evaluate(target, rules):
    rows = []
    def add(check, status, reason, rule=None):
        rule = rule or {}
        kind, value = source(rule)
        rows.append(dict(check=check, target=target['name'], status=status, reason=reason,
                         security_group=rule.get('GroupId', ''), rule_id=rule.get('SecurityGroupRuleId', ''),
                         protocol=rule.get('IpProtocol', ''), from_port=rule.get('FromPort', ''),
                         to_port=rule.get('ToPort', ''), source_type=kind, source=value))
    policy = target.get('port_policy', {})
    if not policy.get('confirmed'):
        add('N-04', '확인 필요', '승인 포트 기준 미확정')
    elif not rules:
        add('N-04', '확인 필요', '인바운드 규칙 없음: 서비스 연결 별도 확인')
    else:
        for rule in rules:
            result = ports_approved(rule, policy['allowed'])
            add('N-04', '양호' if result is True else '취약' if result is False else '확인 필요',
                '승인 범위 내' if result is True else '미승인 프로토콜 또는 포트 포함' if result is False
                else 'TCP/UDP 외 프로토콜 또는 불완전한 규칙: 수동 검토', rule)
    if target.get('db_policy') is not None:
        policy = target['db_policy']
        port = policy.get('port', 3306)
        candidates = [r for r in rules if proto(r['IpProtocol']) == '-1' or
                      (proto(r['IpProtocol']) == 'tcp' and r.get('FromPort', 0) <= port <= r.get('ToPort', 65535))]
        if not policy.get('confirmed'):
            add('N-03', '확인 필요', '승인 DB 출발지 기준 미확정')
        elif not candidates:
            add('N-03', '확인 필요', 'DB 포트 허용 규칙 없음: 서비스 연결 별도 확인')
        else:
            for rule in candidates:
                result = allowed_source(rule, policy)
                add('N-03', '양호' if result is True else '취약' if result is False else '확인 필요',
                    '승인된 DB 출발지' if result is True else '미승인 DB 출발지' if result is False
                    else 'Prefix List 또는 출발지 정보 수동 확인 필요', rule)
    return rows


def collect(ec2, elb, target, vpc):
    if target['type'] == 'ec2':
        reservations = ec2.describe_instances(InstanceIds=[target['id']])['Reservations']
        instances = [i for r in reservations for i in r['Instances']]
        if len(instances) != 1 or instances[0].get('VpcId') != vpc:
            raise ValueError('인스턴스를 찾지 못했거나 VPC 불일치')
        obj = instances[0]
        groups = {g['GroupId'] for eni in obj.get('NetworkInterfaces', []) for g in eni['Groups']}
    elif target['type'] == 'alb':
        objects = elb.describe_load_balancers(Names=[target['name']])['LoadBalancers']
        obj = objects[0]
        if obj['VpcId'] != vpc or obj['Type'] != 'application':
            raise ValueError('VPC 또는 ALB 유형 불일치')
        groups = set(obj.get('SecurityGroups', []))
    else:
        raise ValueError('지원하지 않는 대상 유형')
    if not groups:
        raise ValueError('연결된 보안 그룹을 찾지 못함')
    rules = []
    for page in ec2.get_paginator('describe_security_group_rules').paginate(
            Filters=[{'Name': 'group-id', 'Values': sorted(groups)}]):
        rules.extend(r for r in page['SecurityGroupRules'] if not r['IsEgress'])
    return rules, sorted(groups)


def validate(config):
    if not config.get('targets'):
        raise ValueError('점검 대상이 없습니다')
    for target in config['targets']:
        for p in target.get('port_policy', {}).get('allowed', []):
            if proto(p['protocol']) not in ('tcp', 'udp') or not 0 <= p['from'] <= p['to'] <= 65535:
                raise ValueError('승인 포트는 TCP/UDP, 0~65535 범위여야 합니다')
        for cidr in (target.get('db_policy') or {}).get('cidrs', []):
            ipaddress.ip_network(cidr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='approved_rules.json')
    parser.add_argument('--profile', help='AWS CLI 프로필; EC2 IAM 역할 사용 시 생략')
    parser.add_argument('--output', default='results')
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding='utf-8-sig'))
    validate(config)
    import boto3
    from botocore.config import Config
    session = boto3.Session(profile_name=args.profile, region_name=config['region'])
    options = Config(connect_timeout=10, read_timeout=30, retries={'max_attempts': 3, 'mode': 'standard'})
    ec2 = session.client('ec2', config=options)
    elb = session.client('elbv2', config=options)
    rows, evidence = [], []
    for target in config['targets']:
        try:
            rules, groups = collect(ec2, elb, target, config['vpc_id'])
            evidence.append({'target': target['name'], 'security_groups': groups, 'ingress_rules': rules})
            rows.extend(evaluate(target, rules))
        except Exception as error:
            for check in (['N-03', 'N-04'] if target.get('db_policy') is not None else ['N-04']):
                rows.append({'check': check, 'target': target['name'], 'status': '확인 필요',
                             'reason': f'수집/평가 실패: {type(error).__name__}: {error}'})
    now = datetime.now(timezone.utc)
    folder = Path(args.output) / now.strftime('%Y%m%dT%H%M%S_%fZ')
    folder.mkdir(parents=True, exist_ok=False)
    report = {'timestamp_utc': now.isoformat(), 'scope': '인바운드 SG 설정 점검; 실제 접속 및 OS 리스닝 검증 제외',
              'config': config, 'results': rows, 'evidence': evidence}
    (folder / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding='utf-8')
    fields = ['check', 'target', 'status', 'reason', 'security_group', 'rule_id', 'protocol',
              'from_port', 'to_port', 'source_type', 'source']
    with (folder / 'report.csv').open('w', encoding='utf-8-sig', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    for row in rows:
        print(f"{row['check']} | {row['target']} | {row['status']} | {row['reason']}")
    print(f'결과: {folder.resolve()}')
    return 2 if any(r['status'] == '확인 필요' for r in rows) else 1 if any(r['status'] == '취약' for r in rows) else 0


if __name__ == '__main__':
    raise SystemExit(main())
