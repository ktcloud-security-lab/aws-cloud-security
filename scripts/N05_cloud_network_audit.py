#!/usr/bin/env python3
"""404 team N-05: EC2 public IPv4 assignment audit (read-only).

Checks the four named project EC2 instances in one VPC. Only the approved
NAT instance may have a public IPv4 address. This is a configuration check,
not a reachability test or a guarantee of network isolation.
"""
import os
from collections import Counter

import boto3
from botocore.exceptions import BotoCoreError, ClientError

REGION = os.getenv('AWS_REGION', 'ap-northeast-2')
VPC_ID = os.getenv('AUDIT_VPC_ID', 'vpc-063a3a54bd0d5907a')
APPROVED_NAT_PUBLIC_IP = os.getenv('APPROVED_NAT_PUBLIC_IP', '').strip()
EXPECTED = {
    '404-ec2-db': False,
    '404-ec2-web': False,
    'idp-ips-instance': False,
    'nat-instance': True,
}


def tag_name(resource):
    return next((tag.get('Value', '') for tag in resource.get('Tags', [])
                 if tag.get('Key') == 'Name'), '')


def public_ips(instance):
    """Collect EC2 and ENI-association public IPv4 addresses."""
    ips = set()
    if instance.get('PublicIpAddress'):
        ips.add(instance['PublicIpAddress'])
    for eni in instance.get('NetworkInterfaces', []):
        association = eni.get('Association') or {}
        if association.get('PublicIp'):
            ips.add(association['PublicIp'])
        for private in eni.get('PrivateIpAddresses', []):
            assoc = private.get('Association') or {}
            if assoc.get('PublicIp'):
                ips.add(assoc['PublicIp'])
    return sorted(ips)


def main():
    ec2 = boto3.client('ec2', region_name=REGION)
    try:
        ec2.describe_vpcs(VpcIds=[VPC_ID])
        paginator = ec2.get_paginator('describe_instances')
        instances = [instance
                     for page in paginator.paginate(Filters=[
                         {'Name': 'vpc-id', 'Values': [VPC_ID]}
                     ])
                     for reservation in page['Reservations']
                     for instance in reservation['Instances']
                     if instance.get('State', {}).get('Name') != 'terminated']
    except (ClientError, BotoCoreError) as exc:
        raise SystemExit(f'AWS READ ERROR: {exc}') from exc

    print(f'N-05 EC2 Public IP Assignment Check | {REGION} | {VPC_ID}')
    print('=' * 100)
    by_name = {}
    for instance in instances:
        by_name.setdefault(tag_name(instance), []).append(instance)

    counts = Counter()
    for name, public_allowed in EXPECTED.items():
        matches = by_name.get(name, [])
        if len(matches) != 1:
            status = 'REVIEW' if not matches else 'FAIL'
            message = f'{name}: expected one instance, found {len(matches)}'
        else:
            instance = matches[0]
            ips = public_ips(instance)
            state = instance.get('State', {}).get('Name', 'unknown')
            if public_allowed:
                if not ips:
                    status = 'FAIL'
                    reason = 'approved NAT instance has no public IPv4'
                elif APPROVED_NAT_PUBLIC_IP and ips != [APPROVED_NAT_PUBLIC_IP]:
                    status = 'FAIL'
                    reason = 'NAT public IPv4 differs from approved value'
                else:
                    status = 'PASS' if state == 'running' else 'REVIEW'
                    reason = 'approved NAT public IPv4' if state == 'running' else 'NAT instance not running'
            else:
                status = 'FAIL' if ips else 'PASS'
                reason = 'unauthorized public IPv4' if ips else 'no public IPv4'
            message = (f'{name}: instance={instance["InstanceId"]}, state={state}, '
                       f'public_ips={ips or "none"}; {reason}')
        counts[status] += 1
        print(f'[{status:6}] N05-01 {message}')

    print('-' * 100)
    print(f'SUMMARY: PASS={counts["PASS"]} FAIL={counts["FAIL"]} REVIEW={counts["REVIEW"]}')
    if not APPROVED_NAT_PUBLIC_IP:
        print('NOTE: NAT public IPv4 is allowed by role; exact IP whitelist was not configured.')
    print('NOTE: Read-only configuration check; security groups, reachability, and other resources are not audited.')
    return 1 if counts['FAIL'] or counts['REVIEW'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
