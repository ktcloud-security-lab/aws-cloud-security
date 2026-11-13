import boto3
from botocore.exceptions import ClientError, BotoCoreError
from collections import Counter

REGION = 'ap-northeast-2'
VPC_ID = 'vpc-063a3a54bd0d5907a'
EXPECTED = {
    'public-subnet-a': ('10.0.1.0/24', 'igw'),
    'public-subnet-c': ('10.0.3.0/24', 'ips'),
    'public-subnet-d': ('10.0.4.0/24', 'ips'),
    'ids-ips-subnet': ('10.0.2.0/24', 'nat'),
    'private-web-subnet': ('10.0.11.0/24', 'ips'),
    'private-db-subnet': ('10.0.12.0/24', 'ips'),
}
EXPECTED_EDGE = {'10.0.3.0/24', '10.0.4.0/24'}

def tag_name(resource):
    return next((t['Value'] for t in resource.get('Tags', []) if t['Key'] == 'Name'), '')

def all_pages(client, method, key, **kwargs):
    return [item for page in client.get_paginator(method).paginate(**kwargs) for item in page[key]]

def route_target(route):
    return next((route[k] for k in ('NetworkInterfaceId', 'GatewayId', 'NatGatewayId', 'TransitGatewayId', 'InstanceId') if route.get(k)), '-')

def route_for(table, cidr):
    return next((r for r in table.get('Routes', []) if r.get('DestinationCidrBlock') == cidr), None)

results = []
def report(code, status, message):
    results.append((code, status, message))
    print(f'[{status:6}] {code:9} {message}')

try:
    ec2 = boto3.client('ec2', region_name=REGION)
    vpcs = ec2.describe_vpcs(VpcIds=[VPC_ID])['Vpcs']
    if len(vpcs) != 1:
        raise RuntimeError('Project VPC not found')
    subnets = all_pages(ec2, 'describe_subnets', 'Subnets', Filters=[{'Name':'vpc-id','Values':[VPC_ID]}])
    tables = all_pages(ec2, 'describe_route_tables', 'RouteTables', Filters=[{'Name':'vpc-id','Values':[VPC_ID]}])
    enis = all_pages(ec2, 'describe_network_interfaces', 'NetworkInterfaces', Filters=[{'Name':'vpc-id','Values':[VPC_ID]}])
    igws = all_pages(ec2, 'describe_internet_gateways', 'InternetGateways', Filters=[{'Name':'attachment.vpc-id','Values':[VPC_ID]}])
except (ClientError, BotoCoreError, RuntimeError) as exc:
    raise SystemExit(f'AWS READ ERROR: {exc}')

print(f'N-06 Subnet & Routing Security Check | {REGION} | {VPC_ID}')
print('=' * 105)

subnet_by_name = {}
for subnet in subnets:
    name = tag_name(subnet)
    if name in subnet_by_name:
        report('SUBNET', 'REVIEW', f'Duplicate subnet name: {name or "UNNAMED"}')
    else:
        subnet_by_name[name] = subnet

report('N06-01', 'PASS' if len(subnets) == 6 and all(name in subnet_by_name and subnet_by_name[name]['CidrBlock'] == cidr for name, (cidr, _) in EXPECTED.items()) else 'FAIL',
       f'Subnet inventory: actual={len(subnets)}, expected=6; names/CIDRs checked')

interfaces = {eni['NetworkInterfaceId']: eni for eni in enis}
instances = all_pages(ec2, 'describe_instances', 'Reservations')
# Reservations are flattened to instances only for the project VPC.
project_instances = [inst for reservation in instances for inst in reservation['Instances'] if inst.get('VpcId') == VPC_ID]
instance_by_name = {tag_name(inst): inst for inst in project_instances if tag_name(inst)}

nat = instance_by_name.get('nat-instance')
ips = instance_by_name.get('idp-ips-instance')
if ips is None:
    ips = next((inst for name, inst in instance_by_name.items() if 'ips' in name.lower()), None)

def primary_eni(instance):
    if not instance:
        return None
    attached = sorted(instance.get('NetworkInterfaces', []), key=lambda eni: eni.get('Attachment', {}).get('DeviceIndex', 99))
    return attached[0]['NetworkInterfaceId'] if attached else None

nat_eni = primary_eni(nat)
ips_eni = primary_eni(ips)
igw_ids = {igw['InternetGatewayId'] for igw in igws}

for label, inst, eni_id in [('NAT', nat, nat_eni), ('IPS', ips, ips_eni)]:
    if not inst or not eni_id or eni_id not in interfaces:
        report('N06-08', 'REVIEW', f'{label} instance/ENI could not be identified')
    else:
        check = interfaces[eni_id].get('SourceDestCheck')
        report('N06-08', 'PASS' if check is False else 'FAIL', f'{label}: ENI={eni_id}, SourceDestCheck={check}')

main_table = next((rt for rt in tables if any(a.get('Main') for a in rt.get('Associations', []))), None)

for name, (cidr, role) in EXPECTED.items():
    subnet = subnet_by_name.get(name)
    if not subnet:
        report('N06-02', 'FAIL', f'{name}: subnet missing')
        continue
    explicit = next((rt for rt in tables if any(a.get('SubnetId') == subnet['SubnetId'] for a in rt.get('Associations', []))), None)
    effective = explicit or main_table
    if effective is None:
        report('N06-02', 'FAIL', f'{name}: no effective route table')
        continue
    report('N06-02', 'PASS' if explicit else 'REVIEW', f'{name}: {tag_name(effective) or effective["RouteTableId"]}, {"EXPLICIT" if explicit else "MAIN inherited"}')
    default = route_for(effective, '0.0.0.0/0')
    target = route_target(default) if default else '-'
    expected_target = {'igw': igw_ids, 'nat': {nat_eni} if nat_eni else set(), 'ips': {ips_eni} if ips_eni else set()}[role]
    status = 'PASS' if target in expected_target and default.get('State') == 'active' else ('REVIEW' if not expected_target else 'FAIL')
    code = {'igw':'N06-03','ips':'N06-04' if name.startswith('public-') else 'N06-05','nat':'N06-06'}[role]
    report(code, status, f'{name}: default -> {target}; expected={role.upper()}')

edge_tables = [rt for rt in tables if any(a.get('GatewayId') in igw_ids for a in rt.get('Associations', []))]
if len(edge_tables) != 1:
    report('N06-07', 'REVIEW' if len(edge_tables) > 1 else 'FAIL', f'IGW edge table count={len(edge_tables)}')
else:
    edge = edge_tables[0]
    for cidr in sorted(EXPECTED_EDGE):
        route = route_for(edge, cidr)
        target = route_target(route) if route else '-'
        status = 'PASS' if nat_eni and target == nat_eni and route.get('State') == 'active' else ('REVIEW' if not nat_eni else 'FAIL')
        report('N06-07', status, f'IGW edge {cidr} -> {target}; expected NAT ENI')

counts = Counter(status for _, status, _ in results)
print('-' * 105)
print(f'SUMMARY: PASS={counts["PASS"]} FAIL={counts["FAIL"]} REVIEW={counts["REVIEW"]}')
print('NOTE: Configuration-only check. Actual traffic forwarding, Snort detection, symmetry, and ALB reachability are not proven.')
