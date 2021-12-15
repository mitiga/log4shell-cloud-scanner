from itertools import chain
from typing import List
from collections import namedtuple, defaultdict
import logging
logger = logging.getLogger()


EC2Url = namedtuple('EC2Url', ['url', 'instance_id'])


def get_ec2_urls(ec2_client) -> List[EC2Url]:
    """
    Returns a collection of EC2 instances URL addresses
    which exposed to the internet.
    param ec2_client: botocore.client.EC2
    """
    urls = set()
    resevs = list(chain(*(page['Reservations']
                          for page in ec2_client.get_paginator('describe_instances').paginate(
        Filters=[
            {
                'Name': 'instance-state-name',
                'Values': ['running']
            }
        ]))))

    group_ids_to_instances = defaultdict(list)
    for instances in resevs:
        for instance_data in instances['Instances']:
            i_id = instance_data['InstanceId']
            for network_inr in instance_data['NetworkInterfaces']:
                association = network_inr.get('Association')
                if not association:
                    continue
                public_ip = association.get('PublicIp')
                if public_ip is None:
                    continue  # only collect public ip addresses
                for group in network_inr.get('Groups', []):
                    group_ids_to_instances[group['GroupId']].append((public_ip, i_id))
    if not group_ids_to_instances:
        return list(urls)
    group_ids_to_instances = dict(group_ids_to_instances)
    sec_groups = list(
        chain(*(page['SecurityGroups']
                for page in ec2_client.get_paginator('describe_security_groups').paginate(
            GroupIds=list(group_ids_to_instances.keys())
        ))))
    for sec in sec_groups:
        for ip_prem in sec['IpPermissions']:
            if ip_prem['FromPort'] == '-1':
                continue  # we can skip DHCP related rules
            for ip_range in ip_prem['IpRanges']:
                if ip_range['CidrIp'].startswith("0.0.0.0/"):
                    for ec2_info in group_ids_to_instances[sec['GroupId']]:
                        urls.add(EC2Url(f'http://{ec2_info[0]}:{ip_prem["FromPort"]}/',
                                           ec2_info[1]))
                        urls.add(EC2Url(f'https://{ec2_info[0]}:{ip_prem["FromPort"]}/',
                                           ec2_info[1]))
    return list(urls)


LoadBalancerUrl = namedtuple('LoadBalancerUrl', ['url', 'identifier', 'header', 'explicit_method', 'params'])


def _get_string_from_reg(s: str) -> str:
    example_string = s.replace('?', 'a')
    return example_string.replace('*', 'test')


def get_load_balancers(elb_client) -> List[LoadBalancerUrl]:
    """
    Returns a collection of load balancers URL addresses
    which exposed to the internet.
    param elb_client: botocore.client.ELB2
    """
    results = list()
    response = elb_client.describe_load_balancers()

    lb_info = response['LoadBalancers']
    for lb in lb_info:
        if lb['Scheme'] != 'internet-facing':
            continue
        dns_name = lb['DNSName']
        load_balancer_identifier = lb['LoadBalancerName']
        resp_listener = elb_client.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn'])
        for listener in resp_listener['Listeners']:
            port = listener['Port']
            if listener['Protocol'] == 'HTTP':
                protocols = ['http']
            elif listener['Protocol'] == 'HTTPS':
                protocols = ['https']
            else:
                protocols = ['http', 'https']
            rules = elb_client.describe_rules(ListenerArn=listener['ListenerArn'])['Rules']
            if not rules:
                for p in protocols:
                    results.append(LoadBalancerUrl(
                        url=f'{p}://{dns_name}:{port}/',
                        identifier=load_balancer_identifier,
                        header={},
                        explicit_method=None,
                        params={}
                    ))
            for rule in rules:
                for action in rule.get('Actions', []):
                    if action['Type'] in ('fixed-response', 'authenticate-oidc', 'authenticate-cognito'):
                        continue # We don't want to check the URI, if the target of the LB of those types.
                subdomain = ""
                params = {}
                explicit_request_method = None
                uri_to_append = '/'
                headers_needed = {}
                for condition in rule.get('Conditions', []):
                    if condition['Field'] == 'http-header':
                        header_config = condition['HttpHeaderConfig']
                        headers_needed[header_config['HttpHeaderName']] = _get_string_from_reg(header_config['Values'][0])
                    elif condition['Field'] == 'path-pattern':
                        path_config = condition['PathPatternConfig']
                        uri_to_append = _get_string_from_reg(path_config['Values'][0])
                        if uri_to_append[0] != '/':
                            uri_to_append = '/' + uri_to_append
                    elif condition['Field'] == 'host-header':
                        host_config = condition['HostHeaderConfig']
                        subdomain = f'{_get_string_from_reg(host_config["Values"][0])}.'
                    elif condition['Field'] == 'query-string':
                        query_config = condition['QueryStringConfig']
                        for val in query_config["Values"]:
                            if 'Key' in val:
                                params[val['Key']] = _get_string_from_reg(val['Value'])
                            else:
                                params['test'] = _get_string_from_reg(val['Value'])
                    elif condition['Field'] == 'http-request-method':
                        request_config = condition['HttpRequestMethodConfig']
                        explicit_request_method = request_config["Values"][0]
                    else:
                        continue
                for p in protocols:
                    results.append(LoadBalancerUrl(
                        url=f'{p}://{subdomain}{dns_name}:{port}{uri_to_append}',
                        identifier=load_balancer_identifier,
                        header=headers_needed,
                        explicit_method=explicit_request_method,
                        params=params
                    ))
    return results

