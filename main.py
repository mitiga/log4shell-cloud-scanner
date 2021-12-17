import logging
from urllib.parse import urlparse
from injector import CVE_2021_44228_Injector, CVE_2021_45046_Injector
import boto3
from aws_detector import get_ec2_urls
from aws_detector import get_load_balancers
import argparse
import sys


formatter = logging.Formatter('%(asctime)s %(levelname)s [%(module)s] [%(region)s]: %(message)s')
logger = logging.getLogger()
sh = logging.StreamHandler()
sh.setFormatter(formatter)
logger.setLevel(logging.INFO)
logger.addHandler(sh)


DEFAULT_CVE = "CVE-2021-44228"

LOG4SHELL_CVE = {"CVE-2021-44228": CVE_2021_44228_Injector,
                 "CVE-2021-45046": CVE_2021_45046_Injector}


def get_parser():
    parser = argparse.ArgumentParser(prog='Mitiga Log4shell AWS Parser')
    parser.add_argument('-d', '--dest-domain', required=True,
                        help='The destination domain where the victim machine will send the message to. Example: '
                             '-d fsfsf.interactsh.com')
    parser.add_argument('-p', '--proxies', nargs='*', help='List of url addresses of your proxy servers. '
                                                           'Default: not using any proxy server. Example: '
                                                           '-p http://127.0.0.1:8080 https://127.0.0.1:8080')
    parser.add_argument('-c', '--cve-id', default=DEFAULT_CVE, choices=list(LOG4SHELL_CVE.keys()),
                        help='Choose which vulnerable to check. If not give, use the first oldest vulnerable: CVE-2021-44228')
    return parser


def main(args):
    parser = get_parser()
    args = parser.parse_args(args)
    proxies = args.proxies
    if proxies:
        format_prox = dict()
        for p in proxies:
            parsed_uri = urlparse(p)
            format_prox[parsed_uri.scheme] = p
    else:
        format_prox = None
    injector_cls = LOG4SHELL_CVE[args.cve_id]
    i = injector_cls(args.dest_domain, format_prox)
    ec2 = boto3.client('ec2')
    regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
    for region in regions:
        logger.info(f"Start scanning resources in {region}", extra={'region': region})
        ec2 = boto3.client('ec2', region_name=region)
        elb_client = boto3.client("elbv2", region_name=region)

        logger.info('Scans EC2 instance URL instances addresses', extra={'region': region})
        ec2_endpoints_info = get_ec2_urls(ec2)
        num = len(ec2_endpoints_info)
        if not num:
            logger.info("Didn't find any Internet facing EC2 urls", extra={'region': region})
        else:
            logger.info(f"Going to scan {num} URL addresses", extra={'region': region})
            for ec2_info in ec2_endpoints_info:
                i.send(victim_url=ec2_info.url, victim_identifier=ec2_info.instance_id)
        logger.info('Finish testing the EC2 instances', extra={'region': region})

        logger.info('Scans load balancers URL addresses', extra={'region': region})
        lb_endpoints_info = get_load_balancers(elb_client)
        num = len(lb_endpoints_info)
        if not num:
            logger.info("Didn't find any Internet facing LB urls", extra={'region': region})
        else:
            logger.info(f"Going to scan {num} URL LB addresses", extra={'region': region})
            for lb_info in lb_endpoints_info:
                i.send(victim_url=lb_info.url, victim_identifier=lb_info.identifier,
                       request_method=lb_info.explicit_method,
                       header_params=lb_info.header, query_params=lb_info.params)
        logger.info(f"Finish scanning resources in {region}", extra={'region': region})


if __name__ == '__main__':
    main(sys.argv[1:])
