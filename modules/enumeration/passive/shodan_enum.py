import shodan
import concurrent.futures
from logging import DEBUG, INFO

from ...log import log_module
from ...log.print import printing_module

DOMAIN = 0
SUBDOMAIN = 1

class Shodan_enum():

    def __init__(self, api_key) -> None:
        self.client = shodan.Shodan(api_key)

    def filter_search(self, results: dict, name: str, type: int):
        temporal_list = list()
        for result in results['matches']:
            if type == 0:
                if (name in result["domains"]) or name in result["hostnames"]:
                    temporal_list.append(result['ip_str'])
            elif type == 1:
                if name in result["hostnames"]:
                    temporal_list.append(result['ip_str'])

        return temporal_list
    
    def subdomain_search(self, data: dict):
        results = self.client.search(f"hostname:{data['Subdomain']['name']}")
        print(f"Result founds for  {data['Subdomain']['name']}: {results['total']}")
        results = list(dict.fromkeys(self.filter_search(results, data['Subdomain']['name'], SUBDOMAIN)))

        return results
    
    def domain_search(self, data: dict):
        results = self.client.search(f"hostname:{data['Domain']}")
        print(f"Result founds for  {data['Domain']}: {results['total']}")
        data["IPs"] = list(dict.fromkeys(self.filter_search(results, data['Domain'], DOMAIN)))
        if data["Subdomain"]["name"] != None:
            data["Subdomain"]["IPs"] = self.subdomain_search(data)

        return data

    def thread_search(self, elements: list):
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ProcessPool:
                log_module.log_cli("Shodan_Enumeration_Module------>Searching public exposed data", "info", INFO)
                futures = ProcessPool.map(self.domain_search, elements)
                futures = list(futures)                

            return elements
            
        except shodan.APIError as e:
            log_module.DEBUG(str(e), "debug", DEBUG)
