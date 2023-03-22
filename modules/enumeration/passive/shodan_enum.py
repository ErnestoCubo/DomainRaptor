import shodan
import concurrent.futures
from logging import DEBUG, INFO

# Local modules imports
from ...log import log_module
from ...log.print import printing_module

# Constants related to the data type given
DOMAIN = 0
SUBDOMAIN = 1
PORTS = 2



class Shodan_enum():
    def __init__(self, api_key) -> None:
        self.client = shodan.Shodan(api_key)
    
    ''' filter_search()
        Description: Filters results
        Params:
            - results: type dict -> dictionary containing results object info
            - name: domain hostname or name
            - type: If 0 it will filter based on domain if 1 it will filter based on subdomain
        returns:
            - It return the a list with the filtered IPs founds
    '''
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
    
    ''' port_search()
        Description: Extract ports for each IP
        Params:
            - data: type dict -> dictionary containing domain/subdomain object info
        returns:
            - return the dict object with the parsed open ports info
    '''
    def port_search(self, data: dict):
        return
    
    ''' subdomain_results()
        Description: Extract subdomain info for each given domain object
        Params:
            - data: type dict -> dictionary containing domain/subdomain object info
        returns:
            - return the dict object with the parsed subdomain info
    '''
    def subdomain_results(self, data: dict):
        results = self.client.search(f"hostname:{data['subdomain']['name']}")
        print(f"Result founds for  {data['subdomain']['name']}: {results['total']}")
        results = list(dict.fromkeys(self.filter_search(results, data['subdomain']['name'], SUBDOMAIN)))

        return results
    
    ''' domain_results()
        Description: Extract domain info for each given domain object
        Params:
            - data: type dict -> dictionary containing domain/subdomain object info
        returns:
            - return the dict object with the parsed domain info
    '''
    def domain_results(self, data: dict):
        results = self.client.search(f"hostname:{data['domain']}")
        print(f"Result founds for  {data['domain']}: {results['total']}")
        data["ip_list"] = list(dict.fromkeys(self.filter_search(results, data['domain'], DOMAIN)))
        if data["subdomain"]["name"] != None:
            data["subdomain"]["ip_list"] = self.subdomain_results(data)

        return data

    ''' thread_search()
        Description: Executes the search in threads for the given info
        Params:
            - data: type dict -> dictionary containing domain/subdomain object info
        returns:
            - return the dict object with the parsed info
    '''
    def thread_search(self, elements: list):
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ThreadExecutor:
                log_module.log_cli("Shodan_Enumeration_Module------>Searching public exposed data", "info", INFO)
                futures = ThreadExecutor.map(self.domain_results, elements)
                futures = list(futures)                

            return elements
            
        except shodan.APIError as e:
            log_module.DEBUG(str(e), "debug", DEBUG)
