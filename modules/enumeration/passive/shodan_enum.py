import shodan
import json
from logging import DEBUG

from ...log import log_module
from ...log.print import printing_module
class Shodan_enum():

    def __init__(self, api_key) -> None:
        self.client = shodan.Shodan(api_key)
        self.FACETS = [
            'org',
            'domain',
            'port',
            'asn',

            # We only care about the top 3 countries, this is how we let Shodan know to return 3 instead of the
            # default 5 for a facet. If you want to see more than 5, you could do ('country', 1000) for example
            # to see the top 1,000 countries for a search query.
            ('country', 100),
        ]

    def filter_search(self, results: dict, key: str):
        temporal_list = list()
        for result in results['matches']:
            if (key in result["domains"]) or key in result["hostnames"]:
                temporal_list.append(result['ip_str'])

        return temporal_list
    
    def basic_search(self, elements: dict):
        try:
            for key in elements.keys():
                results = self.client.search(f"hostname:{key}")
                print(f"Result founds for  {key}: {results['total']}")
                elements[key]["Domain"]["IPs"] = list(dict.fromkeys(self.filter_search(results, key)))
                
            return elements
            
        except shodan.APIError as e:
            log_module.DEBUG(str(e), "debug", DEBUG)
