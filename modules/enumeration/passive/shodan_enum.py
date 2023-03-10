import shodan
import requests
from logging import DEBUG

from ...log import log_module

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

    def basic_search(self, elements: dict):
        try:
            print(elements.keys())
            for key in elements.keys():
                results = self.client.search(key)
                print(f"Result founds for  {key}: {results['total']}")
                elements[key]["IPs"] = list()
                for result in results['matches']:
                    elements[key]["IPs"].append(result['ip_str'])
            
            return elements
            
        except shodan.APIError as e:
            log_module.DEBUG(str(e), "debug", DEBUG)
