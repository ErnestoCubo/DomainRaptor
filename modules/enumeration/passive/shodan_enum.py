import shodan
import requests

class Shodan_enum():

    def __init__(self, api_key) -> None:
        self.api = shodan.Shodan(api_key)
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

    def basic_search(self, query):
        result = self.api.count(query, self.FACETS)

        return result
