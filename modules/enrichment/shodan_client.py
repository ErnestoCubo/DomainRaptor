import shodan
import requests
from logging import DEBUG

from ..utils import logger


class ShodanClient:
    """Client for interacting with Shodan API."""

    def __init__(self, api_key: str) -> None:
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

    def basic_search(self, elements: dict) -> dict:
        """Search Shodan for information about domains.
        
        Args:
            elements: Dictionary of domains to search.
            
        Returns:
            Enriched dictionary with IP information.
        """
        if elements is None:
            return {}
            
        try:
            for key in elements.keys():
                results = self.client.search(key)
                logger.log_cli(f"Results found for {key}: {results['total']}", "info", DEBUG)
                for result in results['matches']:
                    elements[key]["Domain"]["IPs"].append(result['ip_str'])
            
            return elements
            
        except shodan.APIError as e:
            logger.log_cli(f"Shodan API error: {e}", "debug", DEBUG)
            return elements  # Return original elements on error
