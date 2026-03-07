import concurrent.futures

from ..utils import logger
from logging import INFO, DEBUG
from . import regex_engine

# Retrieve data from file
def retrieve_data(file_path: str):
    try:
        with open(file_path  , 'r', encoding="utf-8") as text_file:
            elements = list()
            for line in text_file:
                elements.append(line.replace("\n", ""))

            return elements
    except IOError as e:
        logger.log_cli(str(e), "debug", DEBUG)
        exit(12)

# If regex module was selected for URLs then this search will extract domains and subdomains
def extract_domain(structure_domains: str):
    has_subdomain = structure_domains[3].find(".")
    if has_subdomain != -1:
        splitted_structure = structure_domains[3].split('.')

        return splitted_structure
    
    return structure_domains[3]


def transform_to_dict_in_threads(queried_info: list) -> dict | None:
    formalized_data = dict()
    try:
        with concurrent.futures.ProcessPoolExecutor(max_workers=10) as ThreadExecutor:
            logger.log_cli("Data_Transformation_Module------>Transforming data", "info", INFO)
            futures = ThreadExecutor.map(regex_engine.split_domain, queried_info)
            futures = list(futures)
            for x in futures:
                if type(x) != str:
                    formalized_data[x[1]] = {
                        "Domain": {
                            "name": x[0],
                            "IPs":list()
                        },
                        "Subdomains": [{
                            "name": x[1] + x[0],
                            "IPs":list()
                        }]
                    }
                else:
                    formalized_data[x] = dict()
                    formalized_data[x]["Domain"] = {
                            "name": x,
                            "IPs":list()
                        }
            logger.log_cli('Data_Transformation_Module------>Data transformed correctly', "info", INFO)
            
            return formalized_data
    except Exception as e:
        logger.log_cli(str(e), "debug", DEBUG)
        return None  # Explicit return on error
        return None
