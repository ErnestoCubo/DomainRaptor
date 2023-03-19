import concurrent.futures

from ..log import log_module
from logging import INFO, DEBUG
from ..regex import regex_module

# Retrieve data from file
def retrieve_data(file_path: str):
    try:
        with open(file_path  , 'r', encoding="utf-8") as text_file:
            elements = list()
            for line in text_file:
                elements.append(line.replace("\n", ""))

            return elements
    except IOError as e:
        log_module.log_cli(str(e), "debug", DEBUG)
        exit(12)

# If regex module was selected for URLs then this search will extract domains and subdomains
def extract_domain(structure_domains: str):
    has_subdomain = structure_domains[3].find(".")
    if has_subdomain != -1:
        splitted_structure = structure_domains[3].split('.')

        return splitted_structure
    
    return structure_domains[3]

def tranform_to_dict_in_threads(queried_info: list):
    formalized_data = dict()
    try:
        with concurrent.futures.ProcessPoolExecutor(max_workers=10) as ThreadExecutor:
            log_module.log_cli("Data_Transformation_Module------>Transforming data", "info", INFO)
            futures = ThreadExecutor.map(regex_module.split_domain, queried_info)
            futures = list(futures)
            print(futures)
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
            log_module.log_cli('Data_Trasformation_Module------>Data transformed correctly the preset format is {<DOMAIN>: INFO}', "info", INFO)
            
            return formalized_data
    except Exception as e:
        log_module.log_cli(str(e), "debug", DEBUG)
        return None
