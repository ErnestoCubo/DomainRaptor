import concurrent.futures

from ..log import log_module
from logging import INFO, DEBUG

# Retrieve data from file
def retrieve_data(file_path: str):
    text_file = open(file_path  , 'r', encoding="utf-8")
    elements = list()
    for line in text_file:
        elements.append(line.replace("\n", ""))

    return elements

# If regex module was selected for URLs then this search will extract domains and subdomains
def extract_domain(default_string: str):
    contains = default_string[3].find(".")
    if contains != -1:
        subdomain_list = default_string[3].split('.')

        return subdomain_list
    
    return default_string[3]

def tranform_to_dict_in_threads(queried_info: list):
    formalized_data = dict()
    try:
        with concurrent.futures.ProcessPoolExecutor(max_workers=10) as ThreadExecutor:
            msg = "Data_Transformation_Module------>Transforming data"
            log_module.log_cli(msg, "info", INFO)
            futures = ThreadExecutor.map(extract_domain, queried_info)
            futures = list(futures)
            for x in futures:
                if type(x) != str:
                    formalized_data[x[1]] = None
                else:
                    formalized_data[x] = None
            msg = 'Data_Trasformation_Module------>Data transformed correctly the preset format is {<DOMAIN>: INFO}'
            log_module.log_cli(msg, "info", INFO)
            print(formalized_data)
    except Exception as e:
        log_module.log_cli(str(e), "debug", DEBUG)
