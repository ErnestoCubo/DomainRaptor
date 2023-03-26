import concurrent.futures

from ..log import log_module
from logging import INFO, DEBUG
from ..regex import regex_module

''' retrieve_data()
        Description: Opens and parses the list data
        Params:
            - file_path: type str -> path to the txt file
        returns:
            - It return a list with the parsed data
'''
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

''' ip_dict()
        Description: creates the schema for collecting data of each domain
        Params:
            - ip: type str -> IP to structure it data
            - ports: type list -> open ports of each IP
        returns:
            - It return a dictionary for an IP
'''    
def ip_dict(ip: str, ports=None):
        ip_dict = {
            "name": ip,
            "open_ports": ports
        }

        return ip_dict

''' domain_dict()
        Description: creates the schema for collecting data of each domain
        Params:
            - domain: type str -> domain to structure it data
            - subdomain: type str -> subdomain to structure it data
        returns:
            - It return a dictionary which will be used then for filling with more data
'''
def domain_dict(domain: str, subdomain=None):
    if subdomain != None:
        subdomain = subdomain + domain
    temp_dict = {
        "domain": domain,
        "ip_list":list(),
        "subdomain":{
            "name": subdomain,
            "ip_list":list()
        }
    }

    return temp_dict

''' tranform_to_dict_in_threads()
        Description: Transform all list data to be searched into a dict while using CPU processing threads
        Params:
            - queried_info: type list -> List with all splitted domains and subdomains
        returns:
            - It return a dictionary which will be used then for filling with more data
'''
def tranform_to_dict_in_threads(queried_info: list):
    formalized_data = list()
    try:
        with concurrent.futures.ProcessPoolExecutor(max_workers=10) as ProcessPool:
            log_module.log_cli("Data_Transformation_Module------>Transforming data", "info", INFO)
            futures = ProcessPool.map(regex_module.split_domain, queried_info)
            futures = list(futures)
            for x in futures:
                if type(x) == tuple:
                    formalized_data.append(domain_dict(x[0], x[1]))
                else:                    
                    formalized_data.append(domain_dict(x))
            log_module.log_cli('Data_Trasformation_Module------>Data transformed correctly the preset format is {<DOMAIN>: INFO}', "info", INFO)
            
            return formalized_data
    except Exception as e:
        log_module.log_cli(str(e), "debug", DEBUG)
        
        return None
