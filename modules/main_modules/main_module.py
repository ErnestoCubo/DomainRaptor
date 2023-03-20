import random
from logging import INFO

# Local modules
from ..log import log_module
from ..log.print import printing_module
from ..regex import regex_module
from ..data_transformation import data_transformation_module  
from ..enumeration.passive import shodan_enum


def fetch_data(file_path: str, execution_threads: int, expr):

    log_module.log_cli("Main------>Fetching file data", "info", INFO)
    file_contents = data_transformation_module.retrieve_data(file_path)
    element_count = len(file_contents)
    log_module.log_cli("Printing file data:", "info", INFO)
    log_module.log_cli(f"Elements count -> {element_count}", "info", INFO)
    regexed_list = regex_module.execute_in_threads(execution_threads, element_count, file_contents, expr)

    return regexed_list

def develop_action(select_expr: str, regexed_list: list, api_key: str):

    if select_expr == '2':
        domain_dict = data_transformation_module.tranform_to_dict_in_threads(regexed_list)
        shodan_object = shodan_enum.Shodan_enum(api_key=api_key)
        domain_dict = shodan_object.basic_search(domain_dict)
        printing_module.print_elements(domain_dict)