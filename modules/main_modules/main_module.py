import random
from logging import INFO

# Local modules
from ..log import log_module
from ..log.print import printing_module
from ..regex import regex_module
from ..data_transformation import data_transformation_module  
from ..enumeration.passive import shodan_enum

''' fetch_data()
        Description: Fetch all data for filtering it into a regexed list
        Params:
            - file_path: type str -> path in which the data is stored to be parsed
            - execution_threads: type int -> threads to execute for get a regexed parsed list
            - expr: type regex -> regex expression to be used
        returns:
            - It returns a regexed list
'''
def fetch_data(file_path: str, execution_threads: int, expr):
    log_module.log_cli("Main------>Fetching file data", "info", INFO)
    file_contents = data_transformation_module.retrieve_data(file_path)
    element_count = len(file_contents)
    log_module.log_cli("Printing file data:", "info", INFO)
    log_module.log_cli(f"Elements count -> {element_count}", "info", INFO)
    regexed_list = regex_module.execute_in_threads(execution_threads, element_count, file_contents, expr)

    return regexed_list

''' develop_action()
        Description: Depending on the option choosen by the user it will act in differnt ways for retrieving data from a regexed list
        Params:
            - select_expr: type str -> selected expresion it indicates which type of data its going to be processed
            - regexed_list: type list -> filtered values showed as a list
            - api_key: type str -> Needed to develop shodan enumeration
        returns:
            - None
'''
def develop_action(select_expr: str, regexed_list: list, api_key: str):
    if select_expr == '2':
        domain_list = data_transformation_module.tranform_to_dict_in_threads(regexed_list)
        shodan_object = shodan_enum.Shodan_enum(api_key=api_key)
        domain_list = shodan_object.thread_search(domain_list)
        printing_module.print_elements(domain_list)