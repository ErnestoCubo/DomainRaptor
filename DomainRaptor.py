#!/usr/bin/python3

import random
from logging import INFO

# Local modules
from modules.log import log_module
from modules.log.print import printing_module
from modules.regex import regex_module
from modules.args_parser import args_module
from modules.data_transformation import data_transformation_module  
from modules.enumeration.passive import shodan_enum

# Main function
def main(args):
    title_pos = random.randint(0,3)
    printing_module.print_title(title_pos)

    # storing arguments
    select_expr = args.expr
    expr = regex_module.extract_option(select_expr)
    execution_threads = args.execution_threads
    file_path = args.file_path
    api_key = args.api_key

    # Fething file data
    log_module.log_cli("Main------>Fetching file data", "info", INFO)
    file_contents = data_transformation_module.retrieve_data(file_path)
    element_count = len(file_contents)
    log_module.log_cli("Printing file data:", "info", INFO)
    log_module.log_cli(f"Elements count -> {element_count}", "info", INFO)

    regexed_list = regex_module.execute_in_threads(execution_threads, element_count, file_contents, expr)

    if select_expr == '2':
        domain_dict = data_transformation_module.tranform_to_dict_in_threads(regexed_list)
        if domain_dict != None:
            printing_module.print_elements(domain_dict)
    shodan_object = shodan_enum.Shodan_enum(api_key="sgztonoBQ1APEMl870zNMg1EMBiojN25")
    domain_dict = shodan_object.basic_search(domain_dict)
    printing_module.print_elements(domain_dict)

    return 0

if __name__ == '__main__':
    args = args_module.command_line_args()
    main(args)
