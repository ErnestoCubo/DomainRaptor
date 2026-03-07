#!/usr/bin/python3

import random
from logging import INFO

# Local modules
from modules.utils import logger
from modules.output import printer
from modules.core import regex_engine
from modules.cli import args_parser
from modules.core import data_transformer
from modules.enrichment import shodan_client

# Main function
def main(args):
    title_pos = random.randint(0,3)
    printer.print_title(title_pos)

    # storing arguments
    select_expr = args.expr
    expr = regex_engine.extract_option(select_expr)
    execution_threads = args.execution_threads
    file_path = args.file_path
    api_key = args.api_key

    # Fething file data
    logger.log_cli("Main------>Fetching file data", "info", INFO)
    file_contents = data_transformer.retrieve_data(file_path)
    element_count = len(file_contents)
    logger.log_cli("Printing file data:", "info", INFO)
    logger.log_cli(f"Elements count -> {element_count}", "info", INFO)

    regexed_list = regex_engine.execute_in_threads(execution_threads, element_count, file_contents, expr)

    # Initialize domain_dict to avoid NameError when expr != '2'
    domain_dict = None
    
    if select_expr == '2':
        domain_dict = data_transformer.transform_to_dict_in_threads(regexed_list)
        if domain_dict is not None:
            printer.print_elements(domain_dict)
            
            # Only perform Shodan enrichment if we have domains and an API key
            if api_key:
                shodan_object = shodan_client.ShodanClient(api_key=api_key)
                domain_dict = shodan_object.basic_search(domain_dict)
                printer.print_elements(domain_dict)
    else:
        # For other expression types, just print the extracted patterns
        printer.print_elements(regexed_list)

    return 0

if __name__ == '__main__':
    args = args_parser.command_line_args()
    main(args)
