#!/usr/bin/python3

import random
from logging import INFO, ERROR, DEBUG

# Local modules
from modules.log import log_module
from modules.log.print import printing_module
from modules.regex import regex_module
from modules.args_parser import args_module
from modules.data_transformation import data_transformation_module  

# Main function
def main(args):
    title_pos = random.randint(0,3)
    printing_module.print_title(title_pos)

    # storing arguments
    expr = regex_module.extract_option(args.expr)
    execution_threads = args.execution_threads
    file_path = args.file_path

    # Fething file data
    msg = "Main------>Fetching file data"
    log_module.log_cli(msg, "info", INFO)
    file_contents = data_transformation_module.retrieve_data(file_path)
    element_count = len(file_contents)
    msg = "Printing file data:"
    log_module.log_cli(msg, "info", INFO)
    printing_module.print_list(file_contents)
    msg = "Elements count -> " + str(element_count)
    log_module.log_cli(msg, "info", INFO)

    regex_module.execute_in_threads(execution_threads, element_count, file_contents, expr)

    return 0

if __name__ == '__main__':
    args = args_module.command_line_args()
    main(args)
