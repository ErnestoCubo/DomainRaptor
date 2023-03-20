#!/usr/bin/python3

import random
from logging import INFO

# Local modules
from modules.main_modules import main_module
from modules.regex import regex_module
from modules.args_parser import args_module
from modules.log.print import printing_module

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
    regexed_list = main_module.fetch_data(file_path, execution_threads, expr)

    # Taking passive actions against objetive
    main_module.develop_action(select_expr, regexed_list, api_key)

    return 0

if __name__ == '__main__':
    args = args_module.command_line_args()
    main(args)
