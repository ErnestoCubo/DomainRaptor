#!/usr/bin/python3

import re
import whois
import logging
import argparse
import concurrent.futures
import random
import time
import traceback
from colorama import Fore

def log_CLI(msg: str, context):
    logging_format="%(asctime)s: %(message)s"
    if context == "info":
        logging.basicConfig(format=logging_format, level=logging.INFO, datefmt="[%H:%M:%S]")
        logging.info(msg)
    elif context == "error":
        logging.basicConfig(format=logging_format, level=logging.ERROR, datefmt="[%H:%M:%S]")
        logging.error(msg)
    elif context == 'debug':
        logging.basicConfig(format=logging_format, level=logging.DEBUG, datefmt="[%H:%M:%S]")
        logging.exception(msg)
    return 0

def retrieve_data(file_path: str):
    text_file = open(file_path  , 'r', encoding="utf-8")
    elements = list()
    for line in text_file:
        elements.append(line.replace("\n", ""))

    return elements

# Printing lists
def print_list(elements):
    print(*elements, sep="\n")

    return

def find_patterns(src_list: list, regex_expr):
    regex_pattern = re.compile(regex_expr, flags=re.I|re.M)
    finds = regex_pattern.findall(str(src_list))

    return finds

def execute_in_threads(execution_threads: int, element_count: int, file_contents: list, expr):
    # Calculating elements per thread
    try:
        if execution_threads > element_count:
            msg = "[ERROR] Assigned threads are longer than the length of the list provided"
            raise BufferError(msg)
        length_elements_per_thread = element_count / execution_threads
        elements = [file_contents[x:x+int(length_elements_per_thread)] for x in range(0, element_count, int(length_elements_per_thread))]
        msg = "Main------>Preparing threads for extract domains"
        log_CLI(msg, "info")

        # Adding multithreading
        with concurrent.futures.ThreadPoolExecutor() as threadExecutor:
            msg = "Main------>Execution started"
            log_CLI(msg, "info")
            thread_future = threadExecutor.submit(find_patterns, elements, expr)
            msg = "Main------>Waiting threads to finish the work . . ."
            log_CLI(msg, "info")
            results = thread_future.result()
        msg = "Main------>Execution finished"
        log_CLI(msg, "info")

        # Printing results
        msg = "The matched patterns are:"
        log_CLI(msg, "info")
        print_list(results)

    except Exception as e:
        log_CLI(str(e), "debug")

def validate_domain():
    return

def extract_option(option):
    match option:
        case '1':
            expr = r"\b(?:(?:(?:2[0-5]{2}|1[0-9]{2}|[1-9][0-9]|[0-9])\.){3}(?:2[0-5]{2}|1[0-9]{2}|[1-9][0-9]|[1-9]))"
        case '2':
            expr = r"(http|https)(\:\/{2})(w{3}\.)?([a-zA-Z0-9!@#$&()%-`.+,/\"]+)(\.[a-z]{1,5})"
        case '3':
            expr = r"([a-z,A-Z]+\:\/{2}[a-zA-Z0-9!@#$&()%-`.+,/\"]+)"
        case '4':
            expr = r"^(([0-9a-fA-F]){1,4})\\:){7}([0-9a-fA-F]){1,4}"
        case _:
            msg = "Invalid expression option try again setting a valid -e <value>"
            log_CLI(msg, "error")
            exit(1)
        
    return expr

# Defining CLI args
def command_line_args():
    parser = argparse.ArgumentParser(description="Extract sundomains and domains from a masive list retrieving the list from a file")
    parser.add_argument("-t", "--threads", dest="execution_threads", default=10, help="Threads used for executing the query, the assigned threads should be less than the length of the list", type=int)
    parser.add_argument("-f", "--format", dest="format", default=None, help="Format that should be used in order to export data")
    parser.add_argument("-e", "--expresion", dest="expr", default='1', help="Specifies the data that should be extracted options avalaible are:\n  1 -> Used for extract IPv4\n  2 -> Extract domains and subdoamins\n  3 -> Extract URLs and other protocols URI\n  4) IPv6")
    parser.add_argument("-i", "--input_file", dest="file_path", default='./patterns.txt', help="Specifies the file path where data should be fetched")

    args = parser.parse_args()

    return args

#Printing titles
def print_title(title_pos):
    titles = [
        Fore.RED + "\n\n·▄▄▄▄        • ▌ ▄ ·.  ▄▄▄· ▪   ▐ ▄ ▄▄▄   ▄▄▄·  ▄▄▄·▄▄▄▄▄      ▄▄▄  \n██▪ ██ ▪     ·██ ▐███▪▐█ ▀█ ██ •█▌▐█▀▄ █·▐█ ▀█ ▐█ ▄█•██  ▪     ▀▄ █·\n▐█· ▐█▌ ▄█▀▄ ▐█ ▌▐▌▐█·▄█▀▀█ ▐█·▐█▐▐▌▐▀▀▄ ▄█▀▀█  ██▀· ▐█.▪ ▄█▀▄ ▐▀▀▄ \n██. ██ ▐█▌.▐▌██ ██▌▐█▌▐█ ▪▐▌▐█▌██▐█▌▐█•█▌▐█ ▪▐▌▐█▪·• ▐█▌·▐█▌.▐▌▐█•█▌\n▀▀▀▀▀•  ▀█▄▀▪▀▀  █▪▀▀▀ ▀  ▀ ▀▀▀▀▀ █▪.▀  ▀ ▀  ▀ .▀    ▀▀▀  ▀█▄▀▪.▀  ▀\n",
        Fore.GREEN + "\n\n______ ________  ___  ___  _____ _   _ ______  ___  ______ _____ ___________ \n|  _  \  _  |  \/  | / _ \|_   _| \ | || ___ \/ _ \ | ___ \_   _|  _  | ___ \ \n| | | | | | | .  . |/ /_\ \ | | |  \| || |_/ / /_\ \| |_/ / | | | | | | |_/ /\n| | | | | | | |\/| ||  _  | | | | . ` ||    /|  _  ||  __/  | | | | | |    / \n| |/ /\ \_/ / |  | || | | |_| |_| |\  || |\ \| | | || |     | | \ \_/ / |\ \ \n|___/  \___/\_|  |_/\_| |_/\___/\_| \_/\_| \_\_| |_/\_|     \_/  \___/\_| \_|\n",        
        Fore.GREEN + "\n\n▓█████▄  ▒█████   ███▄ ▄███▓ ▄▄▄       ██▓ ███▄    █  ██▀███   ▄▄▄       ██▓███  ▄▄▄█████▓ ▒█████   ██▀███  \n▒██▀ ██▌▒██▒  ██▒▓██▒▀█▀ ██▒▒████▄    ▓██▒ ██ ▀█   █ ▓██ ▒ ██▒▒████▄    ▓██░  ██▒▓  ██▒ ▓▒▒██▒  ██▒▓██ ▒ ██▒\n░██   █▌▒██░  ██▒▓██    ▓██░▒██  ▀█▄  ▒██▒▓██  ▀█ ██▒▓██ ░▄█ ▒▒██  ▀█▄  ▓██░ ██▓▒▒ ▓██░ ▒░▒██░  ██▒▓██ ░▄█ ▒\n░▓█▄   ▌▒██   ██░▒██    ▒██ ░██▄▄▄▄██ ░██░▓██▒  ▐▌██▒▒██▀▀█▄  ░██▄▄▄▄██ ▒██▄█▓▒ ▒░ ▓██▓ ░ ▒██   ██░▒██▀▀█▄  \n░▒████▓ ░ ████▓▒░▒██▒   ░██▒ ▓█   ▓██▒░██░▒██░   ▓██░░██▓ ▒██▒ ▓█   ▓██▒▒██▒ ░  ░  ▒██▒ ░ ░ ████▓▒░░██▓ ▒██▒\n ▒▒▓  ▒ ░ ▒░▒░▒░ ░ ▒░   ░  ░ ▒▒   ▓▒█░░▓  ░ ▒░   ▒ ▒ ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░▒▓▒░ ░  ░  ▒ ░░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░\n ░ ▒  ▒   ░ ▒ ▒░ ░  ░      ░  ▒   ▒▒ ░ ▒ ░░ ░░   ░ ▒░  ░▒ ░ ▒░  ▒   ▒▒ ░░▒ ░         ░      ░ ▒ ▒░   ░▒ ░ ▒░\n ░ ░  ░ ░ ░ ░ ▒  ░      ░     ░   ▒    ▒ ░   ░   ░ ░   ░░   ░   ░   ▒   ░░         ░      ░ ░ ░ ▒    ░░   ░ \n   ░        ░ ░         ░         ░  ░ ░           ░    ░           ░  ░                      ░ ░     ░    \n\n",
        Fore.RED + "\n\n_____________________  _____________________   ______________________________________________ \n___  __ \_  __ \__   |/  /__    |___  _/__  | / /__  __ \__    |__  __ \__  __/_  __ \__  __ \ \n__  / / /  / / /_  /|_/ /__  /| |__  / __   |/ /__  /_/ /_  /| |_  /_/ /_  /  _  / / /_  /_/ /\n_  /_/ // /_/ /_  /  / / _  ___ |_/ /  _  /|  / _  _, _/_  ___ |  ____/_  /   / /_/ /_  _, _/ \n/_____/ \____/ /_/  /_/  /_/  |_/___/  /_/ |_/  /_/ |_| /_/  |_/_/     /_/    \____/ /_/ |_|  \n"
        ]
    print(titles[title_pos] + Fore.WHITE)
    time.sleep(1)

    return

# Main function
def main(args):
    title_pos = random.randint(0,3)
    print_title(title_pos)

    # storing arguments
    expr = extract_option(args.expr)
    execution_threads = args.execution_threads
    file_path = args.file_path

    # Fething file data
    msg = "Main------>Fetching file data"
    log_CLI(msg, "info")
    file_contents = retrieve_data(file_path)
    element_count = len(file_contents)
    msg = "Printing file data:"
    log_CLI(msg, "info")
    print_list(file_contents)
    msg = "Elements count -> " + str(element_count)
    log_CLI(msg, "info")

    execute_in_threads(execution_threads, element_count, file_contents, expr)

    return 0

if __name__ == '__main__':
    args = command_line_args()
    main(args)
