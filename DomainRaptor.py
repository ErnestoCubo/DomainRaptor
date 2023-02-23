#!/usr/bin/python3

import argparse
import random
import time
from colorama import Fore
from logging import INFO, ERROR, DEBUG

# Local modules
from modules.log import log_module
from modules.log.print import printing_module
from modules.regex import regex_module

def retrieve_data(file_path: str):
    text_file = open(file_path  , 'r', encoding="utf-8")
    elements = list()
    for line in text_file:
        elements.append(line.replace("\n", ""))

    return elements

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
    expr = regex_module.extract_option(args.expr)
    execution_threads = args.execution_threads
    file_path = args.file_path

    # Fething file data
    msg = "Main------>Fetching file data"
    log_module.log_cli(msg, "info", INFO)
    file_contents = retrieve_data(file_path)
    element_count = len(file_contents)
    msg = "Printing file data:"
    log_module.log_cli(msg, "info", INFO)
    printing_module.print_list(file_contents)
    msg = "Elements count -> " + str(element_count)
    log_module.log_cli(msg, "info", INFO)

    regex_module.execute_in_threads(execution_threads, element_count, file_contents, expr)

    return 0

if __name__ == '__main__':
    args = command_line_args()
    main(args)
