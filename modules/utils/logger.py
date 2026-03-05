import logging
from colorama import Fore
from logging import INFO, ERROR, DEBUG

# Logging featuraes
def log_cli(msg: str, context: str, logging_level):
    logging_format="%(asctime)s: %(message)s"
    logging.basicConfig(format=logging_format, level=logging_level, datefmt="[%H:%M:%S]")
    if context == "info":
        logging.info( Fore.YELLOW + msg + Fore.WHITE)
    elif context == "error":
        logging.error( Fore.RED + msg + Fore.WHITE)
    elif context == 'debug':
        logging.exception(msg)
    return 0
