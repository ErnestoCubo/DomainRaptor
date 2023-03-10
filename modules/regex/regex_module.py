import concurrent.futures
import re
from logging import INFO, ERROR, DEBUG
from ..log import log_module
from ..log.print import printing_module

REGEX_SPLIT_DOMAINS = re.compile(r"(?P<domain>(?:\w*\.)*)(?P<subdomain>\w*)")


def find_patterns(src_list: list, regex_expr):
    regex_pattern = re.compile(regex_expr, flags=re.I|re.M)
    finds = regex_pattern.findall(str(src_list))

    return finds

def execute_in_threads(execution_threads: int, element_count: int, file_contents: list, expr):
    # Calculating elements per thread
    try:
        if execution_threads > element_count:
            raise BufferError("[ERROR] Assigned threads are longer than the length of the list provided")
        length_elements_per_thread = element_count / execution_threads
        elements = [file_contents[x:x+int(length_elements_per_thread)] for x in range(0, element_count, int(length_elements_per_thread))]
        log_module.log_cli("Main------>Preparing threads for extract domains", "info", INFO)

        # Adding multithreading
        with concurrent.futures.ProcessPoolExecutor() as ProccessExecutor:
            log_module.log_cli("Main------>Execution started", "info", INFO)
            future = ProccessExecutor.submit(find_patterns, elements, expr)
            log_module.log_cli("Main------>Waiting threads to finish the work . . .", "info", INFO)
            results = future.result()
            
        log_module.log_cli("Main------>Execution finished", "info", INFO)

        # Printing results
        log_module.log_cli("The matched patterns are:", "info", INFO)
        printing_module.print_elements(results)

        return results

    except Exception as e:
        log_module.log_cli(str(e), "debug", DEBUG)

def validate_domain():
    return

# Splitting domains and subdomains
def split_domain(structure_domains):
    splitted_list = REGEX_SPLIT_DOMAINS.match(structure_domains[3])

    return splitted_list.group("domain"), splitted_list.group("subdomain")

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
            log_module.log_cli("Invalid expression option try again setting a valid -e <value>", "error", ERROR)
            exit(1)
        
    return expr
