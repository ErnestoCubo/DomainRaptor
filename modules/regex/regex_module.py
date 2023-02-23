import concurrent.futures
import re
from logging import INFO, ERROR, DEBUG
from ..log import log_module
from ..log.print import printing_module

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
        log_module.log_cli(msg, "info", INFO)

        # Adding multithreading
        with concurrent.futures.ThreadPoolExecutor() as threadExecutor:
            msg = "Main------>Execution started"
            log_module.log_cli(msg, "info", INFO)
            thread_future = threadExecutor.submit(find_patterns, elements, expr)
            msg = "Main------>Waiting threads to finish the work . . ."
            log_module.log_cli(msg, "info", INFO)
            results = thread_future.result()
            
        msg = "Main------>Execution finished"
        log_module.log_cli(msg, "info", INFO)

        # Printing results
        msg = "The matched patterns are:"
        log_module.log_cli(msg, "info", INFO)
        printing_module.print_list(results)

    except Exception as e:
        log_module.log_cli(str(e), "debug", DEBUG)

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
            log_module.log_cli(msg, "error", ERROR)
            exit(1)
        
    return expr
