import concurrent.futures
import re
from logging import INFO, ERROR, DEBUG
from ..log import log_module
from ..log.print import printing_module

REGEX_SPLIT_DOMAINS = re.compile(r"(?P<Subdomain>([\w-]+\.){1,10})?(?P<Domain>[\w-]+\.{1}[\w-]+$)")

''' find_patterns()
        Description: It will filter and match all patterns given by a compiled regex expression
        Params:
            - src_list: type str -> list of data in which the regex will be performed
            - regex_expr: type int -> regex expression that will be used to filter and match data
        returns:
            - It returns a tuple with the finds
'''
def find_patterns(src_list: list, regex_expr):
    regex_pattern = re.compile(regex_expr, flags=re.I|re.M)
    finds = regex_pattern.findall(str(src_list))

    return finds

''' execute_in_threads()
        Description: It will execute the regex filter by dividing the data list into smaller pieces of data which will be proccesed then using CPU bound operations
        it will divide the list into smaller data lists by using compression lists, note that its important to now that the given threads can't be a larger number than the list length
        Params:
            - execution_threads: type int -> threads to be used
            - element_count: type int -> len of the list
            - file_contents: type list -> data to be processed
            - expr: type regex expression -> regex expression that will be used to filter and match data
        returns:
            - It returns a list with the filtered data
'''
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
        log_module.log_cli("The matched patterns are:", "info", INFO)
        printing_module.print_elements(results)

        return results

    except Exception as e:
        log_module.log_cli(str(e), "debug", DEBUG)

''' split_domain()
        Description: It will match subdomain and domainand give them into a tuple
        Params:
            - structure_domains: type list -> list with a domain and subdomain to be splitted into
        returns:
            - It returns a tuple with the splitted matches
'''
def split_domain(structure_domains):
    domain_string = structure_domains[3]
    splitted_list = REGEX_SPLIT_DOMAINS.match(domain_string)
    if splitted_list:
        
        if splitted_list.group("Subdomain") is not None:
            return splitted_list.group("Domain"), splitted_list.group("Subdomain")
        return splitted_list.group("Domain")

''' extract_option()
        Description: 
        Params:
            - option: type str -> option given to select a regex expression
        returns:
            - It returns the expression object to be used then
'''
def extract_option(option):
    match option:
        case '1':
            expr = r"\b(?:(?:(?:2[0-5]{2}|1[0-9]{2}|[1-9][0-9]|[0-9])\.){3}(?:2[0-5]{2}|1[0-9]{2}|[1-9][0-9]|[1-9]))"
        case '2':
            expr = r"(http|https)(\:\/{2})(w{3}\.)?([a-zA-Z0-9!@#$&()%-`.+,\"][^',\/]+)"
        case '3':
            expr = r"([a-z,A-Z]+\:\/{2}[a-zA-Z0-9!@#$&()%-`.+,/\"]+)"
        case '4':
            expr = r"^(([0-9a-fA-F]){1,4})\\:){7}([0-9a-fA-F]){1,4}"
        case _:
            log_module.log_cli("Invalid expression option try again setting a valid -e <value>", "error", ERROR)
            exit(1)
        
    return expr
