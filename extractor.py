import re
import whois
import logging
import time
import concurrent.futures

def log_CLI(msg: str):
    logging_format="%(asctime)s: %(message)s"
    logging.basicConfig(format=logging_format, level=logging.INFO, datefmt="[%H:%M:%S]")
    logging.info(msg)
    
    return 0

def open_file(file_path: str):
    text_file = open(file_path  , 'r')
    content = text_file.read()

    return content

def find_patterns(regex_expr: str, src_string: str):
    regex_pattern = re.compile(regex_expr, flags=re.I|re.M)
    finds = regex_pattern.findall(src_string)

    return finds

def validate_domain():
    return

def export_option(option_selected):
    export_format =  input("In which format do you want to export data:\n 1) JSON\n 2) CSV\n 3) YML\n 4) Plain text file\n 5) EXIT\nSelect an option: ")
    match export_format:
        case '1':
            print('JSON\n')
        case '2':
            print('CSV\n')
        case '3':
            print('YML\n')
        case '4':
            print('TXT\n')
        case '5':
            return 0
        case _:
            print("[ERROR]::Invalid option")
            exit(1)
    return

def extract_option():
    user_input = input("Which regex you want to use:\n 1) IPv4\n 2) Split for Domains\n 3) Search for URLs and file acceses\n 4) IPv6\nSelect an option: ")
    match user_input:
        case '1':
            expr = r"\b(?:(?:(?:2[0-5]{2}|1[0-9]{2}|[1-9][0-9]|[0-9])\.){3}(?:2[0-5]{2}|1[0-9]{2}|[1-9][0-9]|[1-9]))"
        case '2':
            expr = r"^(http|https)(\:\/{2})(w{3}\.)?([a-zA-Z0-9!@#$&()%-`.+,/\"]+)(\.[a-z]{1,5})"
        case '3':
            expr = r"(\b[a-z,A-Z]+\:\/{2}[a-zA-Z0-9!@#$&()%-`.+,/\"]+)"
        case '4':
            expr = r"((([0-9a-fA-F]){1,4})\\:){7}([0-9a-fA-F]){1,4}"
        case _:
            print("[ERROR]::Invalid option")
            exit(1)
        
    return expr

def main():
    msg = "Main------>Preparing file to read"
    log_CLI(msg)
    file_path = './patterns.txt'
    file_contents = open_file(file_path)
    print("\nPrinting file content:\n\n" + file_contents + "\n")
    expr = extract_option()
    
    msg = "Main------>Preparing threads for extract domains"
    log_CLI(msg)
    with concurrent.futures.ThreadPoolExecutor() as threadExecutor:
        
        threads = threadExecutor.submit(find_patterns, expr, file_contents)
        msg = "Main------>Execution started"
        log_CLI(msg)
        msg = "Main------>Waiting threads to finish the work . . ."
        log_CLI(msg)
        finds = threads.result()
    
    msg = "Main------>Execution finished"
    log_CLI(msg)
    print("The matched patterns are: \n")
    print(finds)

    return 0

if __name__ == '__main__':
    main()
