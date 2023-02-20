import re
import whois
import logging
import threading
import time

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

def export(option_selected):
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

def main():
    user_input = input("Which regex you want to use:\n 1) IP\n 2) Split for Domains\n 3) Search for URLs and file acceses\n 4) Export\nSelect an option: ")
    match user_input:
        case '1':
            expr = r"\b(?:(?:(?:2[0-5]{2}|1[0-9]{2}|[1-9][0-9]|[0-9])\.){3}(?:2[0-5]{2}|1[0-9]{2}|[1-9][0-9]|[1-9]))"
        case '2':
            expr = r"^(http|https)(\:\/{2})(w{3}\.)?([a-zA-Z0-9!@#$&()%-`.+,/\"]+)(\.[a-z]{1,5})"
        case '3':
            expr = r"(\b[a-z,A-Z]+\:\/{2}[a-zA-Z0-9!@#$&()%-`.+,/\"]+)"
        case _:
            print("[ERROR]::Invalid option")
            exit(1)

    file_path = './patterns.txt'
    file_contents = open_file(file_path)
    print("\nPrinting file content:" + file_contents + "\n")
    print(time.clock_gettime())
    finds = find_patterns(expr, file_contents)
    print("The matched patterns are: \n")
    print(finds)
    export(user_input)
    return 0

if __name__ == '__main__':
    main()
