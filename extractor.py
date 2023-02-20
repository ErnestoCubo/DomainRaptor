import re
import os

def open_file(file_path: str):
    text_file = open(file_path  , 'r')
    content = text_file.read()

    return content

def find_patterns(regex_expr: str, src_string: str):
    regex_pattern = re.compile(regex_expr, flags=re.I|re.M)
    finds = regex_pattern.findall(src_string)

    return finds

def main():
    user_input = input("Which regex you want to use:\n 1) IP\n 2) URLs\n 3) Search for URLs and file acceses\nSelect an option: ")
    match user_input:
        case '1':
            expr = r"(?:\d{1,3}\.){3}\d{1,3}"
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
    finds = find_patterns(expr, file_contents)
    print("The matched patterns are: \n")
    print(finds)
    return 0

if __name__ == '__main__':
    main()
