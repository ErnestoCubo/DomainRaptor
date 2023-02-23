import argparse

# Defining CLI args
def command_line_args():
    parser = argparse.ArgumentParser(description="Extract sundomains and domains from a masive list retrieving the list from a file")
    parser.add_argument("-t", "--threads", dest="execution_threads", default=10, help="Threads used for executing the query, the assigned threads should be less than the length of the list", type=int)
    parser.add_argument("-f", "--format", dest="format", default=None, help="Format that should be used in order to export data")
    parser.add_argument("-e", "--expresion", dest="expr", default='1', help="Specifies the data that should be extracted options avalaible are:\n  1 -> Used for extract IPv4\n  2 -> Extract domains and subdoamins\n  3 -> Extract URLs and other protocols URI\n  4) IPv6")
    parser.add_argument("-i", "--input_file", dest="file_path", default='./patterns.txt', help="Specifies the file path where data should be fetched")

    args = parser.parse_args()

    return args
