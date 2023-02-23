# Retrieve data from file
def retrieve_data(file_path: str):
    text_file = open(file_path  , 'r', encoding="utf-8")
    elements = list()
    for line in text_file:
        elements.append(line.replace("\n", ""))

    return elements
