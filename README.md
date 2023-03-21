# DomainRaptor

## Usage

```

DomainRaptor.py [-h] [-t EXECUTION_THREADS] [-f FORMAT] [-e EXPR] [-i FILE_PATH] [-a API_KEY]

Extract sundomains and domains from a masive list retrieving the list from a file

options:
  -h, --help            show this help message and exit
  -t EXECUTION_THREADS, --threads EXECUTION_THREADS
                        Threads used for executing the query, the assigned threads should be less than the length of the list
  -f FORMAT, --format FORMAT
                        Format that should be used in order to export data
  -e EXPR, --expresion EXPR
                        Specifies the data that should be extracted options avalaible are: 1 -> Used for extract IPv4 2 -> Extract domains and subdoamins 3 -> Extract URLs and other protocols URI 4) IPv6
  -i FILE_PATH, --input_file FILE_PATH
                        Specifies the file path where data should be fetched
  -a API_KEY, --api_key API_KEY
                        API key used for researching in shodan
```

![image](https://user-images.githubusercontent.com/30570774/226492038-ece35c9d-ff58-433d-b05c-ac0796aac8a3.png)
![image](https://user-images.githubusercontent.com/30570774/226492085-6c7259f5-6173-4fd0-9ccc-76b35c163483.png)
