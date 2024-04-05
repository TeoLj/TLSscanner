# TLSscanner
This is a TLS scanner tool that allows you to scan for TLS 1.2 and TLS 1.3 supported ciphers of domains. It provides various options that can be used through the terminal to customize the scanning process, including a HTML report containing plots of the results.

The scan results consist of:
- a csv file containing the domain names and their supported ciphers
- a csv file containing the ciphers and how often they occured
- a text file containing the reported errors per domain
- a html report containing an error plot and a plot of cipher occurences

## Installation
To install the TLS scanner, follow these steps:

1. Clone the repository:
    ```shell
    git clone https://github.com/your-username/TLSscanner.git
    ```

2.  Navigate to the TLSscanner directory:
    ```shell
    cd TLSscanner
    ```


3. Install the required dependencies by running the following command:
    ```shell
    go mod 
    ```
This will download the necessary Go modules as specified in `go.mod` and update `go.sum` accordingly.

## Usage
The scanner's repository includes *api_urls.csv* which contains 1427 of the most popular public api urls. 
To use the TLS scanner, navigate to the project directory and run:

```shell
go run . [options]
```
Options include:
- **-domains** to specify domains for scanning
- **-csv to** specify a path to a csv-file containing a list of domains (one per line) to scan.
- **-entries** to set the number of entries to scan from the CSV file (default set to -1 to scan all entries)
- **-timeout** to set the timeout for each scan attempt of a domain (default 3s)
- **-naive** to scan sequentially without concurrency feature
- **-concurrency** to set the number of concurrent scans (default set to maximum number of logical CPUs )
- **-saveDir** to specify the directory to save the scan results
 

## Example
This example scans 30 entries of the file *api_urls.csv*. The scan results are saved in a default *output* folder within the same directory as the scanner.

```shell
go run . -csv= api_urls.csv -entries=30 
```

This example does the same as above but saves the output files in the specified *saveDir* directory.

``` shell
go run . -csv=api_urls.csv -entries=30 -saveDir="/home/teodora/Desktop"
```

This example scans two specified domains and saves the results in the default folder called *output* within the scanner's directory.
``` shell
 go run . -domains=www.tum.de,www.google.com
```

### HTML Plot
![Scan results of 500 entries](/home/teodora/Desktop/ExamplePlot.jpeg)


## Features 
- Support for scanning TLS 1.2 and TLS 1.3 cipher suites.
- Options for concurrent scanning to improve speed.
- Ability to handle and categorize various connection errors.
- Generation of an HTML report summarizing the scan results.