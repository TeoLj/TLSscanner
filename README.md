# TLSscanner
This is a TLS scanner tool that allows you to scan for TLS 1.2 and TLS 1.3 supported ciphers of domains. It provides various options that can be used through the terminal to customize the scanning process, including a HTML report containing plots of the results.

The scan results are saved in a default output folder which consists of:
- a csv file containing the domain names and their supported ciphers
- a csv file containing the ciphers and how often they occured
- a text file containing the reported errors per domain
- a html report containing an error plot and a plot of cipher occurences
- 
The HTML page is saved in the output folder and by double-clicking it, the plots are visible in a browser's tab. Another option to open the HTML page is through the following command in the terminal:
```shell
    open output/top-1m_plot.html
```

## Installation
To install the TLS scanner, follow these steps:

1. Clone the repository:
    ```shell
    git clone https://github.com/your-username/TLSscanner_FP.git
    ```

2.  Navigate to the TLSscanner directory:
    ```shell
    cd TLSscanner_FP
    ```


3. Install the required dependencies by running the following command:
    ```shell
    go mod tidy
    ```
This will download the necessary Go modules as specified in `go.mod` and update `go.sum` accordingly. The Go version is **go1.22.0**.

## Usage
The scanner's repository includes *top-1m.csv* which contains 1 million of the most popular public api urls. 
To use the TLS scanner, navigate to the project directory and run:

```shell
go run . [options]
```
Options include:
- **-domains (STRING)** to specify domains for scanning.
- **-csv (STRING)** to specify a path to a csv-file containing a list of domains (one per line) to scan. The format of the csv file should be *number,domain name*.
- **-entries (INT)** to set the number of entries to scan from the CSV file (default set to -1 to scan all entries).
- **-timeout (INT)** to set the timeout for each scan attempt of a domain (default 3s).
- **-naive (BOOL)** to scan sequentially without concurrency feature (default false).
- **-concurrency (INT)** to set the number of concurrent scans (default set to maximum number of logical CPUs). Default mode.
- **-saveDir (STRING)** to specify the directory to save the scan results.

Only **-domains** OR **-csv** can be used, not both. 

## Example
This example scans 30 entries of the file *top-1m.csv*. The scan results are saved in a default *output* folder within the same directory as the scanner.

```shell
go run . -csv=top-1m.csv -entries=30 
```

This example does the same as above but saves the output files in the specified *saveDir* directory. The naive scanner runs.

``` shell
go run . -csv=top-1m.csv -entries=30 -naive -saveDir="/home/teodora/Desktop"
```

This example scans two specified domains and saves the results in the default folder called *output* within the scanner's directory. Do not use blank spaces to separate the domains! Just use comma separation.
``` shell
 go run . -domains=www.tum.de,www.google.com
```

### HTML Plot
Scan results of 500 entries from *top-1m.csv*
![ExamplePlot](https://github.com/TeoLj/TLSscanner_FP/assets/16741630/5797aadb-c4d0-4d8c-8613-fecef2c53482)


## Features 
- Support for scanning TLS 1.2 and TLS 1.3 cipher suites.
- Option for concurrent scanning to improve speed.
- Ability to handle and categorize various connection errors.
- Generation of an HTML report summarizing the scan results.
