# TLSscanner
This is a TLS scanner tool that allows you to scan for TLS 1.2 and TLS 1.3 supported ciphers of domains. It provides various options that can be used through the terminal to customize the scanning process, including a HTML page with plots of the results.

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

To use the TLS scanner, navigate to the project directory and run:

```shell
go run . [options]
```
