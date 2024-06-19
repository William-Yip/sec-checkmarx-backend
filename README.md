# GoLang Security Code Scanner API

This project is a GoLang API that allows users to scan their project folder for security vulnerabilities. The API accepts a path to the source code and scan configuration parameters, then performs security checks and returns the results.

## Prerequisites

- [Go](https://golang.org/dl/) (version 1.20 or higher)
- `gosec` installed globally and available on your `PATH`

### Installing `gosec` Globally

To install `gosec` globally, use the following command:

```sh
go install github.com/securego/gosec/v2/cmd/gosec@latest
````

### Running the project

Go into the folder where the project was cloned and run the following command. It will run on localhost:8080

```sh
go run main.go
```

### API - [POST] /scan

Request payload

```json
{
  "path": "<folder_path_to_project>",
  "codeType": "golang | web", // [string] which code type option should the application scan
  "checks": ["XSS", "SQLI"] // [array of string] array of security checks
}
```

Response payload

```json
{
  {
    "issues": [
        {
            "file": "<filename>", // file that occurred the error
            "details": "Blocklisted import crypto/md5: weak cryptographic primitive", // details about the security issue
            "line": "4", // which line of the file occured the error was found
            "column": "2" // which column of the file occured the error was found
        }
    ],
    "error": "" // message about a possible error. Ex: folder provided not exists
}
}
```
