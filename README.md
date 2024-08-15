# leakh

leakh is a multi-threaded command line utility and helper tool to handle password leakage files.

It uses regular expressions to extract passwords from `.txt` or `.csv` files. Each file, inside the given `directory`, is read out by a seperate thread that returns the list of all passwords and the count how often it appeard inside the list. After extracting all passwords, the resulting list is sorted accordingly to the count and douplicates are removed. It will write each password with its count in a seperate `$(output).stats.csv` file.

## Usage

```bash
Extracts passwords from files

Usage: leakh [OPTIONS] --config <FILE> --directory <DIR> --output <FILE>

Options:
  -c, --config <FILE>    Specifies the config file
  -d, --directory <DIR>  Specifies the directory to scan for files
  -o, --output <FILE>    Specifies the output file location
  -v, --verbose          Enables verbose output
  -h, --help             Print help
  -V, --version          Print version
```

## Configuration

leakh uses a configuration file that follows the `.toml` syntax.

```toml
# Default configuration for all files
[default]
# Regex pattern to extract password (e.g., password is after the second ":")
pattern = "^[^:]+:(\\S[^\n]*)"
# Minimum length for passwords to be considered valid
min_length = 6
# List of unwanted strings to filter out using regular expressions
unwanted_strings = [
    "imap\\.[^\\s]+",
    "smtp\\.[^\\s]+",
    "NULL",
    "^#file_links.*",
    "^lUCKY&quot;=&quot;=STEVEN.*"
]

# Optional specific configurations for individual files
[files]

# Custom configuration for "special_file.txt"
[files."special_file.txt"]
pattern = "\\|\\s*(\\S+)"
unwanted_strings = ["domain\\.com", "test\\.com"]
min_length = 8

```
