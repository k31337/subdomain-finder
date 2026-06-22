# subdomain-finder

A Python tool to discover subdomains of a target domain via concurrent DNS resolution, with optional HTTP verification.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python subdomain_finder.py example.com
```

Options:

- `-w, --wordlist`: path to the subdomain wordlist (default `wordlists/subdomains.txt`)
- `-t, --threads`: number of concurrent threads (default 50)
- `--http`: check whether the subdomain responds over HTTP/HTTPS
- `--timeout`: timeout in seconds for each DNS/HTTP lookup (default 3)
- `--retries`: number of retries for a lookup before giving up (default 2)
- `--rate-limit`: maximum DNS lookups per second across all threads, 0 = unlimited (default 0)
- `-o, --output`: file to save the results to
- `-f, --format`: output format (`txt`, `json`, `csv`); inferred from the output file extension if not set, defaults to `txt`

Example:

```bash
python subdomain_finder.py example.com -w wordlists/subdomains.txt --http -o results.json
```

## Disclaimer

Only use this tool on domains you are authorized to test.