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
- `-o, --output`: file to save the results to

Example:

```bash
python subdomain_finder.py example.com -w wordlists/subdomains.txt --http -o results.txt
```

## Disclaimer

Only use this tool on domains you are authorized to test.