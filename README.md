# subdomain-finder

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-GPL--3.0-green)

A Python CLI tool to discover subdomains of a target domain via concurrent DNS resolution, with optional HTTP verification, rate limiting, and multi-resolver support.

## Features

- Concurrent DNS brute-forcing using a configurable thread pool
- Optional HTTP/HTTPS liveness check on discovered hosts
- Per-lookup retries with exponential backoff
- Global rate limiting shared across all threads
- Round-robin DNS resolution across multiple nameservers
- Export results as `txt`, `json`, or `csv`

## Installation

```bash
git clone https://github.com/<your-username>/subdomain-finder.git
cd subdomain-finder
pip install -r requirements.txt
```

Requires Python 3.8+.

## Usage

```bash
python subdomain_finder.py example.com
```

### Options

| Flag | Description | Default |
| --- | --- | --- |
| `-w, --wordlist` | Path to the subdomain wordlist | `wordlists/subdomains.txt` |
| `-t, --threads` | Number of concurrent threads | `50` |
| `--http` | Check whether the subdomain responds over HTTP/HTTPS | off |
| `--timeout` | Timeout in seconds for each DNS/HTTP lookup | `3` |
| `--retries` | Number of retries for a lookup before giving up | `2` |
| `--rate-limit` | Maximum DNS lookups per second across all threads, `0` = unlimited | `0` |
| `--resolvers` | Comma-separated list of DNS resolver IPs to round-robin lookups across, e.g. `8.8.8.8,1.1.1.1` | system resolver |
| `-o, --output` | File to save the results to | none |
| `-f, --format` | Output format: `txt`, `json`, or `csv` (inferred from `--output` extension if not set) | `txt` |

### Examples

Basic scan with HTTP check, saved to JSON:

```bash
python subdomain_finder.py example.com -w wordlists/subdomains.txt --http -o results.json
```

Spread lookups across multiple DNS resolvers instead of overloading a single one:

```bash
python subdomain_finder.py example.com --resolvers 8.8.8.8,1.1.1.1,9.9.9.9
```

Stay under a target's rate limit:

```bash
python subdomain_finder.py example.com --rate-limit 10 -t 10
```

## Wordlists

A default wordlist is provided at [`wordlists/subdomains.txt`](wordlists/subdomains.txt). Swap it for a larger one (e.g. SecLists) with `-w`.

## Disclaimer

Only use this tool on domains you are authorized to test. Unauthorized scanning of systems you do not own or have explicit permission to test may be illegal.

## License

[GPL-3.0](LICENSE)
