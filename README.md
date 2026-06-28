# subdomain-finder

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
[![CI](https://github.com/k31337/subdomain-finder/actions/workflows/ci.yml/badge.svg)](https://github.com/k31337/subdomain-finder/actions/workflows/ci.yml)

A Python CLI tool to discover subdomains of a target domain via concurrent DNS resolution, with optional HTTP verification, rate limiting, and multi-resolver support.

## Features

- Concurrent DNS brute-forcing using a configurable thread pool, resolving A, AAAA, and CNAME records
- Optional HTTP/HTTPS liveness check on discovered hosts
- Per-lookup retries with exponential backoff
- Global rate limiting shared across all threads
- Round-robin DNS resolution across multiple nameservers
- Wildcard DNS detection, automatically filtering out false positives
- Recursive brute-forcing of discovered subdomains (e.g. `sub.sub.example.com`)
- Passive subdomain discovery via crt.sh certificate transparency logs
- Export results as `txt`, `json`, or `csv`
- JSON Lines streaming to stdout for piping into other tools

## Installation

```bash
git clone https://github.com/k31337/subdomain-finder.git
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
| `--recursive` | Recursively brute-force subdomains of found subdomains, up to DEPTH levels | `1` (no recursion) |
| `--no-wildcard-check` | Skip wildcard DNS detection | off (check enabled) |
| `--crt-sh` | Augment the wordlist with subdomains found via crt.sh certificate transparency logs | off |
| `-q, --quiet` | Suppress progress bar and per-host/info messages; only fatal errors and the final summary | off |
| `--jsonl` | Stream each found subdomain to stdout as a JSON object per line; progress/info messages move to stderr | off |
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

Combine brute-force with passive subdomains found via crt.sh:

```bash
python subdomain_finder.py example.com --crt-sh -o results.json
```

Discover subdomains nested two levels deep (e.g. `dev.api.example.com`):

```bash
python subdomain_finder.py example.com --recursive 2
```

Run quietly for scripting/CI, only saving results to a file:

```bash
python subdomain_finder.py example.com --quiet -o results.json
```

Pipe discovered subdomains straight into another tool as they're found:

```bash
python subdomain_finder.py example.com --jsonl | jq -r '.host'
```

## Wordlists

A default wordlist is provided at [`wordlists/subdomains.txt`](wordlists/subdomains.txt). Swap it for a larger one (e.g. SecLists) with `-w`.

## Testing

```bash
pip install -r requirements-dev.txt
pytest
```

## Disclaimer

Only use this tool on domains you are authorized to test. Unauthorized scanning of systems you do not own or have explicit permission to test may be illegal.

## License

[MIT](LICENSE)
