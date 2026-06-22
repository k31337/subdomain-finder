#!/usr/bin/env python3
import argparse
import csv
import json
import os
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutureTimeoutError

import requests
from tqdm import tqdm


def load_wordlist(path):
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


class RateLimiter:
    """Caps how many operations can start per second, shared across threads."""

    def __init__(self, rate):
        self.min_interval = 1.0 / rate if rate and rate > 0 else 0
        self._lock = threading.Lock()
        self._next_slot = time.monotonic()

    def wait(self):
        if not self.min_interval:
            return
        with self._lock:
            now = time.monotonic()
            start = max(now, self._next_slot)
            self._next_slot = start + self.min_interval
            delay = start - now
        if delay > 0:
            time.sleep(delay)


def resolve(subdomain, domain, retries=2, backoff=0.5):
    host = f"{subdomain}.{domain}"
    last_error = None
    for attempt in range(retries + 1):
        try:
            ip = socket.gethostbyname(host)
            return {"host": host, "ip": ip}
        except socket.gaierror:
            return None
        except OSError as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(backoff * (2 ** attempt))
    return {"host": host, "error": str(last_error)}


def check_http(host, timeout=5, retries=1, backoff=0.5):
    for scheme in ("https://", "http://"):
        url = scheme + host
        for attempt in range(retries + 1):
            try:
                r = requests.get(url, timeout=timeout, allow_redirects=True)
                return url, r.status_code
            except requests.Timeout:
                if attempt < retries:
                    time.sleep(backoff * (2 ** attempt))
                    continue
                break
            except requests.RequestException:
                break
    return None


def find_subdomains(domain, wordlist, threads=50, check_http_status=False,
                     timeout=3, retries=2, rate_limit=0):
    found = []
    errors = []
    limiter = RateLimiter(rate_limit)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {}
        for word in wordlist:
            limiter.wait()
            futures[executor.submit(resolve, word, domain, retries=retries)] = word

        for future in tqdm(as_completed(futures), total=len(futures), desc="Resolving", unit="host"):
            try:
                result = future.result(timeout=timeout)
            except FutureTimeoutError:
                result = {"host": f"{futures[future]}.{domain}", "error": "lookup timed out"}

            if not result:
                continue

            if "error" in result:
                errors.append(result)
                tqdm.write(f"[!] {result['host']} -> {result['error']}", file=sys.stderr)
                continue

            host, ip = result["host"], result["ip"]
            entry = {"host": host, "ip": ip}
            if check_http_status:
                http_result = check_http(host, timeout=timeout)
                if http_result:
                    entry["url"], entry["status"] = http_result
            found.append(entry)
            tqdm.write(f"[+] {host} -> {ip}")

    if errors:
        print(f"[!] {len(errors)} lookups failed after retries", file=sys.stderr)

    return found


def save_results(results, path, fmt=None):
    if fmt is None:
        ext = os.path.splitext(path)[1].lower()
        fmt = {"json": "json", "csv": "csv"}.get(ext.lstrip("."), "txt")

    if fmt == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    elif fmt == "csv":
        fieldnames = ["host", "ip", "url", "status"]
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for entry in results:
                writer.writerow({field: entry.get(field, "") for field in fieldnames})
    else:
        with open(path, "w", encoding="utf-8") as f:
            for entry in results:
                line = f"{entry['host']} -> {entry['ip']}"
                if "url" in entry:
                    line += f" ({entry['url']} [{entry['status']}])"
                f.write(line + "\n")


def main():
    parser = argparse.ArgumentParser(description="Subdomain finder")
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument(
        "-w", "--wordlist", default="wordlists/subdomains.txt",
        help="Path to the subdomain wordlist"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=50,
        help="Number of concurrent threads"
    )
    parser.add_argument(
        "--http", action="store_true",
        help="Check whether the subdomain responds over HTTP/HTTPS"
    )
    parser.add_argument(
        "--timeout", type=float, default=3,
        help="Timeout in seconds for each DNS/HTTP lookup (default: 3)"
    )
    parser.add_argument(
        "--retries", type=int, default=2,
        help="Number of retries for a lookup before giving up (default: 2)"
    )
    parser.add_argument(
        "--rate-limit", type=float, default=0,
        help="Maximum DNS lookups per second across all threads, 0 = unlimited (default: 0)"
    )
    parser.add_argument(
        "-o", "--output", help="File to save the results to"
    )
    parser.add_argument(
        "-f", "--format", choices=["txt", "json", "csv"],
        help="Output format (default: inferred from the output file extension, falls back to txt)"
    )
    args = parser.parse_args()

    try:
        wordlist = load_wordlist(args.wordlist)
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {args.wordlist}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Searching for subdomains of {args.domain} ({len(wordlist)} candidates)...")
    results = find_subdomains(
        args.domain, wordlist, threads=args.threads, check_http_status=args.http,
        timeout=args.timeout, retries=args.retries, rate_limit=args.rate_limit
    )

    print(f"\n[*] Total found: {len(results)}")

    if args.output:
        save_results(results, args.output, fmt=args.format)
        print(f"[*] Results saved to {args.output}")


if __name__ == "__main__":
    main()