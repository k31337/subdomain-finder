#!/usr/bin/env python3
import argparse
import csv
import json
import os
import random
import socket
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutureTimeoutError

import dns.resolver
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


class ResolverPool:
    """Round-robins DNS lookups across a set of nameservers."""

    def __init__(self, nameservers=None):
        self.nameservers = nameservers
        self._lock = threading.Lock()
        self._index = 0

    def next_resolver(self):
        if not self.nameservers:
            return None
        with self._lock:
            ns = self.nameservers[self._index % len(self.nameservers)]
            self._index += 1
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ns]
        return resolver


def resolve(subdomain, domain, retries=2, backoff=0.5, resolver=None):
    host = f"{subdomain}.{domain}"
    last_error = None
    for attempt in range(retries + 1):
        try:
            if resolver is not None:
                answer = resolver.resolve(host, "A")
                ip = answer[0].to_text()
            else:
                ip = socket.gethostbyname(host)
            return {"host": host, "ip": ip}
        except (socket.gaierror, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except (OSError, dns.exception.DNSException) as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(backoff * (2 ** attempt))
    return {"host": host, "error": str(last_error)}


def detect_wildcard(domain, resolver=None, retries=1, samples=2):
    """Probes random non-existent subdomains to detect wildcard DNS.

    Returns the set of IPs a wildcard record resolves to, or an empty
    set if no wildcard is configured.
    """
    ips = set()
    for _ in range(samples):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        result = resolve(label, domain, retries=retries, resolver=resolver)
        if result and "ip" in result:
            ips.add(result["ip"])
    return ips


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
                     timeout=3, retries=2, rate_limit=0, nameservers=None,
                     skip_wildcard_check=False):
    found = []
    errors = []
    limiter = RateLimiter(rate_limit)
    pool = ResolverPool(nameservers)

    wildcard_ips = set()
    if not skip_wildcard_check:
        wildcard_ips = detect_wildcard(domain, resolver=pool.next_resolver(), retries=retries)
        if wildcard_ips:
            print(
                f"[!] Wildcard DNS detected for *.{domain} -> {', '.join(sorted(wildcard_ips))} "
                "(matching results will be excluded)",
                file=sys.stderr,
            )

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {}
        for word in wordlist:
            limiter.wait()
            resolver = pool.next_resolver()
            futures[executor.submit(resolve, word, domain, retries=retries, resolver=resolver)] = word

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
            if ip in wildcard_ips:
                continue
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
        "--no-wildcard-check", action="store_true",
        help="Skip wildcard DNS detection (by default, results matching a wildcard IP are excluded)"
    )
    parser.add_argument(
        "--resolvers",
        help="Comma-separated list of DNS resolver IPs to round-robin lookups across "
             "(default: system resolver), e.g. 8.8.8.8,1.1.1.1"
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
    nameservers = [ns.strip() for ns in args.resolvers.split(",") if ns.strip()] if args.resolvers else None
    results = find_subdomains(
        args.domain, wordlist, threads=args.threads, check_http_status=args.http,
        timeout=args.timeout, retries=args.retries, rate_limit=args.rate_limit,
        nameservers=nameservers, skip_wildcard_check=args.no_wildcard_check
    )

    print(f"\n[*] Total found: {len(results)}")

    if args.output:
        save_results(results, args.output, fmt=args.format)
        print(f"[*] Results saved to {args.output}")


if __name__ == "__main__":
    main()