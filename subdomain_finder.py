#!/usr/bin/env python3
import argparse
import csv
import json
import os
import random
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutureTimeoutError

import dns.resolver
import requests
from colorama import Fore, Style, init as colorama_init
from tqdm import tqdm

colorama_init()

USER_AGENT = "Mozilla/5.0 (compatible; subdomain-finder)"


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
            return dns.resolver.Resolver()
        with self._lock:
            ns = self.nameservers[self._index % len(self.nameservers)]
            self._index += 1
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ns]
        return resolver


def resolve(subdomain, domain, retries=2, backoff=0.5, resolver=None):
    host = f"{subdomain}.{domain}"
    resolver = resolver or dns.resolver.Resolver()
    last_error = None
    for attempt in range(retries + 1):
        try:
            entry = {"host": host}

            try:
                answer = resolver.resolve(host, "CNAME")
                entry["cname"] = answer[0].target.to_text().rstrip(".")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass

            ips = []
            for record_type in ("A", "AAAA"):
                try:
                    answer = resolver.resolve(host, record_type)
                    ips.extend(a.to_text() for a in answer)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    continue

            if not ips and "cname" not in entry:
                return None
            if ips:
                entry["ip"] = ips[0]
                if len(ips) > 1:
                    entry["all_ips"] = ips
            return entry
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


def fetch_crtsh_subdomains(domain, timeout=10):
    """Queries crt.sh certificate transparency logs for known subdomains.

    Returns a set of subdomain labels (relative to `domain`) found in
    certificate SANs, or an empty set if the query fails.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
        r.raise_for_status()
        entries = r.json()
    except (requests.RequestException, ValueError):
        return set()

    suffix = f".{domain}"
    labels = set()
    for entry in entries:
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(suffix):
                label = name[: -len(suffix)]
                if label:
                    labels.add(label)
    return labels


def check_http(host, timeout=5, retries=1, backoff=0.5):
    for scheme in ("https://", "http://"):
        url = scheme + host
        for attempt in range(retries + 1):
            try:
                r = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": USER_AGENT})
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
                     skip_wildcard_check=False, quiet=False):
    found = []
    errors = []
    limiter = RateLimiter(rate_limit)
    pool = ResolverPool(nameservers)

    wildcard_ips = set()
    if not skip_wildcard_check:
        wildcard_ips = detect_wildcard(domain, resolver=pool.next_resolver(), retries=retries)
        if wildcard_ips and not quiet:
            print(
                Fore.YELLOW + f"[!] Wildcard DNS detected for *.{domain} -> {', '.join(sorted(wildcard_ips))} "
                "(matching results will be excluded)" + Style.RESET_ALL,
                file=sys.stderr,
            )

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {}
        for word in wordlist:
            limiter.wait()
            resolver = pool.next_resolver()
            futures[executor.submit(resolve, word, domain, retries=retries, resolver=resolver)] = word

        progress = tqdm(as_completed(futures), total=len(futures), desc="Resolving", unit="host", disable=quiet)
        for future in progress:
            try:
                result = future.result(timeout=timeout)
            except FutureTimeoutError:
                result = {"host": f"{futures[future]}.{domain}", "error": "lookup timed out"}

            if not result:
                continue

            if "error" in result:
                errors.append(result)
                if not quiet:
                    tqdm.write(Fore.RED + f"[!] {result['host']} -> {result['error']}" + Style.RESET_ALL, file=sys.stderr)
                continue

            host = result["host"]
            ip = result.get("ip")
            if ip is not None and ip in wildcard_ips:
                continue
            entry = {"host": host}
            if ip is not None:
                entry["ip"] = ip
            if "cname" in result:
                entry["cname"] = result["cname"]
            if check_http_status:
                http_result = check_http(host, timeout=timeout)
                if http_result:
                    entry["url"], entry["status"] = http_result
            found.append(entry)
            if not quiet:
                target = ip if ip is not None else entry.get("cname", "?")
                cname_part = f" (CNAME {entry['cname']})" if "cname" in entry and ip is not None else ""
                status_part = f" ({entry['url']} [{entry['status']}])" if "url" in entry else ""
                tqdm.write(Fore.GREEN + f"[+] {host} -> {target}" + Style.RESET_ALL + cname_part + status_part)

    if errors and not quiet:
        print(Fore.RED + f"[!] {len(errors)} lookups failed after retries" + Style.RESET_ALL, file=sys.stderr)

    return found


def find_subdomains_recursive(domain, wordlist, max_depth=1, threads=50, check_http_status=False,
                               timeout=3, retries=2, rate_limit=0, nameservers=None,
                               skip_wildcard_check=False, quiet=False):
    """Repeatedly applies find_subdomains to discovered hosts, up to max_depth levels deep."""
    all_results = []
    seen_hosts = set()
    current_domains = [domain]

    for depth in range(1, max_depth + 1):
        level_results = []
        for current_domain in current_domains:
            if depth > 1 and not quiet:
                print(Fore.CYAN + f"[*] Recursing into {current_domain} (depth {depth})..." + Style.RESET_ALL, file=sys.stderr)
            results = find_subdomains(
                current_domain, wordlist, threads=threads, check_http_status=check_http_status,
                timeout=timeout, retries=retries, rate_limit=rate_limit,
                nameservers=nameservers, skip_wildcard_check=skip_wildcard_check, quiet=quiet
            )
            for entry in results:
                if entry["host"] not in seen_hosts:
                    seen_hosts.add(entry["host"])
                    all_results.append(entry)
                    level_results.append(entry)

        if depth == max_depth:
            break
        current_domains = [entry["host"] for entry in level_results]
        if not current_domains:
            break

    return all_results


def save_results(results, path, fmt=None):
    if fmt is None:
        ext = os.path.splitext(path)[1].lower()
        fmt = {"json": "json", "csv": "csv"}.get(ext.lstrip("."), "txt")

    if fmt == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    elif fmt == "csv":
        fieldnames = ["host", "ip", "cname", "url", "status"]
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for entry in results:
                writer.writerow({field: entry.get(field, "") for field in fieldnames})
    else:
        with open(path, "w", encoding="utf-8") as f:
            for entry in results:
                line = f"{entry['host']} -> {entry.get('ip', entry.get('cname', '?'))}"
                if "cname" in entry and "ip" in entry:
                    line += f" (CNAME {entry['cname']})"
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
        "--recursive", type=int, default=1, metavar="DEPTH",
        help="Recursively brute-force subdomains of found subdomains, up to DEPTH levels "
             "(e.g. sub.sub.example.com at depth 2) (default: 1, i.e. no recursion)"
    )
    parser.add_argument(
        "--crt-sh", action="store_true",
        help="Augment the wordlist with subdomains found via crt.sh certificate transparency logs"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress progress bar and per-host/info messages; only print fatal errors and the final summary"
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

    if args.crt_sh:
        if not args.quiet:
            print(Fore.CYAN + f"[*] Querying crt.sh for {args.domain}..." + Style.RESET_ALL)
        crtsh_labels = fetch_crtsh_subdomains(args.domain)
        new_labels = crtsh_labels - set(wordlist)
        if not args.quiet:
            print(Fore.CYAN + f"[*] crt.sh returned {len(crtsh_labels)} subdomains ({len(new_labels)} new)" + Style.RESET_ALL)
        wordlist = wordlist + sorted(new_labels)

    if not args.quiet:
        print(Fore.CYAN + f"[*] Searching for subdomains of {args.domain} ({len(wordlist)} candidates)..." + Style.RESET_ALL)
    nameservers = [ns.strip() for ns in args.resolvers.split(",") if ns.strip()] if args.resolvers else None
    results = find_subdomains_recursive(
        args.domain, wordlist, max_depth=max(1, args.recursive), threads=args.threads,
        check_http_status=args.http, timeout=args.timeout, retries=args.retries,
        rate_limit=args.rate_limit, nameservers=nameservers, skip_wildcard_check=args.no_wildcard_check,
        quiet=args.quiet
    )

    if not args.quiet:
        print(Style.BRIGHT + f"\n[*] Total found: {len(results)}" + Style.RESET_ALL)

    if args.output:
        save_results(results, args.output, fmt=args.format)
        if not args.quiet:
            print(Fore.CYAN + f"[*] Results saved to {args.output}" + Style.RESET_ALL)


if __name__ == "__main__":
    main()