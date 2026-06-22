#!/usr/bin/env python3
import argparse
import csv
import json
import os
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


def load_wordlist(path):
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def resolve(subdomain, domain):
    host = f"{subdomain}.{domain}"
    try:
        ip = socket.gethostbyname(host)
        return host, ip
    except socket.gaierror:
        return None


def check_http(host, timeout=5):
    for scheme in ("https://", "http://"):
        url = scheme + host
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True)
            return url, r.status_code
        except requests.RequestException:
            continue
    return None


def find_subdomains(domain, wordlist, threads=50, check_http_status=False):
    found = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(resolve, word, domain): word for word in wordlist}
        for future in as_completed(futures):
            result = future.result()
            if result:
                host, ip = result
                entry = {"host": host, "ip": ip}
                if check_http_status:
                    http_result = check_http(host)
                    if http_result:
                        entry["url"], entry["status"] = http_result
                found.append(entry)
                print(f"[+] {host} -> {ip}")
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
    results = find_subdomains(args.domain, wordlist, threads=args.threads, check_http_status=args.http)

    print(f"\n[*] Total found: {len(results)}")

    if args.output:
        save_results(results, args.output, fmt=args.format)
        print(f"[*] Results saved to {args.output}")


if __name__ == "__main__":
    main()