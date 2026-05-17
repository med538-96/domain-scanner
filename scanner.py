#!/usr/bin/env python3
"""
Domain Scanner

Basic domain reconnaissance tool that:
- Resolves DNS A/AAAA records
- Checks HTTP(S) status and extracts page title
- Retrieves SSL certificate expiry
- Performs a basic whois lookup
- Tests a few common ports

Usage:
    python scanner.py --input domains.txt --output report.json --concurrency 10

"""
import argparse
import concurrent.futures
import json
import logging
import socket
import ssl
import sys
from datetime import datetime
from typing import Dict, List, Optional

import requests
import dns.resolver
import whois
import tldextract

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

COMMON_PORTS = [80, 443, 22]


def resolve_dns(domain: str) -> Dict[str, List[str]]:
    result = {"A": [], "AAAA": []}
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=5)
        result["A"] = [r.to_text() for r in answers]
    except Exception:
        pass
    try:
        answers = dns.resolver.resolve(domain, "AAAA", lifetime=5)
        result["AAAA"] = [r.to_text() for r in answers]
    except Exception:
        pass
    return result


def get_ssl_expiry(domain: str, timeout: float = 5.0) -> Optional[str]:
    try:
        ctx = ssl.create_default_context()
        # Set up SNI
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                if not_after:
                    # Example format: 'Jun 20 12:00:00 2024 GMT'
                    dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    return dt.isoformat()
    except Exception as e:
        logger.debug("SSL check failed for %s: %s", domain, e)
    return None


def check_http(domain: str, timeout: float = 7.0) -> Dict[str, Optional[str]]:
    result = {"url": None, "status_code": None, "title": None}
    # prefer https
    for scheme in ("https://", "http://"):
        url = f"{scheme}{domain}"
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True)
            result["url"] = resp.url
            result["status_code"] = resp.status_code
            # try to extract <title>
            if resp.text:
                start = resp.text.find("<title")
                if start != -1:
                    # find closing > then </title>
                    start = resp.text.find('>', start)
                    if start != -1:
                        end = resp.text.find("</title>", start)
                        if end != -1:
                            result["title"] = resp.text[start+1:end].strip()
            break
        except requests.RequestException as e:
            logger.debug("HTTP check failed for %s (%s): %s", domain, scheme, e)
            continue
    return result


def get_whois(domain: str) -> Dict[str, Optional[str]]:
    try:
        w = whois.whois(domain)
        return {
            "domain_name": str(w.domain_name) if hasattr(w, "domain_name") else None,
            "registrar": w.registrar if hasattr(w, "registrar") else None,
            "creation_date": str(w.creation_date) if hasattr(w, "creation_date") else None,
            "expiration_date": str(w.expiration_date) if hasattr(w, "expiration_date") else None,
        }
    except Exception as e:
        logger.debug("Whois lookup failed for %s: %s", domain, e)
        return {}


def scan_ports(domain: str, ports: List[int], timeout: float = 2.0) -> Dict[int, bool]:
    results = {}
    for port in ports:
        try:
            with socket.create_connection((domain, port), timeout=timeout):
                results[port] = True
        except Exception:
            results[port] = False
    return results


def scan_domain(domain: str) -> Dict:
    domain_clean = domain.strip()
    logger.info("Scanning %s", domain_clean)
    data = {"domain": domain_clean, "scanned_at": datetime.utcnow().isoformat()}

    # Basic parsing
    parsed = tldextract.extract(domain_clean)
    data["subdomain"] = parsed.subdomain
    data["domain_root"] = parsed.domain
    data["suffix"] = parsed.suffix

    data["dns"] = resolve_dns(domain_clean)
    data["http"] = check_http(domain_clean)
    data["ssl_expiry"] = get_ssl_expiry(domain_clean)
    data["ports"] = scan_ports(domain_clean, COMMON_PORTS)
    # whois can be slow and rate-limited
    try:
        data["whois"] = get_whois(domain_clean)
    except Exception:
        data["whois"] = {}

    return data


def load_domains(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    return lines


def save_json(path: str, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Domain Scanner")
    parser.add_argument("--input", "-i", required=True, help="Input file with domains (one per line)")
    parser.add_argument("--output", "-o", default="report.json", help="Output JSON file")
    parser.add_argument("--concurrency", "-c", type=int, default=10, help="Number of concurrent workers")

    args = parser.parse_args()

    domains = load_domains(args.input)
    if not domains:
        logger.error("No domains found in input file")
        sys.exit(1)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futures = {ex.submit(scan_domain, d): d for d in domains}
        for fut in concurrent.futures.as_completed(futures):
            d = futures[fut]
            try:
                res = fut.result()
                results.append(res)
            except Exception as e:
                logger.exception("Failed to scan %s: %s", d, e)

    save_json(args.output, results)
    logger.info("Scan complete. Results saved to %s", args.output)


if __name__ == "__main__":
    main()
