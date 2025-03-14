#!/usr/bin/env python3

import argparse
import concurrent.futures
import json
import logging
import os
import re
import sys
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

import colorama
import requests
import yaml
from colorama import Fore, Style
from requests.exceptions import RequestException, Timeout
from tqdm import tqdm

# Initialize and configure
colorama.init(autoreset=True)
logging.basicConfig(level=logging.INFO, format="%(message)s", handlers=[logging.StreamHandler()])
logger = logging.getLogger("LeakJS")
DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "patterns")
VERSION = "1.1.0"  # Increment version for changes

# --- New Features ---
# 1. Output to file (JSON, CSV, TXT)
# 2. Proxy support
# 3. Custom pattern addition via CLI
# 4. Verbose mode

def print_banner(args, urls):
    if args.silent: return
    print(f"{Fore.BLUE}LeakJS v{VERSION}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}{'=' * 50}{Style.RESET_ALL}")
    print(f"URLs to scan: {len(urls)}")
    print(f"Threads: {args.threads}")
    print(f"Timeout: {args.timeout or DEFAULT_TIMEOUT}s")
    mode = "LinkFinder" if args.linkfinder else "SecretFinder" if args.secretfinder else "Both"
    print(f"Mode: {mode}")
    if args.proxy:
        print(f"Proxy: {args.proxy}")
    print(f"{Fore.BLUE}{'=' * 50}{Style.RESET_ALL}\n")

def parse_args(custom_args=None):
    parser = argparse.ArgumentParser(description="LeakJS - JavaScript secrets and endpoint scanner")
    
    # URL inputs
    url_group = parser.add_argument_group("URL Options")
    url_exclusive = url_group.add_mutually_exclusive_group()
    url_exclusive.add_argument("-u", "--url", help="Single URL to scan")
    url_exclusive.add_argument("-l", "--url-file", help="File containing URLs to scan (one per line)")
    
    # Pattern inputs
    pattern_group = parser.add_argument_group("Pattern Options")
    pattern_group.add_argument("--regex-file", help="Custom regex patterns file (YAML)")
    parser.add_argument("--add-pattern", help="Add a custom regex pattern directly from the command line")
    pattern_group.add_argument("--secretfinder", action="store_true", help="Use SecretFinder patterns")
    pattern_group.add_argument("--linkfinder", action="store_true", help="Use LinkFinder patterns")
    
    # Request options
    request_group = parser.add_argument_group("Request Options")
    request_group.add_argument("-t", "--threads", type=int, default=5, help="Number of threads")
    request_group.add_argument("--timeout", type=int, help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    request_group.add_argument("--user-agent", help="Custom User-Agent")
    request_group.add_argument("--headers", help="Additional headers as JSON string")
    request_group.add_argument("--insecure", action="store_true", help="Disable SSL verification")
    request_group.add_argument("--follow-redirects", action="store_true", help="Follow redirects")
    request_group.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("--summary", action="store_true", help="Show summary at the end")
    output_group.add_argument("--silent", action="store_true", help="Silent mode, no output except findings")
    output_group.add_argument("--no-color", action="store_true", help="Disable colored output")
    output_group.add_argument("--progress", action="store_true", help="Show progress bar")
    output_group.add_argument("--output", help="Output file (JSON, CSV, TXT)")
    output_group.add_argument("--output-format", choices=['json', 'csv', 'txt'], default='json', help="Output format (json, csv, txt)")
    output_group.add_argument("-v", "--verbose", action="store_true", help="Increase verbosity (show more information)")

    # Misc options
    misc_group = parser.add_argument_group("Miscellaneous Options")
    misc_group.add_argument("--exit-on-error", action="store_true", help="Exit on error")
    misc_group.add_argument("--health-check", action="store_true", help="Perform health check")
    misc_group.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    return parser.parse_args(custom_args) if custom_args is not None else parser.parse_args()

class LeakJS:
    def __init__(self, args):
        self.args = args
        self.urls = []
        self.patterns = []
        self.results = []
        self.loaded_pattern_files = set()  # Track already loaded pattern files
        if self.args.no_color: colorama.deinit()
        self.session = self._create_session()
        self.setup_patterns()
        if self.args.debug:
            logger.setLevel(logging.DEBUG)
        if self.args.verbose:
            logger.setLevel(logging.INFO) # setting level to info to show more details

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        headers = {
            "User-Agent": self.args.user_agent or DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }
        if self.args.headers:
            try:
                headers.update(json.loads(self.args.headers))
            except json.JSONDecodeError as e:
                logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} Failed to parse custom headers JSON: {str(e)}")
        session.headers.update(headers)
        if self.args.proxy:
            session.proxies = {'http': self.args.proxy, 'https': self.args.proxy}
        return session
    
    def setup_patterns(self):
        patterns_to_load = []
        if self.args.regex_file:
            patterns_to_load.append((self.args.regex_file, "custom"))
        if self.args.linkfinder or (not self.args.regex_file and not self.args.secretfinder and not self.args.add_pattern):
            patterns_to_load.append((os.path.join(DEFAULT_PATH, "linkfinder.yaml"), "linkfinder"))
        if self.args.secretfinder or (not self.args.regex_file and not self.args.linkfinder and not self.args.add_pattern):
            patterns_to_load.append((os.path.join(DEFAULT_PATH, "secrets.yaml"), "secrets"))

        if self.args.add_pattern:
            self._add_pattern_from_cli(self.args.add_pattern)
        
        for pattern_file, pattern_type in patterns_to_load:
            if pattern_file in self.loaded_pattern_files:  # Skip if already loaded
                continue
            self._load_pattern_file(pattern_file, pattern_type)
            self.loaded_pattern_files.add(pattern_file)  # Mark as loaded
    
    def _add_pattern_from_cli(self, pattern_string: str):
        try:
            pattern_data = {'name': 'cli_pattern', 'regex': pattern_string, 'confidence': 'high'}
            re.compile(pattern_data['regex'])  # Validate regex
            pattern_data['type'] = 'custom'
            self.patterns.append(pattern_data)
            logger.info(f"Added custom pattern from CLI: {pattern_string}")
        except re.error as e:
            logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} Invalid regex pattern: {str(e)}")

    def _load_pattern_file(self, pattern_file: str, pattern_type: str):
        try:
            if not os.path.exists(pattern_file):
                raise FileNotFoundError(f"Pattern file not found: {pattern_file}")
            with open(pattern_file, "r", encoding="utf-8") as f:
                patterns_data = yaml.safe_load(f)
                if not patterns_data:
                    logger.info(f"No patterns found in {pattern_file}")
                    return
                count = 0
                for pattern in patterns_data:
                    if 'pattern' in pattern:
                        try:
                            pattern_info = pattern['pattern']
                            re.compile(pattern_info['regex'])  # Validate regex
                            pattern_info['type'] = pattern_type
                            self.patterns.append(pattern_info)
                            count += 1
                        except re.error as e:
                            logger.debug(f"Skipping invalid pattern: {pattern.get('name', 'Unnamed')} - {e}")  # More specific logging
                if not self.args.health_check:  # Avoid duplicate messages during health check
                    logger.info(f"Loaded {count} patterns from {pattern_file}")
        except (yaml.YAMLError, FileNotFoundError) as e:
            logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} Error loading pattern file {pattern_file}: {str(e)}")
            if self.args.exit_on_error: sys.exit(1)
    
    def load_urls(self):
        try:
            if self.args.url:
                self.urls.append(self.args.url)
            elif self.args.url_file:
                if not os.path.exists(self.args.url_file):
                    raise FileNotFoundError(f"URL file not found: {self.args.url_file}")
                with open(self.args.url_file, "r", encoding="utf-8") as f:
                    self.urls = [line.strip() for line in f if line.strip()]
            self.urls = [url if url.startswith(('http://', 'https://')) else f'https://{url}' for url in self.urls]
            if not self.urls:
                logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} No URLs provided. Use -u/--url or -l/--url-file.")
                sys.exit(1)
        except Exception as e:
            logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} Error loading URLs: {str(e)}")
            if self.args.exit_on_error: sys.exit(1)
    
    def fetch_url(self, url: str) -> Tuple[str, Optional[str]]:
        try:
            if self.args.verbose:
                print(f"{Fore.WHITE}[INFO]{Style.RESET_ALL} Fetching {url}")
            response = self.session.get(
                url,
                timeout=self.args.timeout or DEFAULT_TIMEOUT,
                verify=not self.args.insecure,
                allow_redirects=self.args.follow_redirects
            )
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            return url, response.text
        except requests.exceptions.HTTPError as e:
            logger.warning(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} HTTP Error {e.response.status_code} for {url}")
            return url, None
        except requests.exceptions.RequestException as e:
            logger.debug(f"Error fetching {url}: {str(e)}")
            return url, None
    
    def scan_content(self, url: str, content: str, scan_type: str) -> List[Dict]:
        url_results = []
        for pattern in self.patterns:
            if pattern['type'] != scan_type: continue
            try:
                regex = re.compile(pattern['regex'], re.MULTILINE | re.DOTALL)
                matches = regex.findall(content)
                for match in matches:
                    finding = match[0] if isinstance(match, tuple) else match
                    if finding:
                        url_results.append({
                            "confidence": pattern.get("confidence", "medium"),
                            "url": url,
                            "finding": finding,
                            "pattern_name": pattern.get("name", "unnamed")
                        })
            except Exception as e:
                logger.error(f"Error processing pattern {pattern.get('name', 'Unnamed')}: {e}")
        return url_results
    
    def process_urls(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            future_to_url = {executor.submit(self.fetch_url, url): url for url in self.urls}
            disable_progress = self.args.silent or not self.args.progress
            with tqdm(total=len(self.urls), desc=f"{Fore.BLUE}[INF]{Style.RESET_ALL} Processing URLs", disable=disable_progress) as progress_bar:
                for future in concurrent.futures.as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        url, content = future.result()
                        if content:
                            if self.args.linkfinder: scan_type = "linkfinder"
                            elif self.args.secretfinder: scan_type = "secrets"
                            else: scan_type = "secrets" if url.endswith('.js') else "linkfinder"
                            matches = self.scan_content(url, content, scan_type)
                            if matches:
                                self.results.extend(matches)
                                self.print_results(url, matches)
                    except Exception as e:
                        logger.error(f"Error processing {url}: {e}")
                    finally:
                        progress_bar.update(1)

    def print_results(self, url: str, findings: List[Dict]):
        if not self.args.silent:
            color_map = {"high": Fore.RED, "medium": Fore.YELLOW, "low": Fore.GREEN}
            print(f"{Fore.GREEN}[FOUND]{Style.RESET_ALL} {url}")
            for finding in findings:
                confidence = finding['confidence'].lower()
                color = color_map.get(confidence, "")
                print(f"  [{color}{finding['pattern_name']}{Style.RESET_ALL}] {finding['finding']}")

    def print_summary(self, start_time: float):
        if self.args.silent: return
        elapsed_time = time.time() - start_time
        print(f"\n{Fore.BLUE}[INF]{Style.RESET_ALL} Summary:")
        print(f"Total URLs processed: {len(self.urls)}")
        print(f"Findings: {len(self.results)}")
        print(f"Time taken: {elapsed_time:.2f}s")
        
        if not self.results: return
        
        pattern_counts, confidence_counts = {}, {"high": 0, "medium": 0, "low": 0}
        for result in self.results:
            pattern_name = result['pattern_name']
            pattern_counts[pattern_name] = pattern_counts.get(pattern_name, 0) + 1
            confidence = result['confidence'].lower()
            if confidence in confidence_counts:
                confidence_counts[confidence] += 1
        
        print(f"\n{Fore.BLUE}[INF]{Style.RESET_ALL} Findings by pattern:")
        for pattern, count in sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {pattern}: {count}")
        
        print(f"\n{Fore.BLUE}[INF]{Style.RESET_ALL} Findings by confidence:")
        colors = {"high": Fore.RED, "medium": Fore.YELLOW, "low": Fore.GREEN}
        for confidence, count in confidence_counts.items():
            print(f"  {colors.get(confidence, '')}{confidence.capitalize()}{Style.RESET_ALL}: {count}")

    def output_results(self):
        if not self.args.output:
            return

        output_data = self.results

        try:
            if self.args.output_format == 'json':
                with open(self.args.output, 'w') as f:
                    json.dump(output_data, f, indent=4)
                logger.info(f"{Fore.GREEN}[INF]{Style.RESET_ALL} Results saved to {self.args.output} in JSON format")
            elif self.args.output_format == 'csv':
                import csv
                with open(self.args.output, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=output_data[0].keys())
                    writer.writeheader()
                    writer.writerows(output_data)
                logger.info(f"{Fore.GREEN}[INF]{Style.RESET_ALL} Results saved to {self.args.output} in CSV format")
            elif self.args.output_format == 'txt':
                with open(self.args.output, 'w') as f:
                    for result in output_data:
                        f.write(f"{result['url']} - {result['pattern_name']} - {result['finding']}\n")
                logger.info(f"{Fore.GREEN}[INF]{Style.RESET_ALL} Results saved to {self.args.output} in TXT format")
        except Exception as e:
            logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} Error writing to output file: {str(e)}")

    def run(self):
        try:
            if not self.patterns:
                logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} No valid patterns loaded. Exiting.")
                return
            self.load_urls()
            print_banner(self.args, self.urls)
            logger.debug(f"Loaded {len(self.urls)} URLs, {len(self.patterns)} patterns")
            start_time = time.time()
            self.process_urls()
            if self.args.summary:
                self.print_summary(start_time)
            self.output_results()

        except KeyboardInterrupt:
            logger.error(f"\n{Fore.RED}[ERR]{Style.RESET_ALL} Interrupted by user. Exiting...")
            sys.exit(1)
        except Exception as e:
            logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} Error during run: {str(e)}")
            if self.args.debug:
                import traceback
                traceback.print_exc()
            if self.args.exit_on_error: sys.exit(1)

    def health_check(self):
        self.args.silent = True  # Silence normal output during health check
        print(f"{Fore.BLUE}[INF]{Style.RESET_ALL} Running health check...")
        test_flags = [
            ("--url", ["https://example.com"]),
            ("--regex-file", ["test_patterns.yaml"]),
            ("--secretfinder", []),
            ("--linkfinder", []),
            ("--threads", ["2"]),
            ("--timeout", ["5"]),
            ("--user-agent", ["TestAgent"]),
            ("--headers", ['{"Test-Header": "Value"}']),
            ("--insecure", []),
            ("--follow-redirects", []),
            ("--summary", []),
            ("--silent", []),
            ("--no-color", []),
            ("--progress", []),
            ("--exit-on-error", []),
            ("--proxy", ["http://127.0.0.1:8080"]),
            ("--add-pattern", ["test_pattern"])
        ]

        results = []
        for flag, value in test_flags:
            try:
                # Create a temporary test configuration with just this flag
                test_args = [flag] + value
                args = parse_args(test_args)
                
                # Avoid actual execution by creating a minimal test instance
                test_instance = LeakJS(args)
                results.append((flag, "OK"))
            except Exception as e:
                results.append((flag, "ERR"))
                logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} Error testing flag {flag}: {str(e)}")

        # Print test results
        print(f"\n{Fore.BLUE}[INF]{Style.RESET_ALL} Health Check Results:")
        for flag, status in results:
            status_marker = f"{Fore.GREEN}✓{Style.RESET_ALL}" if status == "OK" else f"{Fore.RED}✗{Style.RESET_ALL}"
            print(f"  {status_marker} {flag}")
        
        # Overall status
        if all(status == "OK" for _, status in results):
            print(f"\n{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} All checks passed!")
        else:
            print(f"\n{Fore.RED}[WARNING]{Style.RESET_ALL} Some checks failed.")

def main():
    try:
        args = parse_args()
        if args.health_check:
            scanner = LeakJS(args)
            scanner.health_check()
        else:
            scanner = LeakJS(args)
            scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[ERR]{Style.RESET_ALL} Interrupted by user. Exiting...")
        sys.exit(1)
    except SystemExit:
        raise
    except Exception as e:
        print(f"{Fore.RED}[CRITICAL ERROR]{Style.RESET_ALL} {str(e)}")
        print("Try running with --debug for more information.")
        sys.exit(1)

if __name__ == "__main__":
    main()
