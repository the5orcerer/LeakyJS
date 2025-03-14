#!/usr/bin/env python3

import argparse
import concurrent.futures
import csv
import json
import logging
import os
import re
import sys
import time
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse, urljoin

import colorama
import requests
import yaml
from colorama import Fore, Style
from requests.exceptions import RequestException, Timeout
from tqdm import tqdm

# Initialize and configure
colorama.init(autoreset=True)
logging.basicConfig(level=logging.DEBUG if '--debug' in sys.argv else logging.INFO, format="%(message)s", handlers=[logging.StreamHandler()])
logger = logging.getLogger("LeakJS")
DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "patterns")
VERSION = "1.0.0"

def print_banner(args, urls):
    """Prints the banner with basic information."""
    if args.silent: return
    print(f"{Fore.BLUE}LeakJS v{VERSION}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}{'=' * 50}{Style.RESET_ALL}")
    print(f"URLs to scan: {len(urls)}")
    print(f"Threads: {args.threads}")
    print(f"Timeout: {args.timeout or DEFAULT_TIMEOUT}s")
    print(f"Mode: {args.mode}")
    print(f"Output format: {args.format.upper()}")
    if args.output:
        print(f"Output file: {args.output}")
    print(f"{Fore.BLUE}{'=' * 50}{Style.RESET_ALL}\n")

def parse_args(custom_args=None):
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description="LeakJS - JavaScript secrets and endpoint scanner")

    # General Options
    general_group = parser.add_argument_group("General Options")
    general_group.add_argument("-v", "-verbose", action="store_true", help="Enable verbose output")
    general_group.add_argument("-debug", action="store_true", help="Enable debug logging")
    general_group.add_argument("-exit-on-error", action="store_true", help="Exit on error")
    general_group.add_argument("-health-check", action="store_true", help="Perform health check")
    general_group.add_argument("-o", "-output", help="Output file to write results")
    general_group.add_argument("-format", choices=['csv', 'json', 'txt'], default='txt', help="Output format (csv, json, txt)")
    general_group.add_argument("-progress", action="store_true", help="Show progress bar")
    general_group.add_argument("-summary", action="store_true", help="Show detailed summary at the end")
    general_group.add_argument("-silent", action="store_true", help="Silent mode, no output except findings")


    # URL Options
    url_group = parser.add_argument_group("URL Options")
    url_exclusive = url_group.add_mutually_exclusive_group()
    url_exclusive.add_argument("-u", "-url", dest="url", help="Single URL to scan")
    url_exclusive.add_argument("-l", "-url-file", dest="url_file", help="File containing URLs to scan (one per line)")

    # Mode Options
    mode_group = parser.add_argument_group("Mode Options")
    mode_group.add_argument("-mode", choices=['auto', 'lazy', 'anonymous'], default='auto', help="Scanning mode: auto, lazy, anonymous")

    # Pattern Options
    pattern_group = parser.add_argument_group("Pattern Options")
    pattern_exclusive = pattern_group.add_mutually_exclusive_group()
    pattern_exclusive.add_argument("-regex-file", help="Custom regex patterns file (YAML)")
    pattern_exclusive.add_argument("-regex", help="Regex pattern from command line")
    pattern_exclusive.add_argument("-secretfinder", action="store_true", help="Use SecretFinder patterns")
    pattern_exclusive.add_argument("-linkfinder", action="store_true", help="Use LinkFinder patterns")
    pattern_exclusive.add_argument("-emailfinder", action="store_true", help="Use EmailFinder patterns")
    pattern_exclusive.add_argument("-uuidfinder", action="store_true", help="Use UUIDFinder patterns")

    # Request Options
    request_group = parser.add_argument_group("Request Options")
    request_group.add_argument("-t", "-threads", dest="threads", type=int, default=5, help="Number of threads")
    request_group.add_argument("-timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    request_group.add_argument("-ua", "-user-agent", dest="user_agent", help="Custom User-Agent")
    request_group.add_argument("-headers", help="Additional headers as JSON string")
    request_group.add_argument("-cookie", help="Additional cookie as string")
    request_group.add_argument("-insecure", action="store_true", help="Disable SSL verification")
    request_group.add_argument("-follow-redirects", action="store_true", help="Follow redirects")
    request_group.add_argument("-retries", type=int, default=0, help="Number of retries per request")
    request_group.add_argument("-fullpath", action="store_true", help="Show full path in linkfinder")
    # WAF options would go here

    return parser.parse_args(custom_args) if custom_args is not None else parser.parse_args()

class LeakJS:
    """Main class for the LeakJS tool."""

    def __init__(self, args):
        """Initializes the LeakJS object."""
        self.args = args
        self.urls = []
        self.patterns = []
        self.results = []
        self.loaded_pattern_files = set()  # Track already loaded pattern files
        self.session = self._create_session()
        self.setup_patterns()

    def _create_session(self) -> requests.Session:
        """Creates a session object with configured headers."""
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
        if self.args.cookie:
            headers["Cookie"] = self.args.cookie
        session.headers.update(headers)
        return session

    def setup_patterns(self):
        """Sets up the regex patterns to be used for scanning."""
        patterns_to_load = []
        if self.args.regex_file:
            patterns_to_load.append((self.args.regex_file, "custom"))
        if self.args.regex:
            self.patterns.append({"name": "cli-regex", "regex": self.args.regex, "type": "custom"})
        if self.args.linkfinder or (not self.args.regex_file and not self.args.secretfinder and not self.args.emailfinder and not self.args.uuidfinder and not self.args.regex):
            patterns_to_load.append((os.path.join(DEFAULT_PATH, "linkfinder.yaml"), "linkfinder"))
        if self.args.secretfinder or (not self.args.regex_file and not self.args.linkfinder and not self.args.emailfinder and not self.args.uuidfinder and not self.args.regex):
            patterns_to_load.append((os.path.join(DEFAULT_PATH, "secrets.yaml"), "secrets"))
        if self.args.emailfinder or (not self.args.regex_file and not self.args.linkfinder and not self.args.secretfinder and not self.args.uuidfinder and not self.args.regex):
            patterns_to_load.append((os.path.join(DEFAULT_PATH, "emailfinder.yaml"), "email"))
        if self.args.uuidfinder or (not self.args.regex_file and not self.args.linkfinder and not self.args.secretfinder and not self.args.emailfinder and not self.args.regex):
            patterns_to_load.append((os.path.join(DEFAULT_PATH, "uuidfinder.yaml"), "uuid"))

        for pattern_file, pattern_type in patterns_to_load:
            if pattern_file in self.loaded_pattern_files:  # Skip if already loaded
                continue
            self._load_pattern_file(pattern_file, pattern_type)
            self.loaded_pattern_files.add(pattern_file)  # Mark as loaded

    def _load_pattern_file(self, pattern_file: str, pattern_type: str):
        """Loads regex patterns from a YAML file."""
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
                            logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} Invalid regex in {pattern_file}: {pattern_info.get('name', 'unnamed')} - {str(e)}")
                            continue  # Skip invalid patterns
                if not self.args.health_check and self.args.verbose:  # Avoid duplicate messages during health check
                    logger.info(f"Loaded {count} patterns from {pattern_file}")
        except (yaml.YAMLError, FileNotFoundError, IOError) as e:
            logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} Error loading pattern file {pattern_file}: {str(e)}")
            if self.args.exit_on_error: sys.exit(1)

    def load_urls(self):
        """Loads URLs from a single URL, a file, or stdin."""
        try:
            if self.args.url:
                self.urls.append(self.args.url)
            elif self.args.url_file:
                if not os.path.exists(self.args.url_file):
                    raise FileNotFoundError(f"URL file not found: {self.args.url_file}")
                with open(self.args.url_file, "r", encoding="utf-8") as f:
                    self.urls = [line.strip() for line in f if line.strip()]
            else:  # Read from stdin
                if not sys.stdin.isatty():
                    self.urls = [line.strip() for line in sys.stdin if line.strip()]
                else:
                    logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} No URLs provided. Use -u/--url, -l/--url-file, or pipe input.")
                    sys.exit(1)

            self.urls = [url if url.startswith(('http://', 'https://')) else f'https://{url}' for url in self.urls]
            if not self.urls:
                logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} No URLs provided.")
                sys.exit(1)
        except FileNotFoundError as e:
            logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} {str(e)}")
            if self.args.exit_on_error: sys.exit(1)
        except Exception as e:
            logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} Error loading URLs: {str(e)}")
            if self.args.exit_on_error: sys.exit(1)

    def fetch_url(self, url: str) -> Tuple[str, Optional[str]]:
        """Fetches the content of a URL."""
        try:
            response = self.session.get(
                url,
                timeout=self.args.timeout,
                verify=not self.args.insecure,
                allow_redirects=self.args.follow_redirects
            )
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            return url, response.text
        except requests.exceptions.HTTPError as e:
            logger.debug(f"HTTP error fetching {url}: {str(e)}")
            return url, None
        except requests.exceptions.ConnectionError as e:
            logger.debug(f"Connection error fetching {url}: {str(e)}")
            return url, None
        except requests.exceptions.Timeout as e:
            logger.debug(f"Timeout error fetching {url}: {str(e)}")
            return url, None
        except Exception as e:
            logger.debug(f"Error fetching {url}: {str(e)}")
            return url, None

    def scan_content(self, url: str, content: str, scan_type: str) -> List[Dict]:
        """Scans the content for patterns of the specified type."""
        url_results = []
        for pattern in self.patterns:
            if pattern['type'] != scan_type: continue
            try:
                regex = re.compile(pattern['regex'], re.MULTILINE | re.DOTALL)
                matches = regex.findall(content)
                for match in matches:
                    finding = match[0] if isinstance(match, tuple) else match
                    if finding:
                        result = {
                            "confidence": pattern.get("confidence", "medium"),
                            "url": url,
                            "finding": finding,
                            "pattern_name": pattern.get("name", "unnamed")
                        }
                        if self.args.fullpath and scan_type == "linkfinder":
                            parsed_url = urlparse(url)
                            result["full_path"] = urljoin(f"{parsed_url.scheme}://{parsed_url.netloc}", finding)
                        url_results.append(result)
            except Exception as e:
                logger.error(f"Error scanning content with pattern {pattern.get('name', 'unnamed')}: {str(e)}")
                continue
        return url_results

    def process_urls(self):
        """Processes the URLs using a thread pool."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            future_to_url = {executor.submit(self.fetch_url, url): url for url in self.urls}
            disable_progress = self.args.silent or not self.args.progress
            with tqdm(total=len(self.urls), desc=f"{Fore.BLUE}[INF]{Style.RESET_ALL} Processing URLs", disable=disable_progress) as progress_bar:
                for future in concurrent.futures.as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        url, content = future.result()
                        if content:
                            scan_type = self.determine_scan_type(url)
                            matches = self.scan_content(url, content, scan_type)
                            if matches:
                                self.results.extend(matches)
                                self.print_results(url, matches)
                    except Exception as e:
                        logger.error(f"Error processing URL {url}: {str(e)}")
                    finally:
                        progress_bar.update(1)
                        progress_bar.set_description(f"{Fore.BLUE}[INF]{Style.RESET_ALL} Processing: {url}")  # Show current URL

    def determine_scan_type(self, url: str) -> str:
        """Determines the scan type based on the mode and URL."""
        if self.args.mode == 'auto':
            return "secrets" if url.endswith('.js') else "linkfinder"
        elif self.args.linkfinder:
            return "linkfinder"
        elif self.args.secretfinder:
            return "secrets"
        elif self.args.emailfinder:
            return "email"
        elif self.args.uuidfinder:
            return "uuid"
        else:
            return "secrets" if url.endswith('.js') else "linkfinder"  # Default

    def print_results(self, url: str, findings: List[Dict]):
        """Prints the findings to the console."""
        if not self.args.silent and self.args.v:
            color_map = {"high": Fore.RED, "medium": Fore.YELLOW, "low": Fore.GREEN}
            print(f"{Fore.GREEN}[FOUND]{Style.RESET_ALL} {url}")
            for finding in findings:
                confidence = finding['confidence'].lower()
                color = color_map.get(confidence, "")
                output = f"  [{color}{finding['pattern_name']}{Style.RESET_ALL}] {finding['finding']}" if 'pattern_name' in finding else f"  {finding['finding']}"
                if "full_path" in finding:
                    output += f"  Full Path: {finding['full_path']}"
                print(output)

    def print_summary(self, start_time: float):
        """Prints a summary of the scan results."""
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

    def write_output(self):
        """Writes the results to a file in the specified format."""
        if not self.args.output:
            return

        if not self.results:
            logger.info(f"{Fore.BLUE}[INF]{Style.RESET_ALL} No results to write.")
            return

        try:
            if self.args.output:
                output_file = self.args.output
            else:
                # If no output file is specified, create one based on the URL
                parsed_url = urlparse(self.urls[0])
                base_filename = parsed_url.netloc.replace('.', '_')
                output_file = f"{base_filename}_leaks.{self.args.format}"

            with open(output_file, 'w', encoding='utf-8') as f:
                if self.args.format == 'json':
                    json.dump(self.results, f, indent=4)
                elif self.args.format == 'csv':
                    fieldnames = self.results[0].keys()
                    writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=self.args.delimiter)
                    writer.writeheader()
                    writer.writerows(self.results)
                elif self.args.format == 'txt':
                    for result in self.results:
                        f.write(f"URL: {result['url']}\n")
                        f.write(f"Finding: {result['finding']}\n")
                        f.write(f"Confidence: {result['confidence']}\n")
                        if 'pattern_name' in result:
                            f.write(f"Pattern Name: {result['pattern_name']}\n")
                        if "full_path" in result:
                            f.write(f"Full Path: {result['full_path']}\n")
                        f.write("-" * 30 + "\n")
                else:
                    logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} Invalid output format: {self.args.format}")
                    return

            logger.info(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Results written to {output_file} in {self.args.format.upper()} format.")

        except Exception as e:
            logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} Error writing output to file: {str(e)}")

    def run(self):
        """Runs the LeakJS scanner."""
        try:
            # Mode-specific settings
            if self.args.mode == 'lazy':
                self.args.timeout = 4
                self.args.follow_redirects = True
                self.args.retries = 2
            elif self.args.mode == 'anonymous':
                # Implement Tor/proxy setup here
                pass

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
            self.write_output()

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
        """Performs a health check to verify the tool's configuration."""
        self.args.silent = True  # Silence normal output during health check
        print(f"{Fore.BLUE}[INF]{Style.RESET_ALL} Running health check...")
        test_flags = [
            ("-url", ["https://example.com"]),
            ("-regex-file", ["test_patterns.yaml"]),
            ("-secretfinder", []),
            ("-linkfinder", []),
            ("-emailfinder", []),
            ("-uuidfinder", []),
            ("-threads", ["2"]),
            ("-timeout", ["5"]),
            ("-ua", ["TestAgent"]),
            ("-headers", ['{"Test-Header": "Value"}']),
            ("-cookie", ["test=value"]),
            ("-insecure", []),
            ("-follow-redirects", []),
            ("-summary", []),
            ("-progress", []),
            ("-exit-on-error", []),
            ("-fullpath", []),
            ("-v", []),
            ("-o", ["test_output.txt"]),
            ("-format", ["json"]),
            ("-mode", ["auto"])
        ]

        results = []
        for flag, value in test_flags:
            try:
                # Create a temporary test configuration with just this flag
                test_args = [flag] + value
                args = parse_args(test_args)

                # Avoid actual execution by creating a minimal test instance
                test_instance = LeakJS(args)
                # Trigger pattern loading to check regex
                test_instance.setup_patterns()
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
    """Main function to run the LeakJS tool."""
    try:
        args = parse_args()
        if args.debug:
            logger.setLevel(logging.DEBUG)

        scanner = LeakJS(args)
        if args.health_check:
            scanner.health_check()
        else:
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
