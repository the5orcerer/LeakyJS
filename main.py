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
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

import colorama
import requests
import yaml
from colorama import Fore, Style
from tqdm import tqdm

# --- Constants ---
COLOR_BLUE = Fore.BLUE
COLOR_RED = Fore.RED
COLOR_GREEN = Fore.GREEN
COLOR_YELLOW = Fore.YELLOW
STYLE_RESET = Style.RESET_ALL
DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "patterns")
VERSION = "1.0.0"

# --- Initialize ---
colorama.init(autoreset=True)
logging.basicConfig(level=logging.DEBUG if '--debug' in sys.argv else logging.INFO, format="%(message)s", handlers=[logging.StreamHandler()])
logger = logging.getLogger("LeakJS")


# --- Utility Functions ---
def print_banner(args: argparse.Namespace, urls: List[str]) -> None:
    """Prints the program banner with configuration details."""
    if args.silent:
        return

    print(f"{COLOR_BLUE}LeakJS v{VERSION}{STYLE_RESET}")
    print(f"{COLOR_BLUE}{'=' * 50}{STYLE_RESET}")
    print(f"URLs to scan: {len(urls)}")
    print(f"Threads: {args.threads}")
    print(f"Timeout: {args.timeout or DEFAULT_TIMEOUT}s")
    print(f"Mode: {args.mode}")
    print(f"Output format: {args.format.upper()}")
    if args.output:
        print(f"Output file: {args.output}")
    print(f"{COLOR_BLUE}{'=' * 50}{STYLE_RESET}\n")


def parse_arguments(custom_args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parses command-line arguments using argparse."""
    parser = argparse.ArgumentParser(description="LeakJS - JavaScript secrets and endpoint scanner")

    # --- Argument Groups ---
    general_group = parser.add_argument_group("General Options")
    url_group = parser.add_argument_group("URL Options")
    mode_group = parser.add_argument_group("Mode Options")
    pattern_group = parser.add_argument_group("Pattern Options")
    request_group = parser.add_argument_group("Request Options")

    # --- General Options ---
    general_group.add_argument("-v", "-verbose", action="store_true", help="Enable verbose output")
    general_group.add_argument("-debug", action="store_true", help="Enable debug logging")
    general_group.add_argument("-exit-on-error", action="store_true", help="Exit on error")
    general_group.add_argument("-health-check", action="store_true", help="Perform health check")
    general_group.add_argument("-o", "-output", help="Output file to write results")
    general_group.add_argument("-format", choices=['csv', 'json', 'txt'], default='txt', help="Output format (csv, json, txt)")
    general_group.add_argument("-progress", action="store_true", help="Show progress bar")
    general_group.add_argument("-summary", action="store_true", help="Show detailed summary at the end")
    general_group.add_argument("-silent", action="store_true", help="Silent mode, no output except findings")

    # --- URL Options ---
    url_exclusive = url_group.add_mutually_exclusive_group()
    url_exclusive.add_argument("-u", "-url", dest="url", help="Single URL to scan")
    url_exclusive.add_argument("-l", "-url-file", dest="url_file", help="File containing URLs to scan (one per line)")

    # --- Mode Options ---
    mode_group.add_argument("-mode", choices=['auto', 'lazy', 'anonymous'], default='auto', help="Scanning mode: auto, lazy, anonymous")

    # --- Pattern Options ---
    pattern_exclusive = pattern_group.add_mutually_exclusive_group()
    pattern_exclusive.add_argument("-regex-file", help="Custom regex patterns file (YAML)")
    pattern_exclusive.add_argument("-regex", help="Regex pattern from command line")
    pattern_exclusive.add_argument("-secretfinder", action="store_true", help="Use SecretFinder patterns")
    pattern_exclusive.add_argument("-linkfinder", action="store_true", help="Use LinkFinder patterns")
    pattern_exclusive.add_argument("-emailfinder", action="store_true", help="Use EmailFinder patterns")
    pattern_exclusive.add_argument("-uuidfinder", action="store_true", help="Use UUIDFinder patterns")

    # --- Request Options ---
    request_group.add_argument("-t", "-threads", dest="threads", type=int, default=5, help="Number of threads")
    request_group.add_argument("-timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    request_group.add_argument("-ua", "-user-agent", dest="user_agent", help="Custom User-Agent")
    request_group.add_argument("-headers", help="Additional headers as JSON string")
    request_group.add_argument("-cookie", help="Additional cookie as string")
    request_group.add_argument("-insecure", action="store_true", help="Disable SSL verification")
    request_group.add_argument("-follow-redirects", action="store_true", help="Follow redirects")
    request_group.add_argument("-retries", type=int, default=0, help="Number of retries per request")
    request_group.add_argument("-fullpath", action="store_true", help="Show full path in linkfinder")
    request_group.add_argument("-delimiter", default=",", help="Delimiter for CSV output (default: ,)")

    return parser.parse_args(custom_args) if custom_args else parser.parse_args()


# --- Core Class ---
class LeakJS:
    """Main class for the LeakJS tool."""

    def __init__(self, args: argparse.Namespace) -> None:
        """Initializes the LeakJS object."""
        self.args = args
        self.urls: List[str] = []
        self.patterns: List[Dict] = []
        self.results: List[Dict] = []
        self.loaded_pattern_files: set[str] = set()  # Track already loaded pattern files
        self.session: requests.Session = self._create_session()
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
                logger.error(f"{COLOR_RED}[ERR]{STYLE_RESET} Failed to parse custom headers JSON: {e}")
        if self.args.cookie:
            headers["Cookie"] = self.args.cookie
        session.headers.update(headers)
        return session

    def setup_patterns(self) -> None:
        """Sets up the regex patterns for scanning."""
        patterns_to_load: List[Tuple[str, str]] = []

        if self.args.regex_file:
            patterns_to_load.append((self.args.regex_file, "custom"))
        if self.args.regex:
            self.patterns.append({"name": "cli-regex", "regex": self.args.regex, "type": "custom"})

        # Load default patterns if no specific pattern options are provided
        if not any([self.args.regex_file, self.args.regex, self.args.secretfinder, self.args.linkfinder, self.args.emailfinder, self.args.uuidfinder]):
            patterns_to_load.extend([
                (os.path.join(DEFAULT_PATH, "linkfinder.yaml"), "linkfinder"),
                (os.path.join(DEFAULT_PATH, "secrets.yaml"), "secrets"),
                (os.path.join(DEFAULT_PATH, "emailfinder.yaml"), "email"),
                (os.path.join(DEFAULT_PATH, "uuidfinder.yaml"), "uuid")
            ])
        else:
            if self.args.linkfinder:
                patterns_to_load.append((os.path.join(DEFAULT_PATH, "linkfinder.yaml"), "linkfinder"))
            if self.args.secretfinder:
                patterns_to_load.append((os.path.join(DEFAULT_PATH, "secrets.yaml"), "secrets"))
            if self.args.emailfinder:
                patterns_to_load.append((os.path.join(DEFAULT_PATH, "emailfinder.yaml"), "email"))
            if self.args.uuidfinder:
                patterns_to_load.append((os.path.join(DEFAULT_PATH, "uuidfinder.yaml"), "uuid"))

        for pattern_file, pattern_type in patterns_to_load:
            if pattern_file not in self.loaded_pattern_files:
                self._load_pattern_file(pattern_file, pattern_type)
                self.loaded_pattern_files.add(pattern_file)

    def _load_pattern_file(self, pattern_file: str, pattern_type: str) -> None:
        """Loads regex patterns from a YAML file and compiles them."""
        try:
            if not os.path.exists(pattern_file):
                raise FileNotFoundError(f"Pattern file not found: {pattern_file}")

            with open(pattern_file, "r", encoding="utf-8") as f:
                patterns_data = yaml.safe_load(f)

            if not patterns_data:
                logger.info(f"No patterns found in {pattern_file}")
                return

            count = 0
            for pattern_data in patterns_data:
                if 'pattern' in pattern_data:
                    try:
                        pattern_info = pattern_data['pattern']
                        regex = pattern_info['regex']
                        re.compile(regex)  # Validate regex
                        compiled_regex = re.compile(regex, re.MULTILINE | re.DOTALL)  # Compile regex
                        pattern = {
                            "name": pattern_info.get('name', 'unnamed'),
                            "regex": compiled_regex,  # Store compiled regex
                            "type": pattern_type,
                            "confidence": pattern_info.get('confidence', 'medium')
                        }
                        self.patterns.append(pattern)
                        count += 1
                    except re.error as e:
                        logger.error(f"{COLOR_RED}[ERR]{STYLE_RESET} Invalid regex in {pattern_file}: {pattern_info.get('name', 'unnamed')} - {e}")

            if not self.args.health_check and self.args.verbose:
                logger.info(f"Loaded {count} patterns from {pattern_file}")

        except (yaml.YAMLError, FileNotFoundError, IOError) as e:
            logger.error(f"{COLOR_RED}[ERR]{STYLE_RESET} Error loading pattern file {pattern_file}: {e}")
            if self.args.exit_on_error:
                sys.exit(1)

    def load_urls(self) -> None:
        """Loads URLs from a single URL, a file, or stdin."""
        try:
            if self.args.url:
                self.urls = [self.args.url]
            elif self.args.url_file:
                if not os.path.exists(self.args.url_file):
                    raise FileNotFoundError(f"URL file not found: {self.args.url_file}")
                with open(self.args.url_file, "r", encoding="utf-8") as f:
                    self.urls = [line.strip() for line in f if line.strip()]
            else:  # Read from stdin
                if not sys.stdin.isatty():
                    self.urls = [line.strip() for line in sys.stdin if line.strip()]

            # Add scheme if missing
            self.urls = [url if url.startswith(('http://', 'https://')) else f'https://{url}' for url in self.urls]

            if not self.urls and not self.args.health_check:
                logger.error(f"{COLOR_RED}[ERR]{STYLE_RESET} No URLs provided.")
                sys.exit(1)

        except FileNotFoundError as e:
            logger.error(f"{COLOR_RED}[ERR]{STYLE_RESET} {e}")
            if self.args.exit_on_error:
                sys.exit(1)
        except Exception as e:
            logger.error(f"{COLOR_RED}[ERR]{STYLE_RESET} Error loading URLs: {e}")
            if self.args.exit_on_error:
                sys.exit(1)

    def fetch_url(self, url: str) -> Tuple[str, Optional[str]]:
        """Fetches the content of a URL."""
        try:
            response = self.session.get(
                url,
                timeout=self.args.timeout,
                verify=not self.args.insecure,
                allow_redirects=self.args.follow_redirects,
                retries=self.args.retries  # Use retries
            )
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            return url, response.text

        except requests.exceptions.RequestException as e:
            logger.info(f"Error fetching {url}: {e}")
            return url, None

    def scan_content(self, url: str, content: str, scan_type: str) -> List[Dict]:
        """Scans the content for patterns of the specified type."""
        url_results: List[Dict] = []
        for pattern in self.patterns:
            if pattern['type'] != scan_type:
                continue
            try:
                matches = pattern['regex'].findall(content)  # Use precompiled regex
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
                logger.error(f"Error scanning content with pattern {pattern.get('name', 'unnamed')}: {e}")
        return url_results

    def process_urls(self) -> None:
        """Processes the URLs using a thread pool."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            future_to_url = {executor.submit(self.fetch_url, url): url for url in self.urls}
            disable_progress = self.args.silent or not self.args.progress

            with tqdm(total=len(self.urls), desc=f"{COLOR_BLUE}[INF]{STYLE_RESET} Processing URLs", disable=disable_progress) as progress_bar:
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
                        logger.error(f"Error processing URL {url}: {e}")
                    finally:
                        progress_bar.update(1)
                        progress_bar.set_description(f"{COLOR_BLUE}[INF]{STYLE_RESET} Processing: {url}")

    def determine_scan_type(self, url: str) -> str:
        """Determines the scan type based on the mode and URL."""
        if self.args.mode == 'auto':
            return "secrets" if url.endswith('.js') else "linkfinder"

        if self.args.linkfinder:
            return "linkfinder"
        if self.args.secretfinder:
            return "secrets"
        if self.args.emailfinder:
            return "email"
        if self.args.uuidfinder:
            return "uuid"
        return "secrets" if url.endswith('.js') else "linkfinder"

    def print_results(self, url: str, findings: List[Dict]) -> None:
        """Prints the findings to the console."""
        if not self.args.silent and self.args.v:
            color_map = {"high": COLOR_RED, "medium": COLOR_YELLOW, "low": COLOR_GREEN}
            print(f"{COLOR_GREEN}[FOUND]{STYLE_RESET} {url}")
            for finding in findings:
                confidence = finding['confidence'].lower()
                color = color_map.get(confidence, "")
                output = f"  [{color}{finding['pattern_name']}{STYLE_RESET}] {finding['finding']}" if 'pattern_name' in finding else f"  {finding['finding']}"
                if "full_path" in finding:
                    output += f"  Full Path: {finding['full_path']}"
                print(output)

    def print_summary(self, start_time: float) -> None:
        """Prints a summary of the scan results."""
        if self.args.silent:
            return

        elapsed_time = time.time() - start_time

        print(f"\n{COLOR_BLUE}[INF]{STYLE_RESET} Summary:")
        print(f"Total URLs processed: {len(self.urls)}")
        print(f"Findings: {len(self.results)}")
        print(f"Time taken: {elapsed_time:.2f}s")

        if not self.results:
            return

        pattern_counts: Dict[str, int] = {}
        confidence_counts: Dict[str, int] = {"high": 0, "medium": 0, "low": 0}

        for result in self.results:
            pattern_name = result['pattern_name']
            pattern_counts[pattern_name] = pattern_counts.get(pattern_name, 0) + 1
            confidence = result['confidence'].lower()
            confidence_counts[confidence] += 1

        print(f"\n{COLOR_BLUE}[INF]{STYLE_RESET} Findings by pattern:")
        for pattern, count in sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {pattern}: {count}")

        print(f"\n{COLOR_BLUE}[INF]{STYLE_RESET} Findings by confidence:")
        colors = {"high": COLOR_RED, "medium": COLOR_YELLOW, "low": COLOR_GREEN}
        for confidence, count in confidence_counts.items():
            color = colors.get(confidence, '')
            print(f"  {color}{confidence.capitalize()}{STYLE_RESET}: {count}")

    def write_output(self) -> None:
        """Writes the results to a file in the specified format."""
        if not self.args.output:
            return

        if not self.results:
            logger.info(f"{COLOR_BLUE}[INF]{STYLE_RESET} No results to write.")
            return

        try:
            output_file = self.args.output if self.args.output else "leaks.txt"  # Default output file

            if not self.args.output:
                # If no output file is specified, create one based on the URL
                if self.urls:
                    parsed_url = urlparse(self.urls[0])
                    base_filename = parsed_url.netloc.replace('.', '_')
                else:
                    base_filename = "leaks"
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
                    logger.error(f"{COLOR_RED}[ERR]{STYLE_RESET} Invalid output format: {self.args.format}")
                    return

            logger.info(f"{COLOR_GREEN}[SUCCESS]{STYLE_RESET} Results written to {output_file} in {self.args.format.upper()} format.")

        except Exception as e:
            logger.error(f"{COLOR_RED}[ERR]{STYLE_RESET} Error writing output to file: {e}")

    def run(self) -> None:
        """Runs the LeakJS scanner."""
        try:
            # --- Mode-specific settings ---
            if self.args.mode == 'lazy':
                self.args.timeout = 4
                self.args.follow_redirects = True
                self.args.retries = 2
            elif self.args.mode == 'anonymous':
                # Implement Tor/proxy setup here (e.g., using a Tor proxy)
                pass

            if not self.patterns and not self.args.health_check:
                logger.error(f"{COLOR_RED}[ERR]{STYLE_RESET} No valid patterns loaded. Exiting.")
                return

            self.load_urls()
            if self.urls or self.args.health_check:
                print_banner(self.args, self.urls)
            logger.debug(f"Loaded {len(self.urls)} URLs, {len(self.patterns)} patterns")

            start_time = time.time()
            self.process_urls()

            if self.args.summary:
                self.print_summary(start_time)

            self.write_output()

        except KeyboardInterrupt:
            logger.error(f"\n{COLOR_RED}[ERR]{STYLE_RESET} Interrupted by user. Exiting...")
            sys.exit(1)
        except Exception as e:
            logger.error(f"{COLOR_RED}[ERR]{STYLE_RESET} Error during run: {e}")
            if self.args.debug:
                import traceback
                traceback.print_exc()
            if self.args.exit_on_error:
                sys.exit(1)

    def health_check(self) -> None:
        """Performs a health check to verify the tool's configuration."""
        self.args.silent = True  # Silence normal output during health check
        print(f"{COLOR_BLUE}[INF]{STYLE_RESET} Running health check...")

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

        # Create a dummy test_patterns.yaml
        with open("test_patterns.yaml", "w") as f:
            f.write("""
patterns:
  - pattern:
      name: Test Pattern
      regex: "test_pattern"
      confidence: high
""")

        results: List[Tuple[str, str]] = []
        for flag, value in test_flags:
            try:
                # Create a temporary test configuration with just this flag
                test_args = [flag] + value
                args = parse_arguments(test_args)

                # Avoid actual execution by creating a minimal test instance
                test_instance = LeakJS(args)
                # Trigger pattern loading to check regex
                test_instance.setup_patterns()
                results.append((flag, "OK"))
            except Exception as e:
                results.append((flag, "ERR"))
                logger.error(f"{COLOR_RED}[ERR]{STYLE_RESET} Error testing flag {flag}: {e}")

        # Print test results
        print(f"\n{COLOR_BLUE}[INF]{STYLE_RESET} Health Check Results:")
        for flag, status in results:
            status_marker = f"{COLOR_GREEN}✓{STYLE_RESET}" if status == "OK" else f"{COLOR_RED}✗{STYLE_RESET}"
            print(f"  {status_marker} {flag}")

        # Overall status
        if all(status == "OK" for _, status in results):
            print(f"\n{COLOR_GREEN}[SUCCESS]{STYLE_RESET} All checks passed!")
        else:
            print(f"\n{COLOR_RED}[WARNING]{STYLE_RESET} Some checks failed.")

        # Clean up the dummy file
        os.remove("test_patterns.yaml")


# --- Main Function ---
def main() -> None:
    """Main function to run the LeakJS tool."""
    try:
        args = parse_arguments()
        if args.debug:
            logger.setLevel(logging.DEBUG)

        scanner = LeakJS(args)
        if args.health_check:
            scanner.health_check()
        else:
            scanner.run()

    except KeyboardInterrupt:
        print(f"\n{COLOR_RED}[ERR]{STYLE_RESET} Interrupted by user. Exiting...")
        sys.exit(1)
    except SystemExit:
        raise
    except Exception as e:
        print(f"{COLOR_RED}[CRITICAL ERROR]{STYLE_RESET} {e}")
        print("Try running with --debug for more information.")
        sys.exit(1)


if __name__ == "__main__":
    main()
