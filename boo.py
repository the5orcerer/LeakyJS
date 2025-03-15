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
from urllib.parse import urlparse, urljoin, unquote

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
VERSION = "1.0.1"

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
    if args.proxy:
        print(f"Proxy: {args.proxy}")
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
    general_group.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Enable verbose output")
    general_group.add_argument("--debug", dest="debug", action="store_true", help="Enable debug logging")
    general_group.add_argument("--exit-on-error", dest="exit_on_error", action="store_true", help="Exit on error")
    general_group.add_argument("--health-check", dest="health_check", action="store_true", help="Perform health check")
    general_group.add_argument("-o", "--output", dest="output", help="Output file to write results")
    general_group.add_argument("--format", dest="format", choices=['csv', 'json', 'txt'], default='txt', help="Output format (csv, json, txt)")
    general_group.add_argument("--progress", dest="progress", action="store_true", help="Show progress bar")
    general_group.add_argument("--summary", dest="summary", action="store_true", help="Show detailed summary at the end")
    general_group.add_argument("--silent", dest="silent", action="store_true", help="Silent mode, no output except findings and progress bar if enabled")

    # --- URL Options ---
    url_exclusive = url_group.add_mutually_exclusive_group()
    url_exclusive.add_argument("-u", "--url", dest="url", help="Single URL to scan")
    url_exclusive.add_argument("-l", "--url-file", dest="url_file", help="File containing URLs to scan (one per line)")

    # --- Mode Options ---
    mode_group.add_argument("--mode", dest="mode", choices=['auto', 'lazy', 'anonymous'], default='auto', help="Scanning mode: auto, lazy, anonymous")

    # --- Pattern Options ---
    pattern_exclusive = pattern_group.add_mutually_exclusive_group()
    pattern_exclusive.add_argument("--regex-file", dest="regex_file", help="Custom regex patterns file (YAML)")
    pattern_exclusive.add_argument("-r", "--regex", dest="regex", help="Regex pattern from command line")
    pattern_exclusive.add_argument("--secretfinder", dest="secretfinder", action="store_true", help="Use SecretFinder patterns")
    pattern_exclusive.add_argument("--linkfinder", dest="linkfinder", action="store_true", help="Use LinkFinder patterns")
    pattern_exclusive.add_argument("--emailfinder", dest="emailfinder", action="store_true", help="Use EmailFinder patterns")
    pattern_exclusive.add_argument("--uuidfinder", dest="uuidfinder", action="store_true", help="Use UUIDFinder patterns")

    # --- Request Options ---
    request_group.add_argument("-t", "--threads", dest="threads", type=int, default=5, help="Number of threads")
    request_group.add_argument("--timeout", dest="timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    request_group.add_argument("--ua", "--user-agent", dest="user_agent", help="Custom User-Agent")
    request_group.add_argument("--headers", dest="headers", help="Additional headers as JSON string")
    request_group.add_argument("--cookie", dest="cookie", help="Additional cookie as string")
    request_group.add_argument("--proxy", dest="proxy", help="HTTP/HTTPS proxy to use (e.g., http://127.0.0.1:8080)")
    request_group.add_argument("--insecure", dest="insecure", action="store_true", help="Disable SSL verification")
    request_group.add_argument("--follow-redirects", dest="follow_redirects", action="store_true", help="Follow redirects")
    request_group.add_argument("--retries", dest="retries", type=int, default=0, help="Number of retries per request")
    request_group.add_argument("--fullpath", dest="fullpath", action="store_true", help="Show full path in linkfinder")
    request_group.add_argument("--delimiter", dest="delimiter", default=",", help="Delimiter for CSV output (default: ,)")

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
        self.loaded_pattern_files: set = set()  # Track already loaded pattern files
        self.session: requests.Session = self._create_session()
        self.setup_patterns()

    def _create_session(self) -> requests.Session:
        """Creates a session object with configured headers and proxy."""
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
        
        # Configure proxy if provided
        if self.args.proxy:
            proxies = {
                "http": self.args.proxy,
                "https": self.args.proxy
            }
            session.proxies.update(proxies)
            
        return session

    def setup_patterns(self) -> None:
        """Sets up the regex patterns for scanning."""
        patterns_to_load: List[Tuple[str, str]] = []

        if self.args.regex_file:
            patterns_to_load.append((self.args.regex_file, "custom"))
        if self.args.regex:
            # For CLI regex, we need to directly compile it here
            try:
                regex = re.compile(self.args.regex, re.MULTILINE | re.DOTALL)
                self.patterns.append({
                    "name": "cli-regex", 
                    "regex": regex, 
                    "type": "custom",
                    "confidence": "medium"
                })
            except re.error as e:
                logger.error(f"{COLOR_RED}[ERR]{STYLE_RESET} Invalid CLI regex: {e}")

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
                        regex_str = pattern_info['regex']
                        
                        # Compile regex pattern
                        try:
                            compiled_regex = re.compile(regex_str, re.MULTILINE | re.DOTALL)
                            
                            # Create pattern dictionary with compiled regex
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
                            continue
                    except KeyError as e:
                        logger.error(f"{COLOR_RED}[ERR]{STYLE_RESET} Missing key in pattern: {e}")
                        continue

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

            # Add scheme if missing and clean URLs
            self.urls = [self._clean_url(url) for url in self.urls]

            # When running normally (not health check) we need URLs
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

def _clean_url(self, url: str) -> str:
    """Clean and normalize a URL."""
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'
        
    # Fix URLs with backslashes (common copy-paste error)
    url = url.replace('\\/', '/')  # Fix escaped forward slashes
    
    # Handle backslashes in URLs (common in Windows paths or incorrectly escaped URLs)
    url = url.replace('\\', '/')
    
    # Properly decode URL if needed
    try:
        parsed = urlparse(url)
        reassembled = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            reassembled += f"?{parsed.query}"
        if parsed.fragment:
            reassembled += f"#{parsed.fragment}"
        return reassembled
    except Exception:
        return url

def fetch_url(self, url: str) -> Tuple[str, Optional[str]]:
    """Fetches the content of a URL."""
    max_retries = getattr(self.args, 'retries', 0) + 1  # Default to 1 attempt (0 retries)
    
    for attempt in range(max_retries):
        try:
            response = self.session.get(
                url,
                timeout=getattr(self.args, 'timeout', DEFAULT_TIMEOUT),
                verify=not getattr(self.args, 'insecure', False),
                allow_redirects=getattr(self.args, 'follow_redirects', False)
            )
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            return url, response.text
        except requests.exceptions.RequestException as e:
            if not getattr(self.args, 'silent', False):
                logger.info(f"Attempt {attempt+1}/{max_retries}: Error fetching {url}: {e}")
            if attempt == max_retries - 1:  # Last attempt
                return url, None
            # Exponential backoff
            time.sleep(2 ** attempt)
            
    return url, None  # Fallback return if loop exits unexpectedly

def scan_content(self, url: str, content: str, scan_type: str) -> List[Dict]:
    """Scans the content for patterns of the specified type."""
    url_results: List[Dict] = []
    for pattern in self.patterns:
        if pattern['type'] != scan_type:
            continue
        try:
            # Use precompiled regex for finding matches
            matches = pattern['regex'].findall(content)
            for match in matches:
                # Fix string indices must be integers error
                if isinstance(match, tuple):
                    # Extract the first group from the tuple
                    finding = match[0] if match else ""
                else:
                    # Handle single string match
                    finding = match
                
                # Only process non-empty findings
                if finding:
                    result = {
                        "confidence": pattern.get("confidence", "medium"),
                        "url": url,
                        "finding": finding,
                        "pattern_name": pattern.get("name", "unnamed")
                    }
                    if hasattr(self.args, 'fullpath') and self.args.fullpath and scan_type == "linkfinder":
                        parsed_url = urlparse(url)
                        result["full_path"] = urljoin(f"{parsed_url.scheme}://{parsed_url.netloc}", finding)
                    url_results.append(result)
        except Exception as e:
            logger.error(f"Error scanning content with pattern {pattern.get('name', 'unnamed')}: {e}")
    return url_results

def process_urls(self) -> None:
    """Processes the URLs using a thread pool."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=getattr(self.args, 'threads', 5)) as executor:
        future_to_url = {executor.submit(self.fetch_url, url): url for url in self.urls}
        # Show progress bar only when specifically enabled or not in silent mode
        disable_progress = not getattr(self.args, 'progress', False)

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
                    if not getattr(self.args, 'silent', False):
                        logger.error(f"Error processing URL {url}: {e}")
                finally:
                    progress_bar.update(1)
                    progress_bar.set_description(f"{COLOR_BLUE}[INF]{STYLE_RESET} Processing: {url}")

def determine_scan_type(self, url: str) -> str:
    """Determines the scan type based on the mode and URL."""
    if getattr(self.args, 'mode', 'auto') == 'auto':
        return "secrets" if url.endswith('.js') else "linkfinder"

    if hasattr(self.args, 'linkfinder') and self.args.linkfinder:
        return "linkfinder"
    if hasattr(self.args, 'secretfinder') and self.args.secretfinder:
        return "secrets"
    if hasattr(self.args, 'emailfinder') and self.args.emailfinder:
        return "email"
    if hasattr(self.args, 'uuidfinder') and self.args.uuidfinder:
        return "uuid"
    return "secrets" if url.endswith('.js') else "linkfinder"

def print_results(self, url: str, findings: List[Dict]) -> None:
    """Prints the findings to the console."""
    if not getattr(self.args, 'silent', False) or (hasattr(self.args, 'verbose') and self.args.verbose):
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
    if getattr(self.args, 'silent', False):
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
        if confidence in confidence_counts:
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
    if not hasattr(self.args, 'output') or not self.args.output:
        return

    if not self.results:
        if not getattr(self.args, 'silent', False):
            logger.info(f"{COLOR_BLUE}[INF]{STYLE_RESET} No results to write.")
        return

    try:
        output_file = self.args.output if self.args.output else "leaks.txt"

        if not self.args.output:
            # If no output file is specified, create one based on the URL
            if self.urls:
                parsed_url = urlparse(self.urls[0])
                base_filename = parsed_url.netloc.replace('.', '_')
            else:
                base_filename = "leaks"
            output_file = f"{base_filename}_leaks.{getattr(self.args, 'format', 'txt')}"

        with open(output_file, 'w', encoding='utf-8') as f:
            if getattr(self.args, 'format', 'txt') == 'json':
                json.dump(self.results, f, indent=4)
            elif getattr(self.args, 'format', 'txt') == 'csv':
                fieldnames = self.results[0].keys() if self.results else []
                writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=getattr(self.args, 'delimiter', ','))
                if fieldnames:
                    writer.writeheader()
                    writer.writerows(self.results)
            elif getattr(self.args, 'format', 'txt') == 'txt':
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
                logger.error(f"{COLOR_RED}[ERR]{STYLE_RESET} Invalid output format: {getattr(self.args, 'format', 'txt')}")
                return

        if not getattr(self.args, 'silent', False):
            logger.info(f"{COLOR_GREEN}[SUCCESS]{STYLE_RESET} Results written to {output_file} in {getattr(self.args, 'format', 'txt').upper()} format.")

    except Exception as e:
        logger.error(f"{COLOR_RED}[ERR]{STYLE_RESET} Error writing output to file: {e}")

def run(self) -> None:
    """Runs the LeakJS scanner."""
    try:
        # --- Mode-specific settings ---
        if getattr(self.args, 'mode', 'auto') == 'lazy':
            self.args.timeout = 4
            self.args.follow_redirects = True
            self.args.retries = 2
        elif getattr(self.args, 'mode', 'auto') == 'anonymous':
            # Use proxy if provided in anonymous mode
            if not hasattr(self.args, 'proxy') or not self.args.proxy:
                logger.warning(f"{COLOR_YELLOW}[WARN]{STYLE_RESET} Anonymous mode works best with a proxy. Consider adding --proxy.")

        if not self.patterns and not getattr(self.args, 'health_check', False):
            logger.error(f"{COLOR_RED}[ERR]{STYLE_RESET} No valid patterns loaded. Exiting.")
            return

        self.load_urls()
        if self.urls or getattr(self.args, 'health_check', False):
            print_banner(self.args, self.urls)
        logger.debug(f"Loaded {len(self.urls)} URLs, {len(self.patterns)} patterns")

        start_time = time.time()
        self.process_urls()

        if hasattr(self.args, 'summary') and self.args.summary:
            self.print_summary(start_time)

        self.write_output()

    except KeyboardInterrupt:
        logger.error(f"\n{COLOR_RED}[ERR]{STYLE_RESET} Interrupted by user. Exiting...")
        sys.exit(1)
    except Exception as e:
        logger.error(f"{COLOR_RED}[ERR]{STYLE_RESET} Error during run: {e}")
        if hasattr(self.args, 'debug') and self.args.debug:
            import traceback
            traceback.print_exc()
        if hasattr(self.args, 'exit_on_error') and self.args.exit_on_error:
            sys.exit(1)

def health_check(self) -> None:
    """Performs a health check to verify the tool's configuration."""
    self.args.silent = True  # Silence normal output during health check
    print(f"{COLOR_BLUE}[INF]{STYLE_RESET} Running health check...")

    test_flags = [
        ("--url", ["https://example.com"]),
        ("--regex-file", ["test_patterns.yaml"]),
        ("--secretfinder", []),
        ("--linkfinder", []),
        ("--emailfinder", []),
        ("--uuidfinder", []),
        ("--threads", ["2"]),
        ("--timeout", ["5"]),
        ("--ua", ["TestAgent"]),
        ("--headers", ['{"Test-Header": "Value"}']),
        ("--cookie", ["test=value"]),
        ("--proxy", ["http://127.0.0.1:8080"]),
        ("--insecure", []),
        ("--follow-redirects", []),
        ("--summary", []),
        ("--progress", []),
        ("--exit-on-error", []),
        ("--fullpath", []),
        ("--verbose", []),
        ("--output", ["test_output.txt"]),
        ("--format", ["json"]),
        ("--mode", ["auto"]),
        ("--silent", [])
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
        if getattr(args, 'debug', False):
            logger.setLevel(logging.DEBUG)

        scanner = LeakJS(args)
        if getattr(args, 'health_check', False):
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
