"""
LeakJS - JavaScript secrets and endpoint scanner
Core controller class and main entry point
"""
from scanning_engine import ScanEngine
from leakjs_core import DatabaseManager
from main import VERSION, print_banner, check_for_updates, parse_args, get_filename_from_url, DEFAULT_PATH
import datetime
import json
import logging
import os
import sys
import time
from typing import Dict, List, Optional

from colorama import Fore, Style
import yaml

# Local imports
from main import VERSION, print_banner, check_for_updates, parse_args, get_filename_from_url

logger = logging.getLogger("LeakJS")

class LeakJS:
    """Main controller class for LeakJS scanner"""
    
    def __init__(self, args):
        """Initialize scanner with command-line arguments"""
        self.args = args
        self.urls = []
        self.patterns = []
        self.results = []
        self.loaded_pattern_files = set()  # Track already loaded pattern files
        
        # Setup logging based on args
        if args.debug:
            logger.setLevel(logging.DEBUG)
            
        # Setup log file if specified
        if args.log_file:
            log_dir = os.path.dirname(args.log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
                
            file_handler = logging.FileHandler(args.log_file)
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            logger.addHandler(file_handler)
        
        # Disable colors if requested
        if self.args.no_color:
            from colorama import init
            init(strip=True, convert=False)
        
        # Create session and load patterns
        from scan_engine import ScanEngine
        self.scan_engine = ScanEngine(args)
        self.setup_patterns()
        
        # Configure output directory
        if args.output_file and args.output_dir:
            os.makedirs(args.output_dir, exist_ok=True)
    
    def setup_patterns(self):
        """Set up and load pattern files"""
        patterns_to_load = []
        
        # Add custom regex pattern if specified
        custom_patterns = []
        if self.args.custom_pattern:
            pattern_parts = self.args.custom_pattern.split(':', 2)
            if len(pattern_parts) >= 2:
                name = pattern_parts[0]
                regex = pattern_parts[1]
                confidence = pattern_parts[2] if len(pattern_parts) > 2 else "medium"
                
                custom_patterns.append({
                    'pattern': {
                        'name': name,
                        'regex': regex,
                        'confidence': confidence
                    }
                })
        
        # Determine which pattern files to load
        if self.args.regex_file:
            patterns_to_load.append((self.args.regex_file, "custom"))
            
        if self.args.linkfinder or (not self.args.regex_file and not self.args.secretfinder):
            patterns_to_load.append((os.path.join(DEFAULT_PATH, "linkfinder.yaml"), "linkfinder"))
            
        if self.args.secretfinder or (not self.args.regex_file and not self.args.linkfinder):
            patterns_to_load.append((os.path.join(DEFAULT_PATH, "secrets.yaml"), "secrets"))
        
        # Load pattern files
        for pattern_file, pattern_type in patterns_to_load:
            if pattern_file in self.loaded_pattern_files:  # Skip if already loaded
                continue
            self._load_pattern_file(pattern_file, pattern_type)
            self.loaded_pattern_files.add(pattern_file)  # Mark as loaded
        
        # Add custom patterns
        for pattern in custom_patterns:
            pattern_info = pattern['pattern']
            try:
                # Validate regex
                import re
                re.compile(pattern_info['regex'])
                
                # Add custom type
                pattern_info['type'] = "custom"
                self.patterns.append(pattern_info)
                logger.info(f"Added custom pattern: {pattern_info['name']}")
            except re.error as e:
                logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} Invalid regex in custom pattern: {str(e)}")
        
        # Setup pattern matcher in scan engine
        self.scan_engine.setup_patterns(self.patterns)
    
    def _load_pattern_file(self, pattern_file: str, pattern_type: str):
        """Load patterns from YAML file"""
        try:
            # Handle default paths vs absolute paths
            if not os.path.isabs(pattern_file) and not os.path.exists(pattern_file):
                from main import DEFAULT_PATH
                alt_path = os.path.join(DEFAULT_PATH, pattern_file)
                if os.path.exists(alt_path):
                    pattern_file = alt_path
            
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
                            import re
                            pattern_info = pattern['pattern']
                            re.compile(pattern_info['regex'])  # Validate regex
                            pattern_info['type'] = pattern_type
                            self.patterns.append(pattern_info)
                            count += 1
                        except re.error:
                            logger.debug(f"Skipping invalid regex pattern: {pattern.get('name', 'unnamed')}")
                            
                if not self.args.health_check:  # Avoid duplicate messages during health check
                    logger.info(f"Loaded {count} patterns from {pattern_file}")
                    
        except (yaml.YAMLError, FileNotFoundError) as e:
            logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} Error loading pattern file {pattern_file}: {str(e)}")
            if self.args.exit_on_error:
                sys.exit(1)
    
    def create_pattern_file(self):
        """Create a new pattern file template"""
        if not self.args.create_pattern:
            return
            
        output_file = self.args.create_pattern
        
        # Ensure directory exists
        output_dir = os.path.dirname(output_file)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            
        # Create template
        template = [
            {
                'description': 'API Key Pattern',
                'pattern': {
                    'name': 'api_key',
                    'regex': '(?i)(?:api[_-]?key|apikey)(?:[\s:=]+)(?:[\"\'])([a-zA-Z0-9]{32})(?:[\"\'])',
                    'confidence': 'high'
                }
            },
            {
                'description': 'Authorization Bearer Token',
                'pattern': {
                    'name': 'bearer_token',
                    'regex': '(?i)(?:bearer)(?:\s+)([a-zA-Z0-9\.\-_]+)',
                    'confidence': 'medium'
                }
            },
            {
                'description': 'Generic Secret',
                'pattern': {
                    'name': 'generic_secret',
                    'regex': '(?i)(?:secret|password|token)(?:[\s:=]+)(?:[\"\'])([a-zA-Z0-9]{16,})(?:[\"\'])',
                    'confidence': 'medium'
                }
            }
        ]
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(template, f, default_flow_style=False, sort_keys=False)
            
        logger.info(f"Created pattern file template: {output_file}")
    
    def print_results(self, url: str, findings: List[Dict]):
        """Print findings for a specific URL"""
        if self.args.silent:
            return
            
        # Truncate long URLs for display
        from main import truncate_url
        display_url = truncate_url(url)
        
        # Use color coding based on confidence
        color_map = {
            "critical": Fore.MAGENTA + Style.BRIGHT,
            "high": Fore.RED,
            "medium": Fore.YELLOW,
            "low": Fore.GREEN,
            "info": Fore.CYAN
        }
        
        if self.args.minimal_output:
            # Just show the findings, one per line
            for finding in findings:
                print(f"{finding['url']} | {finding['pattern_name']} | {finding['finding']}")
        else:
            # Show detailed output
            print(f"{Fore.GREEN}[FOUND]{Style.RESET_ALL} {display_url}")
            for finding in findings:
                confidence = finding['confidence'].lower()
                color = color_map.get(confidence, "")
                
                # Print the finding
                print(f"  [{color}{finding['pattern_name']}{Style.RESET_ALL}] [{confidence.upper()}] {finding['finding']}")
                
                # Print context lines if available
                if finding.get('context') and not self.args.minimal_output:
                    context = finding['context']
                    print(f"  {Fore.BLUE}Context:{Style.RESET_ALL}")
                    for line in context.split('\n'):
                        print(f"  {line}")
                    print()
    
    def save_results(self):
        """Save scan results to file"""
        if not self.args.output_file or not self.results:
            return
            
        output_format = self.args.output_format.lower()
        
        # Generate the filename
        base_filename = self.args.output_file
        
        # Ensure output directory exists
        os.makedirs(self.args.output_dir, exist_ok=True)
        
        # Create metadata for the report
        metadata = {
            "scan_date": datetime.datetime.now().isoformat(),
            "version": VERSION,
            "urls_count": len(self.urls),
            "findings_count": len(self.results),
            "scan_time": time.time() - self.scan_engine.start_time if self.scan_engine.start_time else 0
        }
        
        # Generate the report in the requested format
        if output_format == 'json':
            output_file = os.path.join(self.args.output_dir, f"{base_filename}.json")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump({
                    "metadata": metadata,
                    "results": self.results
                }, f, indent=2)
                
        elif output_format == 'csv':
            output_file = os.path.join(self.args.output_dir, f"{base_filename}.csv")
            import csv
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Pattern Name', 'Finding', 'Confidence'])
                for finding in self.results:
                    writer.writerow([
                        finding['url'],
                        finding['pattern_name'],
                        finding['finding'],
                        finding['confidence']
                    ])
                    
        elif output_format == 'html':
            output_file = os.path.join(self.args.output_dir, f"{base_filename}.html")
            self._generate_html_report(output_file, metadata)
            
        elif output_format == 'markdown':
            output_file = os.path.join(self.args.output_dir, f"{base_filename}.md")
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"# LeakJS Scan Report\n\n")
                f.write(f"- **Scan Date:** {metadata['scan_date']}\n")
                f.write(f"- **URLs Scanned:** {metadata['urls_count']}\n")
                f.write(f"- **Findings:** {metadata['findings_count']}\n")
                f.write(f"- **Scan Time:** {metadata['scan_time']:.2f} seconds\n\n")
                
                f.write(f"## Findings\n\n")
                for finding in self.results:
                    f.write(f"### {finding['pattern_name']} ({finding['confidence'].upper()})\n\n")
                    f.write(f"- **URL:** {finding['url']}\n")
                    f.write(f"- **Finding:** `{finding['finding']}`\n\n")
                    if finding.get('context'):
                        f.write("**Context:**\n\n")
                        f.write("```\n")
                        f.write(finding['context'])
                        f.write("\n```\n\n")
                        
        elif output_format == 'yaml':
            output_file = os.path.join(self.args.output_dir, f"{base_filename}.yaml")
            data = {
                "metadata": metadata,
                "results": self.results
            }
            with open(output_file, 'w', encoding='utf-8') as f:
                yaml.dump(data, f, default_flow_style=False)
                
        elif output_format == 'sqlite':
            # Database export handled by db_manager
            if hasattr(self.scan_engine, 'db_manager') and self.scan_engine.db_manager:
                output_file = os.path.join(self.args.output_dir, f"{base_filename}.sqlite")
                self.scan_engine.db_manager.export_to_file(output_file)
            else:
                output_file = None
                logger.error("SQLite output format requires --use-db option")
                
        else:  # Default to text format
            output_file = os.path.join(self.args.output_dir, f"{base_filename}.txt")
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"LeakJS Scan Report\n")
                f.write(f"=================\n\n")
                f.write(f"Scan Date: {metadata['scan_date']}\n")
                f.write(f"URLs Scanned: {metadata['urls_count']}\n")
                f.write(f"Findings: {metadata['findings_count']}\n")
                f.write(f"Scan Time: {metadata['scan_time']:.2f} seconds\n\n")
                
                f.write(f"Findings:\n")
                for finding in self.results:
                    f.write(f"\n[{finding['pattern_name']}] [{finding['confidence'].upper()}]\n")
                    f.write(f"URL: {finding['url']}\n")
                    f.write(f"Finding: {finding['finding']}\n")
                    if finding.get('context'):
                        f.write("\nContext:\n")
                        f.write(finding['context'])
                        f.write("\n")
        
        if output_file:
            logger.info(f"Results saved to: {output_file}")
    
    def _generate_html_report(self, output_file, metadata):
        """Generate HTML report with advanced formatting"""
        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LeakJS Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .metadata { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .metadata-item { margin-bottom: 8px; }
        .findings { margin-top: 30px; }
        .finding { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 15px; border-left: 5px solid #ddd; }
        .critical { border-left-color: #9b59b6; }
        .high { border-left-color: #e74c3c; }
        .medium { border-left-color: #f39c12; }
        .low { border-left-color: #27ae60; }
        .info { border-left-color: #3498db; }
        .pattern-name { font-weight: bold; font-size: 18px; margin: 0 0 10px 0; }
        .confidence { display: inline-block; padding: 3px 6px; border-radius: 3px; font-size: 12px; color: white; margin-left: 10px; }
        .confidence.critical { background-color: #9b59b6; }
        .confidence.high { background-color: #e74c3c; }
        .confidence.medium { background-color: #f39c12; }
        .confidence.low { background-color: #27ae60; }
        .confidence.info { background-color: #3498db; }
        .url { font-family: monospace; word-break: break-all; margin: 10px 0; }
        .found-code { font-family: monospace; background-color: #eee; padding: 10px; border-radius: 3px; overflow-x: auto; }
        .context { background-color: #2c3e50; color: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; white-space: pre-wrap; margin-top: 10px; }
        .stats { display: flex; justify-content: space-between; margin-bottom: 20px; }
        .stat-box { flex: 1; padding: 15px; text-align: center; background-color: #f8f9fa; margin: 0 5px; border-radius: 5px; }
        .stat-value { font-size: 24px; font-weight: bold; }
        .stat-label { font-size: 14px; color: #666; }
        .footer { margin-top: 30px; text-align: center; color: #666; font-size: 12px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { text-align: left; padding: 12px; }
        th { background-color: #2c3e50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>LeakJS Scan Report</h1>
            <p>Generated on: {scan_date}</p>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <div class="stat-value">{urls_count}</div>
                <div class="stat-label">URLs Scanned</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{findings_count}</div>
                <div class="stat-label">Findings</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{scan_time:.2f}s</div>
                <div class="stat-label">Scan Time</div>
            </div>
        </div>

        <div class="metadata">
            <h2>Scan Details</h2>
            <div class="metadata-item"><strong>LeakJS Version:</strong> {version}</div>
            <div class="metadata-item"><strong>Generated By:</strong> {username}</div>
            <div class="metadata-item"><strong>Generated At:</strong> {current_time}</div>
        </div>
        
        <h2>Findings Summary</h2>
        <table>
            <tr>
                <th>Confidence</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>
            {confidence_summary}
        </table>

        <div class="findings">
            <h2>Detailed Findings</h2>
            {findings_html}
        </div>
        
        <div class="footer">
            <p>Report generated by LeakJS v{version} - https://github.com/the5orcerer/LeakyJS</p>
        </div>
    </div>
</body>
</html>
"""

    # Count findings by confidence
    confidence_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in self.results:
        confidence = finding['confidence'].lower()
        confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1
    
    # Generate confidence summary table
    total_findings = len(self.results)
    confidence_rows = []
    for confidence, count in confidence_counts.items():
        if count > 0:
            percentage = (count / total_findings) * 100
            confidence_rows.append(f"<tr><td><span class='confidence {confidence}'>{confidence.upper()}</span></td><td>{count}</td><td>{percentage:.1f}%</td></tr>")
    confidence_summary = "\n".join(confidence_rows)
    
    # Generate findings HTML
    findings_html = []
    for finding in self.results:
        confidence = finding['confidence'].lower()
        context_html = ""
        if finding.get('context'):
            context_html = f"<div class='context'>{finding['context']}</div>"
        
        finding_html = f"""
        <div class="finding {confidence}">
            <div class="pattern-name">{finding['pattern_name']} <span class="confidence {confidence}">{confidence.upper()}</span></div>
            <div class="url"><strong>URL:</strong> {finding['url']}</div>
            <div class="found-code">{finding['finding']}</div>
            {context_html}
        </div>
        """
        findings_html.append(finding_html)
    
    # Get current user and time for report
    import getpass
    import datetime
    username = getpass.getuser()
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Format the HTML report
    html_content = html_template.format(
        scan_date=metadata['scan_date'],
        urls_count=metadata['urls_count'],
        findings_count=metadata['findings_count'],
        scan_time=metadata['scan_time'],
        version=metadata['version'],
        username=username,
        current_time=current_time,
        confidence_summary=confidence_summary,
        findings_html="\n".join(findings_html)
    )
    
    # Write to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

def print_summary(self, start_time: float):
    """Print summary of scan results"""
    if self.args.silent:
        return
        
    elapsed_time = time.time() - start_time
    print(f"\n{Fore.BLUE}[INF]{Style.RESET_ALL} Summary:")
    print(f"Total URLs processed: {len(self.urls)}")
    print(f"Findings: {len(self.results)}")
    print(f"Time taken: {elapsed_time:.2f}s")
    
    if not self.results:
        return
    
    # Findings by pattern
    pattern_counts = {}
    confidence_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
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
    colors = {
        "critical": Fore.MAGENTA + Style.BRIGHT,
        "high": Fore.RED,
        "medium": Fore.YELLOW,
        "low": Fore.GREEN,
        "info": Fore.CYAN
    }
    
    for confidence, count in confidence_counts.items():
        if count > 0:
            print(f"  {colors.get(confidence, '')}{confidence.capitalize()}{Style.RESET_ALL}: {count}")
    
    # Print status code statistics if available
    if hasattr(self.scan_engine, 'scan_stats') and 'status_codes' in self.scan_engine.scan_stats:
        status_codes = self.scan_engine.scan_stats['status_codes']
        if status_codes:
            print(f"\n{Fore.BLUE}[INF]{Style.RESET_ALL} HTTP status codes:")
            for code, count in sorted(status_codes.items()):
                # Color-code based on status code
                if code < 300:
                    color = Fore.GREEN  # 2xx Success
                elif code < 400:
                    color = Fore.BLUE   # 3xx Redirection
                elif code < 500:
                    color = Fore.YELLOW # 4xx Client Error
                else:
                    color = Fore.RED    # 5xx Server Error
                    
                print(f"  {color}{code}{Style.RESET_ALL}: {count}")

def health_check(self):
    """Run health check on all command-line options"""
    self.args.silent = True  # Silence normal output during health check
    print(f"{Fore.BLUE}[INF]{Style.RESET_ALL} Running health check...")
    
    test_flags = [
        # URL Options
        ("--url", ["https://example.com"]),
        ("--url-file", ["urls.txt"]),
        ("--scope", ["example.com,test.com"]),
        ("--exclude", ["example.org,test.org"]),
        ("--scope-domain", []),
        ("--url-filter", ["\.js$"]),
        ("--require-js", []),
        ("--validate-urls", []),
        
        # Spider Options
        ("--spider", []),
        ("--spider-depth", ["2"]),
        ("--spider-timeout", ["30"]),
        ("--max-urls", ["100"]),
        ("--ignore-robots", []),
        ("--only-js-files", []),
        
        # Pattern Options
        ("--regex-file", ["patterns.yaml"]),
        ("--secretfinder", []),
        ("--linkfinder", []),
        ("--custom-pattern", ["test:pattern:low"]),
        ("--pattern-filter", ["api"]),
        ("--create-pattern", ["new_patterns.yaml"]),
        ("--min-confidence", ["medium"]),
        
        # Request Options
        ("--threads", ["10"]),
        ("--timeout", ["15"]),
        ("--user-agent", ["TestBot/1.0"]),
        ("--headers", ['{"X-Test": "Value"}']),
        ("--cookies", ['{"session": "test"}']),
        ("--proxy", ["http://127.0.0.1:8080"]),
        ("--insecure", []),
        ("--follow-redirects", []),
        ("--retry", ["3"]),
        ("--delay", ["1.5"]),
        ("--random-delay", []),
        ("--http2", []),
        ("--method", ["POST"]),
        ("--data", ["test=data"]),
        ("--auth", ["user:pass"]),
        ("--content-type", ["application/json"]),
        ("--jwt-token", ["eyJhbG.eyJzdWIi.SflKxw"]),
        
        # Output Options
        ("--output-dir", ["results"]),
        ("--output-file", ["report"]),
        ("--output-format", ["json"]),
        ("--summary", []),
        ("--silent", []),
        ("--no-color", []),
        ("--progress", []),
        ("--debug", []),
        ("--verbose", []),
        ("--minimal-output", []),
        ("--log-file", ["scan.log"]),
        ("--interactive", []),
        ("--show-system-info", []),
        ("--no-banner", []),
        ("--table-format", ["simple"]),
        
        # Analysis Options
        ("--analyze", []),
        ("--entropy-analysis", []),
        ("--context-lines", ["3"]),
        ("--filter-duplicates", []),
        ("--deobfuscate", []),
        
        # Database Options
        ("--use-db", []),
        ("--db-path", ["custom.db"]),
        ("--db-reset", []),
        
        # Misc Options
        ("--exit-on-error", []),
        ("--health-check", []),
        ("--update", []),
        ("--create-config", ["config.json"]),
        ("--config", ["config.json"]),
        ("--save-responses", []),
        ("--responses-dir", ["raw"]),
        ("--version", []),
        ("--cache", []),
        ("--rate-limit", ["5"]),
    ]
    
    results = []
    for flag, value in test_flags:
        try:
            # Create a temporary test configuration with just this flag
            test_args = ["--url", "https://example.com"]  # Base args for test
            test_args.extend([flag] + value)
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

def run(self):
    """Run the scanner with the configured settings"""
    try:
        # Check for updates if requested
        if self.args.update:
            check_for_updates()
            
        # Create a pattern file if requested
        if self.args.create_pattern:
            self.create_pattern_file()
            return
            
        # Check if patterns are loaded
        if not self.patterns:
            logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} No valid patterns loaded. Exiting.")
            return
        
        # Load URLs
        self.urls = self.scan_engine.load_urls()
        
        # Execute health check if requested
        if self.args.health_check:
            self.health_check()
            return
        
        # Display banner with information
        print_banner(self.args, self.urls)
        
        # Log information about the scan
        logger.debug(f"Loaded {len(self.urls)} URLs, {len(self.patterns)} patterns")
        
        # Spider mode
        if self.args.spider:
            logger.info(f"Spider mode enabled with depth {self.args.spider_depth}")
            # Import and use spider class
            from leakjs_spider import UrlSpider
            spider = UrlSpider(self.scan_engine.session, self.args)
            discovered_urls = spider.spider(self.urls, self.args.spider_depth)
            
            if discovered_urls:
                logger.info(f"Spider discovered {len(discovered_urls)} JavaScript files")
                self.urls = list(discovered_urls)
                
                # Update scan_engine URLs
                self.scan_engine.urls = self.urls
        
        # Start scanning
        start_time = time.time()
        self.results = self.scan_engine.process_urls()
        
        # Show summary if requested
        if self.args.summary:
            self.print_summary(start_time)
            
        # Save results if output file specified
        if self.args.output_file:
            self.save_results()
            
        # Close database connection if used
        if hasattr(self.scan_engine, 'db_manager') and self.scan_engine.db_manager:
            if self.args.db_vacuum:
                logger.info("Optimizing database size...")
                self.scan_engine.db_manager.vacuum()
            self.scan_engine.db_manager.close()
            
    except KeyboardInterrupt:
        logger.error(f"\n{Fore.RED}[ERR]{Style.RESET_ALL} Interrupted by user. Exiting...")
        sys.exit(1)
    except Exception as e:
        logger.error(f"{Fore.RED}[ERR]{Style.RESET_ALL} Error during run: {str(e)}")
        if self.args.debug:
            import traceback
            traceback.print_exc()
        if self.args.exit_on_error:
            sys.exit(1)

def main():
    """Main entry point for LeakJS"""
    try:
        # Parse command line arguments
        args = parse_args()
        
        # Setup logging
        if args.debug:
            logger.setLevel(logging.DEBUG)
        
        # Configure output directory
        if args.output_file and args.output_dir:
            os.makedirs(args.output_dir, exist_ok=True)
            
        # Load config from file if specified
        if args.config:
            if os.path.exists(args.config):
                try:
                    with open(args.config, 'r', encoding='utf-8') as f:
                        config = json.load(f)
                        
                    # Override args with config file values
                    for key, value in config.items():
                        if hasattr(args, key) and getattr(args, key) is None:
                            setattr(args, key, value)
                except Exception as e:
                    logger.error(f"Error loading config file: {str(e)}")
            else:
                logger.error(f"Config file not found: {args.config}")
                
        # Initialize scanner
        scanner = LeakJS(args)
        
        # Set a maximum runtime if specified
        if args.max_time:
            def timeout_handler(signum, frame):
                logger.error(f"\n{Fore.RED}[ERR]{Style.RESET_ALL} Maximum runtime reached ({args.max_time}s). Exiting...")
                sys.exit(0)
                
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(args.max_time)
            
        # Save config if requested
        if args.create_config:
            try:
                config = {k: v for k, v in vars(args).items() if v is not None and k != 'create_config'}
                with open(args.create_config, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2)
                logger.info(f"Configuration saved to: {args.create_config}")
            except Exception as e:
                logger.error(f"Error saving configuration: {str(e)}")
                
        # Run the scanner
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
    # Set fixed values for report generation
    os.environ['USER'] = "the5orcerer"  # Set username for reports
    os.environ['CURRENT_TIME'] = "2025-03-14 19:13:52"  # Set fixed time for reports
    
    # Run the main function
    main()
