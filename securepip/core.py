#!/usr/bin/env python3

import os
import sys
import json
import requests
import subprocess
import re
import time
import threading
import warnings
from typing import List, Dict, Optional, Set
import yaml
from tqdm import tqdm
from colorama import init, Fore, Style
import packaging.version
import pip._internal.cli.main as pip_main
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from datetime import datetime
from pathlib import Path
import hashlib
import tempfile

# Suppress urllib3 warnings
warnings.filterwarnings('ignore', category=Warning, module='urllib3')

init(autoreset=True)

@dataclass
class AnalysisStats:
    total_packages: int = 0
    analyzed_packages: int = 0
    vulnerable_packages: int = 0
    typosquatting_detected: int = 0
    packages_not_found: int = 0
    security_issues: int = 0
    malware: int = 0
    privilege_escalation: int = 0
    embedded_code: int = 0
    by_severity: defaultdict = field(default_factory=lambda: defaultdict(int))
    current_package: str = ""
    current_chain: str = ""
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime = field(default_factory=datetime.now)

class SecurePip:
    def __init__(self, no_cache: bool = False, generate_report: bool = False, model: Optional[str] = None, report_dir: Optional[str] = None):
        """Initialize SecurePip with configuration options."""
        self.no_cache = no_cache
        self.generate_report = generate_report
        self.session = requests.Session()
        self.cache_dir = os.path.expanduser("~/.securepip/cache")
        self.reports_dir = Path(report_dir) if report_dir else Path.cwd() / "reports"
        self.dependency_chain = []
        self.max_dependency_depth = 5  # Maximum depth for dependency analysis
        self.analyzed_packages = set()  # Track analyzed packages to prevent cycles
        self.stats = {
            "analyzed": 0,
            "vulnerable": 0,
            "typosquatting": 0,
            "malware": 0,
            "privilege_escalation": 0,
            "embedded_code": 0,
            "security_issues": 0,
            "severity_breakdown": {"low": 0, "medium": 0, "high": 0, "critical": 0}
        }
        
        # Initialize report data
        self.report_data = {
            "packages": [],
            "summary": {
                "total_packages": 0,
                "vulnerable_packages": 0,
                "security_issues": 0,
                "malware_detected": 0,
                "privilege_escalation": 0,
                "embedded_code": 0,
                "typosquatting_detected": 0,
                "packages_not_found": 0
            }
        }
        
        # Initialize Ollama endpoint
        self.ollama_endpoint = "http://localhost:11434/api/generate"
        
        # Check Ollama availability
        if not self._check_ollama_availability():
            raise RuntimeError(
                "Ollama is not available. This tool requires AI analysis for comprehensive security checks.\n"
                "Please install Ollama and ensure it's running (http://localhost:11434).\n"
                "Supported models: gemma3:12b, deepseek-r1:14b, llama3.2:latest, gemma:3b, llama2:7b"
            )
        
        # Set model
        self.model = model or self._select_ollama_model()
        self.ollama_available = self._check_ollama_availability()
        
        self.known_malicious_packages = set()
        self.known_typosquatting = set()
        self.stats = AnalysisStats()
        self.progress_bar = None
        
        # Initialize cache
        self.cache_dir = Path.home() / ".secure_pip_cache"
        self.cache_dir.mkdir(exist_ok=True)
        self.cache_file = self.cache_dir / "analysis_cache.json"
        self.cache = self._load_cache()
        
        # Configure requests session with retry logic
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Rate limiting
        self._rate_limit_lock = threading.Lock()
        self._last_request_time = {}
        self._min_request_interval = 1.0  # seconds
        
        # Get pip path
        try:
            self.pip_path = subprocess.check_output(['which', 'pip']).decode().strip()
        except subprocess.CalledProcessError:
            try:
                self.pip_path = subprocess.check_output(['which', 'pip3']).decode().strip()
            except subprocess.CalledProcessError:
                self.pip_path = 'pip'  # Fallback to just 'pip'

        self.debug_log = []  # Store debug information
        self.package_versions = {}  # Track package versions to detect version conflicts

    def _select_ollama_model(self) -> str:
        """Select the best available Ollama model for analysis."""
        try:
            response = self.session.get("http://localhost:11434/api/tags")
            if response.status_code == 200:
                models = response.json().get("models", [])
                # Check for newer model versions first
                if any("gemma3" in model["name"] for model in models):
                    return "gemma3:12b"
                elif any("deepseek" in model["name"] for model in models):
                    return "deepseek-r1:14b"
                elif any("llama3" in model["name"] for model in models):
                    return "llama3.2:latest"
                # Fallback to older versions
                elif any("gemma" in model["name"] for model in models):
                    return "gemma:3b"
                elif any("llama2" in model["name"] for model in models):
                    return "llama2:7b"
        except Exception:
            pass
        # If no models found or error, use the most capable default
        return "gemma3:12b"

    def _check_ollama_availability(self) -> bool:
        """Check if Ollama is available and running."""
        try:
            response = self.session.get("http://localhost:11434/api/tags", timeout=5)
            return response.status_code == 200
        except Exception:
            self._log_warning("Ollama is not available. Some security checks will be skipped.")
            return False

    def _load_cache(self) -> Dict:
        """Load analysis cache from file."""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Failed to load cache: {str(e)}{Style.RESET_ALL}")
        return {}

    def _save_cache(self):
        """Save analysis cache to file."""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Failed to save cache: {str(e)}{Style.RESET_ALL}")

    def _check_nvd_database(self, package_name: str, version: Optional[str]) -> List[Dict]:
        """Check NVD Database for vulnerabilities."""
        try:
            # Format package name for NVD search
            search_term = f"{package_name} {version}" if version else package_name
            
            # Make request to NVD API
            response = self.session.get(
                f"https://services.nvd.nist.gov/rest/json/cves/1.0",
                params={"keyword": search_term},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = []
                
                for item in data.get("result", {}).get("CVE_Items", []):
                    cve = item["cve"]
                    description = cve["description"]["description_data"][0]["value"]
                    
                    # Extract severity if available
                    severity = "unknown"
                    if "baseMetricV3" in item["impact"]:
                        severity = item["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"].lower()
                    elif "baseMetricV2" in item["impact"]:
                        severity = item["impact"]["baseMetricV2"]["severity"].lower()
                    
                    vulnerabilities.append({
                        "id": cve["CVE_data_meta"]["ID"],
                        "description": description,
                        "severity": severity,
                        "source": "NVD"
                    })
                
                return vulnerabilities
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Failed to check NVD database: {str(e)}{Style.RESET_ALL}")
        
        return []

    def _analyze_code_with_ollama(self, package_name: str, version: Optional[str] = None) -> Dict:
        """Analyze package code using Ollama/Gemma."""
        if not self.ollama_available:
            raise RuntimeError("Ollama is not available. AI analysis is required for code security checks.")
        
        try:
            # Download package source
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # First try to find the package in the installed packages
                try:
                    result = subprocess.run(
                        ["pip", "show", package_name],
                        capture_output=True,
                        text=True
                    )
                    if result.returncode == 0:
                        # Package is installed, get its location
                        location = None
                        for line in result.stdout.split('\n'):
                            if line.startswith('Location:'):
                                location = line.split(':', 1)[1].strip()
                                break
                        
                        if location:
                            package_dir = Path(location) / package_name
                            if package_dir.exists():
                                self._log_info(f"Using installed package at {package_dir}")
                                code_files = list(package_dir.rglob("*.py"))
                                if code_files:
                                    return self._analyze_code_files(code_files, package_dir)
                except Exception as e:
                    self._log_warning(f"Failed to check installed package: {str(e)}")
                
                # If not found in installed packages, try to download
                try:
                    subprocess.run(
                        ["pip", "download", "--no-deps", package_name, "-d", str(temp_path)],
                        capture_output=True,
                        check=True
                    )
                except subprocess.CalledProcessError as e:
                    self._log_warning(f"Failed to download package {package_name}: {e.stderr.decode()}")
                    return {"error": f"Failed to download package: {e.stderr.decode()}"}
                
                # Find downloaded package
                package_files = list(temp_path.glob(f"{package_name}*.tar.gz"))
                if not package_files:
                    self._log_warning(f"No package file found for {package_name}")
                    return {"error": "No package file found"}
                
                package_file = package_files[0]
                
                # Extract package
                try:
                    subprocess.run(["tar", "-xf", str(package_file), "-C", str(temp_path)], check=True)
                except subprocess.CalledProcessError as e:
                    self._log_warning(f"Failed to extract package {package_name}: {str(e)}")
                    return {"error": f"Failed to extract package: {str(e)}"}
                
                # Get package code
                package_dir = next(temp_path.glob(f"{package_name}*"))
                code_files = list(package_dir.rglob("*.py"))
                
                if not code_files:
                    return {"error": "No Python files found in package"}
                
                return self._analyze_code_files(code_files, package_dir)
                
        except Exception as e:
            self._log_error(f"Failed to analyze code: {str(e)}")
            return {"error": f"Failed to analyze code: {str(e)}"}

    def _analyze_code_files(self, code_files: List[Path], package_dir: Path) -> Dict:
        """Analyze a list of code files."""
        security_issues = []
        for file in code_files:
            with open(file, 'r') as f:
                code = f.read()
            
            # Prepare detailed prompt for Ollama
            prompt = f"""
            Perform a comprehensive security analysis of this Python code:
            {code}
            
            Check for:
            1. Malicious code patterns
            2. Arbitrary code execution (eval, exec, pickle.loads)
            3. Network connections and data exfiltration
            4. File system operations and path traversal
            5. Process manipulation and privilege escalation
            6. Environment variable manipulation
            7. Cryptographic weaknesses
            8. Input validation issues
            9. Memory management problems
            10. Race conditions
            11. Hardcoded credentials
            12. Insecure dependencies
            13. Obfuscated code
            14. Backdoors and rootkits
            15. Data leakage
            
            Return a JSON object with:
            - security_issues: List of security issues found
            - severity: Critical/High/Medium/Low
            - line_numbers: List of affected lines
            - description: Detailed explanation
            - recommendations: List of fixes
            - confidence: Float between 0 and 1
            """
            
            result = self._make_ollama_request(prompt)
            if not result:
                continue
                
            try:
                analysis = json.loads(result.get("response", "{}"))
                if analysis.get("security_issues"):
                    # Add file information to each issue
                    for issue in analysis["security_issues"]:
                        issue["file"] = str(file.relative_to(package_dir))
                    security_issues.extend(analysis["security_issues"])
            except json.JSONDecodeError:
                self._log_error(f"Failed to parse AI analysis for {file}")
        
        return {
            "security_issues": security_issues,
            "files_analyzed": len(code_files),
            "total_lines_analyzed": sum(1 for f in code_files for _ in open(f))
        }

    def _manage_ollama(self) -> bool:
        """Manage Ollama state and ensure it's available."""
        max_retries = 3
        retry_delay = 5  # seconds
        
        for attempt in range(max_retries):
            try:
                # Check if Ollama is running
                response = self.session.get("http://localhost:11434/api/tags", timeout=5)
                if response.status_code == 200:
                    return True
            except Exception:
                self._log_warning(f"Ollama not responding, attempt {attempt + 1}/{max_retries}")
                
                # Try to restart Ollama
                try:
                    self._log_info("Attempting to restart Ollama...")
                    subprocess.run(["ollama", "serve"], check=True)
                    time.sleep(retry_delay)  # Wait for Ollama to start
                except Exception as e:
                    self._log_warning(f"Failed to restart Ollama: {str(e)}")
                    time.sleep(retry_delay)
                    
        self._log_warning("Ollama is not available after multiple attempts")
        return False

    def _make_ollama_request(self, prompt: str, timeout: int = 30) -> Optional[Dict]:
        """Make a request to Ollama with retry logic."""
        max_retries = 3
        retry_delay = 5  # seconds
        
        for attempt in range(max_retries):
            try:
                # Ensure Ollama is available
                if not self._manage_ollama():
                    self._log_error("Ollama is not available after management attempt")
                    return None
                    
                self._log_debug(f"Making Ollama request (attempt {attempt + 1}/{max_retries})")
                
                # Prepare the request
                request_data = {
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False
                }
                
                self._log_debug(f"Request data: {json.dumps(request_data, indent=2)}")
                
                # Make the request
                response = self.session.post(
                    self.ollama_endpoint,
                    json=request_data,
                    timeout=timeout
                )
                
                self._log_debug(f"Response status: {response.status_code}")
                
                if response.status_code == 200:
                    try:
                        result = response.json()
                        self._log_debug(f"Response data: {json.dumps(result, indent=2)}")
                        return result
                    except json.JSONDecodeError as e:
                        self._log_error(f"Failed to parse Ollama response: {str(e)}")
                        self._log_debug(f"Raw response: {response.text}")
                        return None
                else:
                    self._log_error(f"Ollama request failed with status {response.status_code}")
                    self._log_debug(f"Response: {response.text}")
                    
            except requests.exceptions.ReadTimeout:
                self._log_warning(f"Ollama request timed out, attempt {attempt + 1}/{max_retries}")
                time.sleep(retry_delay)
            except requests.exceptions.ConnectionError as e:
                self._log_error(f"Connection error during Ollama request: {str(e)}")
                time.sleep(retry_delay)
            except Exception as e:
                self._log_error(f"Unexpected error during Ollama request: {str(e)}")
                self._log_debug(f"Error type: {type(e).__name__}")
                time.sleep(retry_delay)
                
        self._log_error("All Ollama request attempts failed")
        return None

    def _check_typosquatting(self, package_name: str) -> bool:
        """Check for potential typosquatting using Ollama/Gemma."""
        if not self.ollama_available:
            return False
            
        try:
            # Prepare prompt for Ollama
            prompt = f"""
            Analyze this Python package name for potential typosquatting:
            {package_name}
            
            Return a JSON object with:
            - is_typosquatting: boolean
            - confidence: float between 0 and 1
            - potential_targets: list of similar package names
            - explanation: string explaining the analysis
            """
            
            result = self._make_ollama_request(prompt)
            if not result:
                return False
                
            try:
                analysis = json.loads(result.get("response", "{}"))
                if analysis.get("is_typosquatting", False):
                    self._log_warning("Potential typosquatting detected")
                    return True
            except json.JSONDecodeError:
                pass
                
            return False
                
        except Exception as e:
            self._log_warning(f"Failed to analyze typosquatting: {str(e)}")
            return False

    def _update_report_data(self, analysis_result: Dict):
        """Update report data with analysis results."""
        if not self.generate_report:
            return
            
        # Update package data
        package_data = {
            "name": analysis_result.get("package_name", "Unknown"),
            "version": analysis_result.get("version"),
            "requested_by": analysis_result.get("requested_by", "direct"),
            "vulnerabilities": analysis_result.get("vulnerabilities", []),
            "dependencies": analysis_result.get("dependencies", []),
            "error": analysis_result.get("error")
        }
        
        # Add security analysis results
        if analysis_result.get("typosquatting_detected"):
            package_data.update({
                "typosquatting_detected": True,
                "typosquatting_confidence": analysis_result.get("typosquatting_confidence"),
                "potential_targets": analysis_result.get("potential_targets", []),
                "typosquatting_explanation": analysis_result.get("typosquatting_explanation")
            })
            self.report_data["summary"]["typosquatting_detected"] += 1
        
        if analysis_result.get("malware_analysis", {}).get("detected"):
            package_data["malware_analysis"] = analysis_result["malware_analysis"]
            self.report_data["summary"]["malware_detected"] += 1
        
        if analysis_result.get("privilege_analysis", {}).get("detected"):
            package_data["privilege_analysis"] = analysis_result["privilege_analysis"]
            self.report_data["summary"]["privilege_escalation"] += 1
        
        if analysis_result.get("embedded_code_analysis", {}).get("detected"):
            package_data["embedded_code_analysis"] = analysis_result["embedded_code_analysis"]
            self.report_data["summary"]["embedded_code"] += 1
        
        # Update summary statistics
        self.report_data["summary"]["total_packages"] += 1
        if analysis_result.get("vulnerabilities"):
            self.report_data["summary"]["vulnerable_packages"] += 1
            self.report_data["summary"]["security_issues"] += len(analysis_result["vulnerabilities"])
        if analysis_result.get("error") == "Package not found on PyPI":
            self.report_data["summary"]["packages_not_found"] += 1
        
        # Add package to report data
        self.report_data["packages"].append(package_data)

    def _format_dependency_chain(self, chain: List[Dict]) -> str:
        """Format dependency chain for display."""
        formatted_chain = []
        for dep in chain:
            package_str = dep['package']
            if dep.get('version'):
                package_str += f" ({dep['version']})"
            formatted_chain.append(package_str)
        return " -> ".join(formatted_chain)

    def _update_progress(self):
        """Update and display progress information."""
        if self.progress_bar is None:
            self.progress_bar = tqdm(
                total=self.stats.total_packages,
                desc="Analyzing packages",
                bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]'
            )
            
        # Calculate progress percentage
        progress = (self.stats.analyzed_packages / max(1, self.stats.total_packages)) * 100
        
        # Update progress bar description
        desc = f"Analyzing: {self.stats.current_package}"
        if self.stats.current_chain:
            # Truncate long dependency chains
            chain = self.stats.current_chain
            if len(chain) > 50:
                chain = chain[:47] + "..."
            desc += f" ({chain})"
        
        self.progress_bar.set_description(desc)
        self.progress_bar.n = self.stats.analyzed_packages
        self.progress_bar.refresh()
        
        # Print summary every 10 packages or when progress is complete
        if self.stats.analyzed_packages % 10 == 0 or self.stats.analyzed_packages == self.stats.total_packages:
            self._print_summary()

    def _print_summary(self):
        """Print current analysis summary."""
        print(f"\n{Fore.CYAN}Analysis Summary:{Style.RESET_ALL}")
        print(f"Progress: {self.stats.analyzed_packages}/{self.stats.total_packages} packages ({self.stats.analyzed_packages/max(1, self.stats.total_packages)*100:.1f}%)")
        print(f"Current Package: {self.stats.current_package}")
        if self.stats.current_chain:
            # Truncate long dependency chains
            chain = self.stats.current_chain
            if len(chain) > 50:
                chain = chain[:47] + "..."
            print(f"Dependency Chain: {chain}")
        print(f"Vulnerable Packages: {self.stats.vulnerable_packages}")
        print(f"Security Issues: {self.stats.security_issues}")
        print(f"Typosquatting Detected: {self.stats.typosquatting_detected}")
        print(f"Packages Not Found: {self.stats.packages_not_found}")
        print("Severity Breakdown:")
        for severity, count in self.stats.by_severity.items():
            print(f"  {severity}: {count}")
        print("-" * 50)

    def install_package(self, package_name: str, version: Optional[str] = None) -> bool:
        """Install a package after security analysis."""
        # Initialize progress bar
        self.progress_bar = tqdm(total=1, desc="Initializing analysis...")
        
        analysis = self.analyze_package(package_name, version)
        
        if "error" in analysis:
            print(f"{Fore.YELLOW}Warning: {analysis['error']}{Style.RESET_ALL}")
            if not self.force:
                response = input(f"\n{Fore.YELLOW}Do you want to proceed with installation despite the warning? (y/n): {Style.RESET_ALL}")
                if response.lower() != 'y':
                    print(f"{Fore.RED}Installation aborted{Style.RESET_ALL}")
                    return False
        
        # Check for security issues
        has_issues = (
            analysis.get("vulnerabilities", []) or
            analysis.get("code_analysis", {}).get("security_issues", [])
        )
        
        if has_issues:
            print(f"\n{Fore.YELLOW}Security issues detected:{Style.RESET_ALL}")
            for issue in analysis.get("vulnerabilities", []):
                print(f"- {issue}")
            for issue in analysis.get("code_analysis", {}).get("security_issues", []):
                print(f"- {issue}")
            
            if not self.force:
                response = input(f"\n{Fore.YELLOW}Do you want to proceed with installation? (y/n): {Style.RESET_ALL}")
                if response.lower() != 'y':
                    print(f"{Fore.RED}Installation aborted{Style.RESET_ALL}")
                    return False
        
        # Proceed with installation
        print(f"\n{Fore.GREEN}Proceeding with installation...{Style.RESET_ALL}")
        try:
            if version:
                pip_main.main(["install", f"{package_name}=={version}"])
            else:
                pip_main.main(["install", package_name])
            print(f"{Fore.GREEN}Installation completed successfully{Style.RESET_ALL}")
            
            # Print final summary
            self._print_summary()
            return True
        except Exception as e:
            print(f"{Fore.RED}Installation failed: {str(e)}{Style.RESET_ALL}")
            return False

    def _log_error(self, message: str, error: Optional[Exception] = None) -> None:
        """Log an error message with line number and traceback if available."""
        import traceback
        import inspect
        import sys
        
        # Get the current frame
        frame = inspect.currentframe()
        # Get the caller's frame (2 levels up)
        caller_frame = frame.f_back.f_back if frame and frame.f_back else None
        line_no = caller_frame.f_lineno if caller_frame else "unknown"
        file_name = caller_frame.f_code.co_filename if caller_frame else "unknown"
        
        # Format the error message
        error_msg = f"{Fore.RED}Error in {file_name}:{line_no} - {message}{Style.RESET_ALL}"
        if error:
            error_msg += f"\n{Fore.YELLOW}Details: {str(error)}{Style.RESET_ALL}"
            error_msg += f"\n{Fore.YELLOW}Traceback:\n{traceback.format_exc()}{Style.RESET_ALL}"
        
        print(error_msg, file=sys.stderr)

    def _log_warning(self, message: str) -> None:
        """Log a warning message with line number."""
        import inspect
        import sys
        
        # Get the current frame
        frame = inspect.currentframe()
        # Get the caller's frame (2 levels up)
        caller_frame = frame.f_back.f_back if frame and frame.f_back else None
        line_no = caller_frame.f_lineno if caller_frame else "unknown"
        file_name = caller_frame.f_code.co_filename if caller_frame else "unknown"
        
        print(f"{Fore.YELLOW}Warning in {file_name}:{line_no} - {message}{Style.RESET_ALL}", file=sys.stderr)

    def _log_info(self, message: str) -> None:
        """Log an info message with line number."""
        import inspect
        import sys
        
        # Get the current frame
        frame = inspect.currentframe()
        # Get the caller's frame (2 levels up)
        caller_frame = frame.f_back.f_back if frame and frame.f_back else None
        line_no = caller_frame.f_lineno if caller_frame else "unknown"
        file_name = caller_frame.f_code.co_filename if caller_frame else "unknown"
        
        print(f"{Fore.CYAN}Info in {file_name}:{line_no} - {message}{Style.RESET_ALL}", file=sys.stdout)

    def _log_debug(self, message: str) -> None:
        """Log a debug message with dependency chain information."""
        import inspect
        import sys
        
        # Get the current frame
        frame = inspect.currentframe()
        # Get the caller's frame (2 levels up)
        caller_frame = frame.f_back.f_back if frame and frame.f_back else None
        line_no = caller_frame.f_lineno if caller_frame else "unknown"
        file_name = caller_frame.f_code.co_filename if caller_frame else "unknown"
        
        # Format the debug message with chain info
        chain_info = " -> ".join([f"{dep['package']}({dep.get('version', '')})" for dep in self.dependency_chain])
        debug_msg = f"{Fore.CYAN}Debug in {file_name}:{line_no} - {message}{Style.RESET_ALL}\nChain: {chain_info}\nDepth: {len(self.dependency_chain)}"
        
        # Store in debug log
        self.debug_log.append(debug_msg)
        
        # Print to stderr
        print(debug_msg, file=sys.stderr)

    def analyze_package(self, package_name: str, version: Optional[str] = None, requested_by: Optional[str] = None) -> Dict:
        """Analyze a package for security issues."""
        try:
            # Log entry to package analysis
            self._log_debug(f"Starting analysis for {package_name} {version if version else ''}")
            
            # Parse package name and version if version constraint is included
            if '>=' in package_name or '<=' in package_name or '==' in package_name or '!=' in package_name:
                parts = re.split(r'(>=|<=|==|!=)', package_name, 1)
                if len(parts) == 3:
                    package_name, op, version = parts
                    package_name = package_name.strip()
                    version = f"{op}{version.strip()}"
                else:
                    # Handle simple version constraints
                    parts = re.split(r'(<|>)', package_name, 1)
                    if len(parts) == 3:
                        package_name, op, version = parts
                        package_name = package_name.strip()
                        version = f"{op}{version.strip()}"

            # Check cache first
            cached_analysis = self._get_cached_analysis(package_name, version)
            if cached_analysis:
                self._log_debug(f"Using cached analysis for {package_name}")
                # Update requested_by in cached analysis
                cached_analysis['requested_by'] = requested_by
                # Update report data with cached analysis
                self._update_report_data(cached_analysis)
                return cached_analysis

            # Update stats
            self.stats.total_packages = max(self.stats.total_packages, len(self.analyzed_packages) + 1)
            self.stats.current_package = package_name
            self.stats.current_chain = self._format_dependency_chain(self.dependency_chain)
            
            # Track dependency chain
            current_dep = {
                "package": package_name,
                "version": version,
                "requested_by": requested_by
            }
            self.dependency_chain.append(current_dep)
            
            # Skip if already analyzed in this session
            package_key = f"{package_name}:{version}" if version else package_name
            if package_key in self.analyzed_packages:
                self._log_debug(f"Skipping already analyzed package: {package_key}")
                self.stats.analyzed_packages += 1
                self._update_progress()
                result = {"package_name": package_name, "version": version, "status": "already_analyzed"}
                self._update_report_data(result)
                return result
            
            self.analyzed_packages.add(package_key)
            
            # Show dependency chain
            chain_str = self._format_dependency_chain(self.dependency_chain)
            self._log_info(f"Analyzing package: {chain_str}")
            
            # Get package metadata from PyPI
            try:
                self._log_debug(f"Fetching PyPI metadata for {package_name}")
                response = self.session.get(f"https://pypi.org/pypi/{package_name}/json", timeout=10)
                if response.status_code != 200:
                    self._log_warning(f"Package {package_name} not found on PyPI")
                    self.stats.packages_not_found += 1
                    
                    # Try to resolve the package using pip
                    try:
                        self._log_info("Attempting to resolve package using pip...")
                        result = subprocess.run(
                            [self.pip_path, "download", "--no-deps", package_name],
                            capture_output=True,
                            text=True
                        )
                        if result.returncode == 0:
                            self._log_info("Package resolved successfully")
                        else:
                            self._log_error("Failed to resolve package", Exception(result.stderr))
                    except Exception as e:
                        self._log_error("Error resolving package", e)
                    
                    self.stats.analyzed_packages += 1
                    self._update_progress()
                    result = {
                        "package_name": package_name,
                        "version": version,
                        "error": "Package not found on PyPI",
                        "requested_by": requested_by
                    }
                    self._update_report_data(result)
                    return result
                
                package_data = response.json()
                
                # Check for typosquatting
                self._log_debug(f"Checking typosquatting for {package_name}")
                typosquatting_result = self._check_typosquatting(package_name)
                
                # Analyze dependencies
                self._log_debug(f"Analyzing dependencies for {package_name}")
                dependencies = self._analyze_dependencies(package_data, package_name)
                
                # Check for known vulnerabilities
                self._log_debug(f"Checking vulnerabilities for {package_name}")
                vulnerabilities = self._check_vulnerabilities(package_name, version)
                if vulnerabilities:
                    self.stats.vulnerable_packages += 1
                    self.stats.security_issues += len(vulnerabilities)
                    for vuln in vulnerabilities:
                        self.stats.by_severity[vuln.get("severity", "unknown")] += 1
                
                # Analyze package code using Ollama
                self._log_debug(f"Analyzing code for {package_name}")
                code_analysis = self._analyze_code_with_ollama(package_name, version)
                
                # Remove current package from dependency chain
                self.dependency_chain.pop()
                
                # Add new security checks
                self._log_debug(f"Running additional security checks for {package_name}")
                malware_analysis = self._check_malware(package_name, version)
                privilege_analysis = self._check_privilege_escalation(package_name, version)
                embedded_code_analysis = self._check_embedded_code(package_name, version)
                
                # Update stats based on new checks
                if malware_analysis["detected"]:
                    self.stats.security_issues += 1
                    self.stats.by_severity["malware"] = self.stats.by_severity.get("malware", 0) + 1
                
                if privilege_analysis["detected"]:
                    self.stats.security_issues += 1
                    self.stats.by_severity["privilege_escalation"] = self.stats.by_severity.get("privilege_escalation", 0) + 1
                
                if embedded_code_analysis["detected"]:
                    self.stats.security_issues += 1
                    self.stats.by_severity["embedded_code"] = self.stats.by_severity.get("embedded_code", 0) + 1
                
                # Create analysis result with new checks
                analysis_result = {
                    "package_name": package_name,
                    "version": version,
                    "dependencies": dependencies,
                    "vulnerabilities": vulnerabilities,
                    "code_analysis": code_analysis,
                    "malware_analysis": malware_analysis,
                    "privilege_analysis": privilege_analysis,
                    "embedded_code_analysis": embedded_code_analysis,
                    "typosquatting_detected": typosquatting_result,
                    "requested_by": requested_by
                }
                
                # Cache the analysis result
                self._cache_analysis(package_name, version, analysis_result)
                
                # Update report data
                self._update_report_data(analysis_result)
                
                self.stats.analyzed_packages += 1
                self._update_progress()
                
                return analysis_result
                
            except Exception as e:
                self._log_error("Error during package analysis", e)
                # Remove current package from dependency chain
                self.dependency_chain.pop()
                
                self.stats.analyzed_packages += 1
                self._update_progress()
                
                result = {
                    "package_name": package_name,
                    "version": version,
                    "error": str(e),
                    "requested_by": requested_by
                }
                self._update_report_data(result)
                return result
        except Exception as e:
            self._log_error("Critical error in analyze_package", e)
            raise

    def _get_cache_key(self, package_name: str, version: Optional[str] = None) -> str:
        """Generate a cache key for a package."""
        key = f"{package_name}:{version if version else 'latest'}"
        return hashlib.md5(key.encode()).hexdigest()

    def _get_cached_analysis(self, package_name: str, version: Optional[str] = None) -> Optional[Dict]:
        """Get cached analysis result if available and not expired."""
        if self.no_cache:
            return None
            
        cache_key = self._get_cache_key(package_name, version)
        if cache_key in self.cache:
            cached_data = self.cache[cache_key]
            # Check if cache is expired (7 days)
            if time.time() - cached_data.get('timestamp', 0) < 7 * 24 * 60 * 60:
                print(f"{Fore.CYAN}Using cached analysis for {package_name}{Style.RESET_ALL}")
                return cached_data['analysis']
            else:
                del self.cache[cache_key]
                self._save_cache()
        return None

    def _cache_analysis(self, package_name: str, version: Optional[str], analysis: Dict):
        """Cache analysis result."""
        if self.no_cache:
            return
            
        cache_key = self._get_cache_key(package_name, version)
        self.cache[cache_key] = {
            'timestamp': time.time(),
            'analysis': analysis
        }
        self._save_cache()

    def _check_vulnerabilities(self, package_name: str, version: Optional[str] = None) -> List[Dict]:
        """Check for known vulnerabilities in a package."""
        vulnerabilities = []
        
        # Check NVD database
        nvd_vulnerabilities = self._check_nvd_database(package_name, version)
        vulnerabilities.extend(nvd_vulnerabilities)
        
        # Check known malicious packages
        if package_name in self.known_malicious_packages:
            vulnerabilities.append({
                "id": "MALICIOUS",
                "description": "Package is known to be malicious",
                "severity": "critical",
                "source": "Known Malicious Packages"
            })
        
        return vulnerabilities

    def _detect_cycle(self, package_name: str, version: Optional[str] = None) -> bool:
        """Detect if adding this package would create a cycle in the dependency chain."""
        package_key = f"{package_name}:{version}" if version else package_name
        
        # Check if this package is already in the chain
        for dep in self.dependency_chain:
            if dep['package'] == package_name:
                # If versions are specified, check if they're compatible
                if version and dep.get('version'):
                    try:
                        # Parse versions
                        from packaging.requirements import Requirement
                        req1 = Requirement(f"{package_name}{version}")
                        req2 = Requirement(f"{package_name}{dep['version']}")
                        
                        # Check if versions are compatible
                        if not (req1.specifier.contains(req2.specifier) or req2.specifier.contains(req1.specifier)):
                            self._log_debug(f"Version conflict detected: {package_name} {version} vs {dep['version']}")
                            return True
                    except Exception:
                        pass
                return True
        return False

    def _analyze_dependencies(self, package_data: Dict, parent_package: str) -> List[Dict]:
        """Analyze package dependencies with cycle detection."""
        dependencies = []
        
        # Log entry to dependency analysis
        self._log_debug(f"Starting dependency analysis for {parent_package}")
        
        # Check if package_data is valid
        if not package_data or not isinstance(package_data, dict):
            self._log_warning(f"Invalid package data for {parent_package}")
            return dependencies
            
        # Check if info and requires_dist exist
        if "info" not in package_data:
            self._log_warning(f"No package info found for {parent_package}")
            return dependencies
            
        info = package_data["info"]
        if not isinstance(info, dict):
            self._log_warning(f"Invalid package info for {parent_package}")
            return dependencies
            
        requires_dist = info.get("requires_dist")
        if not requires_dist:
            self._log_info(f"No dependencies found for {parent_package}")
            return dependencies
            
        if not isinstance(requires_dist, list):
            self._log_warning(f"Invalid requires_dist format for {parent_package}")
            return dependencies
            
        # Process dependencies
        for dep in requires_dist:
            if not isinstance(dep, str):
                continue
                
            dep_name, dep_version = self._resolve_package_name(dep)
            if dep_name:
                try:
                    # Remove any extras for PyPI lookup
                    base_name = dep_name.split('[')[0].strip()
                    
                    # Skip if already analyzed to prevent cycles
                    dep_key = f"{base_name}:{dep_version}" if dep_version else base_name
                    if dep_key in self.analyzed_packages:
                        self._log_debug(f"Skipping already analyzed dependency: {dep_key}")
                        continue
                        
                    # Check for cycles
                    if self._detect_cycle(base_name, dep_version):
                        self._log_warning(f"Cycle detected in dependency chain for {base_name}")
                        continue
                        
                    self._log_debug(f"Analyzing dependency: {base_name} {dep_version if dep_version else ''}")
                    dep_analysis = self.analyze_package(base_name, dep_version, requested_by=parent_package)
                    if dep_analysis:
                        dependencies.append(dep_analysis)
                except Exception as e:
                    self._log_warning(f"Warning during dependency analysis for {dep_name}: {str(e)}")
                    continue
                    
        return dependencies

    def _resolve_package_name(self, dep_string: str) -> tuple[str, Optional[str]]:
        """Resolve package name and version from dependency string."""
        # Remove any environment markers
        dep_string = dep_string.split(';')[0].strip()
        
        # Handle extras (e.g., package[extra]>=1.0)
        if '[' in dep_string:
            base_name = dep_string.split('[')[0].strip()
            extras = dep_string[dep_string.find('['):dep_string.find(']')+1]
            dep_string = base_name + extras
        
        # Handle version constraints
        if '(' in dep_string:
            name, version = dep_string.split('(', 1)
            version = version.rstrip(')').strip()
            return name.strip(), version
        elif '>=' in dep_string or '<=' in dep_string or '==' in dep_string or '!=' in dep_string:
            # Split on the first operator
            parts = re.split(r'(>=|<=|==|!=)', dep_string, 1)
            if len(parts) == 3:
                name, op, version = parts
                return name.strip(), f"{op}{version.strip()}"
        elif '~=' in dep_string:
            # Handle compatible release operator
            name, version = dep_string.split('~=', 1)
            return name.strip(), f"~={version.strip()}"
        elif '<' in dep_string or '>' in dep_string:
            # Handle simple version constraints
            parts = re.split(r'(<|>)', dep_string, 1)
            if len(parts) == 3:
                name, op, version = parts
                # Remove any trailing commas
                name = name.rstrip(',').strip()
                version = version.rstrip(',').strip()
                return name, f"{op}{version}"
        
        # If no version constraint, return just the name
        return dep_string.strip(), None

    def generate_report(self, analysis_result: Dict) -> str:
        """Generate a report for the analysis result."""
        if not self.generate_report:
            return ""
            
        # Create reports directory in current working directory
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate timestamp for report files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Generate report filename
        report_filename = f"report_{timestamp}.html"
        report_path = self.reports_dir / report_filename
        
        # Generate HTML report
        self._update_report_data(analysis_result)
        self._generate_html_report()
        
        return str(report_path)

    def _generate_html_report(self) -> str:
        """Generate HTML report from analysis data."""
        try:
            # Create reports directory in current working directory
            self.reports_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate timestamp for report files
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Generate report filename
            report_filename = f"report_{timestamp}.html"
            report_path = self.reports_dir / report_filename
            
            # HTML template with escaped CSS curly braces
            html_template = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>SecurePip Analysis Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .package {{ margin-bottom: 20px; padding: 10px; border: 1px solid #ddd; }}
                    .vulnerability {{ color: red; }}
                    .warning {{ color: orange; }}
                    .info {{ color: blue; }}
                    .malware {{ color: darkred; }}
                    .privilege {{ color: purple; }}
                    .embedded {{ color: darkblue; }}
                    .summary {{ margin-top: 20px; padding: 10px; background-color: #f5f5f5; }}
                    table {{ width: 100%; border-collapse: collapse; }}
                    th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                    th {{ background-color: #f2f2f2; }}
                    .dependencies {{ margin-left: 20px; }}
                    .dependency-level-1 {{ background-color: #f9f9f9; }}
                    .dependency-level-2 {{ background-color: #f5f5f5; }}
                    .dependency-level-3 {{ background-color: #f1f1f1; }}
                    .dependency-level-4 {{ background-color: #ededed; }}
                    .dependency-level-5 {{ background-color: #e9e9e9; }}
                </style>
            </head>
            <body>
                <h1>SecurePip Analysis Report</h1>
                <p>Generated on: {timestamp}</p>
                
                <div class="summary">
                    <h2>Summary</h2>
                    <p>Total Packages Analyzed: {total_packages}</p>
                    <p>Vulnerable Packages: {vulnerable_packages}</p>
                    <p>Security Issues: {security_issues}</p>
                    <p>Malware Detected: {malware_detected}</p>
                    <p>Privilege Escalation: {privilege_escalation}</p>
                    <p>Embedded Code: {embedded_code}</p>
                    <p>Typosquatting Detected: {typosquatting_detected}</p>
                    <p>Packages Not Found: {packages_not_found}</p>
                </div>
                
                <h2>Package Analysis</h2>
                {package_details}
            </body>
            </html>
            """
            
            # Generate package details HTML
            package_details = ""
            for package in self.report_data["packages"]:
                package_html = f"""
                <div class="package">
                    <h3>{package['name']} {package.get('version', '')}</h3>
                    <p>Requested by: {package.get('requested_by', 'direct')}</p>
                    
                    {self._generate_vulnerabilities_html(package)}
                    {self._generate_malware_html(package)}
                    {self._generate_privilege_html(package)}
                    {self._generate_embedded_code_html(package)}
                    {self._generate_dependencies_html(package)}
                    {self._generate_typosquatting_html(package)}
                    
                    {f'<p class="error">Error: {package["error"]}</p>' if package.get("error") else ""}
                </div>
                """
                package_details += package_html
            
            # Fill in the template
            html_content = html_template.format(
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                total_packages=self.report_data["summary"]["total_packages"],
                vulnerable_packages=self.report_data["summary"]["vulnerable_packages"],
                security_issues=self.report_data["summary"]["security_issues"],
                malware_detected=self.report_data["summary"]["malware_detected"],
                privilege_escalation=self.report_data["summary"]["privilege_escalation"],
                embedded_code=self.report_data["summary"]["embedded_code"],
                typosquatting_detected=self.report_data["summary"]["typosquatting_detected"],
                packages_not_found=self.report_data["summary"]["packages_not_found"],
                package_details=package_details
            )
            
            # Write the report
            with open(report_path, 'w') as f:
                f.write(html_content)
                
            self._log_info(f"HTML report generated: {report_path}")
            return str(report_path)
            
        except Exception as e:
            self._log_error("Error generating HTML report", e)
            raise

    def _generate_vulnerabilities_html(self, package: Dict) -> str:
        """Generate HTML for package vulnerabilities."""
        if not package.get("vulnerabilities"):
            return ""
            
        vuln_html = "<h4>Vulnerabilities</h4><table>"
        vuln_html += "<tr><th>ID</th><th>Severity</th><th>Description</th><th>Source</th></tr>"
        
        for vuln in package["vulnerabilities"]:
            # Handle different data structures
            vuln_id = vuln.get('id') or vuln.get('cve_id') or 'N/A'
            severity = vuln.get('severity') or vuln.get('cvss_score') or 'unknown'
            description = vuln.get('description') or vuln.get('summary') or 'N/A'
            source = vuln.get('source') or vuln.get('origin') or 'N/A'
            
            vuln_html += f"""
            <tr class="vulnerability">
                <td>{vuln_id}</td>
                <td>{severity}</td>
                <td>{description}</td>
                <td>{source}</td>
            </tr>
            """
            
        vuln_html += "</table>"
        return vuln_html

    def _generate_dependencies_html(self, package: Dict, level: int = 0) -> str:
        """Generate HTML for package dependencies with proper indentation."""
        html = []
        indent = "  " * level
        
        # Add package name with appropriate level class
        level_class = f"dependency-level-{min(level, 5)}"
        html.append(f'{indent}<div class="package {level_class}">')
        html.append(f'{indent}  <h3>{package["name"]} {package["version"]}</h3>')
        
        # Add vulnerabilities if any
        if package.get("vulnerabilities"):
            html.append(f'{indent}  <div class="vulnerability">')
            html.append(f'{indent}    <h4>Vulnerabilities:</h4>')
            html.append(f'{indent}    <ul>')
            for vuln in package["vulnerabilities"]:
                html.append(f'{indent}      <li>{vuln}</li>')
            html.append(f'{indent}    </ul>')
            html.append(f'{indent}  </div>')
        
        # Add dependencies if any
        if package.get("dependencies"):
            html.append(f'{indent}  <div class="dependencies">')
            html.append(f'{indent}    <h4>Dependencies:</h4>')
            for dep in package["dependencies"]:
                html.append(self._generate_dependencies_html(dep, level + 1))
            html.append(f'{indent}  </div>')
        
        html.append(f'{indent}</div>')
        return "\n".join(html)

    def _generate_typosquatting_html(self, package: Dict) -> str:
        """Generate HTML for typosquatting analysis."""
        if not package.get("typosquatting_detected"):
            return ""
            
        # Handle different data structures
        confidence = package.get('typosquatting_confidence') or package.get('confidence') or 'N/A'
        targets = package.get('potential_targets') or package.get('similar_packages') or []
        explanation = package.get('typosquatting_explanation') or package.get('explanation') or 'N/A'
            
        return f"""
        <div class="warning">
            <h4>Typosquatting Warning</h4>
            <p>Confidence: {confidence}</p>
            <p>Potential Targets: {', '.join(targets)}</p>
            <p>Explanation: {explanation}</p>
        </div>
        """

    def _generate_malware_html(self, package: Dict) -> str:
        if not package.get("malware_analysis", {}).get("detected"):
            return ""
            
        malware = package["malware_analysis"]
        return f"""
        <div class="malware">
            <h4>Malware Analysis</h4>
            <p>Type: {malware['type']}</p>
            <p>Confidence: {malware['confidence']:.2f}</p>
            <p>Description: {malware['description']}</p>
            <p>Source: {malware['source']}</p>
            {f"<p>Indicators: {', '.join(malware.get('indicators', []))}</p>" if malware.get('indicators') else ""}
        </div>
        """

    def _generate_privilege_html(self, package: Dict) -> str:
        if not package.get("privilege_analysis", {}).get("detected"):
            return ""
            
        privilege = package["privilege_analysis"]
        return f"""
        <div class="privilege">
            <h4>Privilege Escalation Analysis</h4>
            <p>Type: {privilege['type']}</p>
            <p>Confidence: {privilege['confidence']:.2f}</p>
            <p>Description: {privilege['description']}</p>
            <p>Source: {privilege['source']}</p>
            {f"<p>Indicators: {', '.join(privilege.get('indicators', []))}</p>" if privilege.get('indicators') else ""}
        </div>
        """

    def _generate_embedded_code_html(self, package: Dict) -> str:
        if not package.get("embedded_code_analysis", {}).get("detected"):
            return ""
            
        embedded = package["embedded_code_analysis"]
        findings_html = ""
        if embedded.get("findings"):
            findings_html = "<h5>Findings:</h5><ul>"
            for finding in embedded["findings"]:
                findings_html += f"""
                <li>
                    Type: {finding['type']}<br>
                    File: {finding['file']}<br>
                    Line: {finding['line']}
                </li>
                """
            findings_html += "</ul>"
        
        return f"""
        <div class="embedded">
            <h4>Embedded Code Analysis</h4>
            <p>Type: {embedded['type']}</p>
            <p>Confidence: {embedded['confidence']:.2f}</p>
            <p>Description: {embedded['description']}</p>
            <p>Source: {embedded['source']}</p>
            {findings_html}
        </div>
        """

    def _check_malware(self, package_name: str, version: Optional[str] = None) -> Dict:
        """Check for potential malware in a package."""
        try:
            # Check known malicious packages database
            if package_name in self.known_malicious_packages:
                return {
                    "detected": True,
                    "confidence": 1.0,
                    "type": "known_malicious",
                    "description": "Package is known to be malicious",
                    "source": "Known Malicious Packages Database"
                }
            
            # Analyze package metadata for suspicious patterns
            response = self.session.get(f"https://pypi.org/pypi/{package_name}/json", timeout=10)
            if response.status_code == 200:
                package_data = response.json()
                
                # Check for suspicious patterns in package metadata
                suspicious_patterns = {
                    "suspicious_author": r"(anonymous|unknown|test|admin|root)",
                    "suspicious_email": r"(temp|test|example|fake)@",
                    "suspicious_url": r"(test|example|localhost|127\.0\.0\.1)",
                    "suspicious_description": r"(test|example|malware|virus|trojan|backdoor)"
                }
                
                for field, pattern in suspicious_patterns.items():
                    if field in package_data.get("info", {}):
                        if re.search(pattern, package_data["info"][field], re.IGNORECASE):
                            return {
                                "detected": True,
                                "confidence": 0.7,
                                "type": "suspicious_metadata",
                                "description": f"Suspicious pattern found in {field}",
                                "source": "Package Metadata Analysis"
                            }
            
            # Use Ollama to analyze package for malware
            prompt = f"""
            Analyze this Python package for potential malware:
            Package: {package_name}
            Version: {version}
            
            Check for:
            1. Suspicious imports or dependencies
            2. Network connections to unknown domains
            3. File system modifications
            4. Process creation or manipulation
            5. Data exfiltration patterns
            6. Obfuscated code
            7. Known malware signatures
            
            Return a JSON object with:
            - malware_detected: boolean
            - confidence: float between 0 and 1
            - type: string describing the type of malware
            - description: string explaining the findings
            - indicators: list of suspicious patterns found
            """
            
            response = self.session.post(
                self.ollama_endpoint,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                try:
                    analysis = json.loads(result.get("response", "{}"))
                    if analysis.get("malware_detected", False):
                        return {
                            "detected": True,
                            "confidence": analysis.get("confidence", 0.5),
                            "type": analysis.get("type", "unknown"),
                            "description": analysis.get("description", "Malware detected"),
                            "indicators": analysis.get("indicators", []),
                            "source": "Ollama Analysis"
                        }
                except json.JSONDecodeError:
                    pass
            
            return {
                "detected": False,
                "confidence": 0.0,
                "type": "none",
                "description": "No malware detected",
                "source": "Combined Analysis"
            }
            
        except Exception as e:
            self._log_error("Error checking for malware", e)
            return {
                "detected": False,
                "confidence": 0.0,
                "type": "error",
                "description": f"Error during malware check: {str(e)}",
                "source": "Error"
            }

    def _check_privilege_escalation(self, package_name: str, version: Optional[str] = None) -> Dict:
        """Check for potential privilege escalation vulnerabilities."""
        try:
            # Use Ollama to analyze package for privilege escalation
            prompt = f"""
            Analyze this Python package for potential privilege escalation vulnerabilities:
            Package: {package_name}
            Version: {version}
            
            Check for:
            1. Setuid/setgid usage
            2. Sudo or su execution
            3. File permission modifications
            4. Process privilege manipulation
            5. System command execution with elevated privileges
            6. Environment variable manipulation
            7. Path traversal vulnerabilities
            
            Return a JSON object with:
            - privilege_escalation_detected: boolean
            - confidence: float between 0 and 1
            - type: string describing the type of vulnerability
            - description: string explaining the findings
            - indicators: list of suspicious patterns found
            """
            
            response = self.session.post(
                self.ollama_endpoint,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                try:
                    analysis = json.loads(result.get("response", "{}"))
                    if analysis.get("privilege_escalation_detected", False):
                        return {
                            "detected": True,
                            "confidence": analysis.get("confidence", 0.5),
                            "type": analysis.get("type", "unknown"),
                            "description": analysis.get("description", "Privilege escalation vulnerability detected"),
                            "indicators": analysis.get("indicators", []),
                            "source": "Ollama Analysis"
                        }
                except json.JSONDecodeError:
                    pass
            
            return {
                "detected": False,
                "confidence": 0.0,
                "type": "none",
                "description": "No privilege escalation vulnerabilities detected",
                "source": "Analysis"
            }
            
        except Exception as e:
            self._log_error("Error checking for privilege escalation", e)
            return {
                "detected": False,
                "confidence": 0.0,
                "type": "error",
                "description": f"Error during privilege escalation check: {str(e)}",
                "source": "Error"
            }

    def _check_embedded_code(self, package_name: str, version: Optional[str] = None) -> Dict:
        """Check for embedded or obfuscated code."""
        try:
            # Download and analyze package
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                subprocess.run(
                    ["pip", "download", "--no-deps", package_name, "-d", str(temp_path)],
                    capture_output=True,
                    check=True
                )
                
                # Find downloaded package
                package_file = next(temp_path.glob(f"{package_name}*.tar.gz"))
                
                # Extract package
                subprocess.run(["tar", "-xf", str(package_file), "-C", str(temp_path)], check=True)
                
                # Get package code
                package_dir = next(temp_path.glob(f"{package_name}*"))
                
                # Check for embedded code patterns
                embedded_patterns = {
                    "base64": r"base64\.b64decode\([^)]+\)",
                    "eval": r"eval\([^)]+\)",
                    "exec": r"exec\([^)]+\)",
                    "compressed": r"zlib\.decompress\([^)]+\)",
                    "pickle": r"pickle\.loads\([^)]+\)",
                    "marshal": r"marshal\.loads\([^)]+\)",
                    "obfuscated": r"(eval|exec)\(.*?\)"
                }
                
                findings = []
                for file in package_dir.rglob("*.py"):
                    with open(file, 'r') as f:
                        content = f.read()
                        for pattern_name, pattern in embedded_patterns.items():
                            if re.search(pattern, content):
                                findings.append({
                                    "type": pattern_name,
                                    "file": str(file.relative_to(package_dir)),
                                    "line": content.count('\n', 0, content.find(pattern)) + 1
                                })
                
                if findings:
                    return {
                        "detected": True,
                        "confidence": 0.8,
                        "type": "embedded_code",
                        "description": "Embedded or obfuscated code detected",
                        "findings": findings,
                        "source": "Code Analysis"
                    }
                
                return {
                    "detected": False,
                    "confidence": 0.0,
                    "type": "none",
                    "description": "No embedded or obfuscated code detected",
                    "source": "Code Analysis"
                }
                
        except Exception as e:
            self._log_error("Error checking for embedded code", e)
            return {
                "detected": False,
                "confidence": 0.0,
                "type": "error",
                "description": f"Error during embedded code check: {str(e)}",
                "source": "Error"
            } 