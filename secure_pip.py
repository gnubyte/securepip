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
import argparse
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
    by_severity: defaultdict = field(default_factory=lambda: defaultdict(int))
    current_package: str = ""
    current_chain: str = ""
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime = field(default_factory=datetime.now)

class SecurePip:
    def __init__(self, generate_report: bool = False):
        self.ollama_endpoint = "http://localhost:11434/api/generate"
        self.ollama_model = self._select_ollama_model()
        self.ollama_available = self._check_ollama_availability()
        self.known_malicious_packages = set()
        self.known_typosquatting = set()
        self.analyzed_packages: Set[str] = set()
        self.dependency_chain: List[Dict] = []
        self.stats = AnalysisStats()
        self.progress_bar = None
        self.generate_report = generate_report
        self.report_data = {
            "packages": [],
            "vulnerabilities": [],
            "typosquatting": [],
            "not_found": [],
            "summary": {}
        }
        
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
        
    def _check_ollama_availability(self) -> bool:
        """Check if Ollama is available and running."""
        try:
            # Check if Ollama is installed
            subprocess.run(["ollama", "--version"], capture_output=True, check=True)
            
            # Check if Ollama service is running
            response = requests.get("http://localhost:11434/api/tags", timeout=5)
            return response.status_code == 200
        except (subprocess.CalledProcessError, requests.exceptions.RequestException):
            print(f"{Fore.YELLOW}Warning: Ollama is not available. Some security checks will be limited.{Style.RESET_ALL}")
            return False

    def _get_available_models(self) -> List[str]:
        """Get list of available Ollama models."""
        try:
            response = requests.get("http://localhost:11434/api/tags", timeout=5)
            if response.status_code == 200:
                models = [model["name"] for model in response.json()["models"]]
                return models
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Failed to get available models: {str(e)}{Style.RESET_ALL}")
        return []

    def _select_ollama_model(self) -> str:
        """Prompt user to select an Ollama model."""
        try:
            models = self._get_available_models()
            if not models:
                print(f"{Fore.YELLOW}No Ollama models found. Using default model.{Style.RESET_ALL}")
                return "gemma:3b"

            print(f"\n{Fore.CYAN}Available Ollama models:{Style.RESET_ALL}")
            for i, model in enumerate(models, 1):
                print(f"{i}. {model}")

            while True:
                try:
                    choice = input(f"\n{Fore.CYAN}Select a model number (1-{len(models)}) or press Enter for default (gemma:3b): {Style.RESET_ALL}")
                    if not choice:
                        return "gemma:3b"
                    
                    choice = int(choice)
                    if 1 <= choice <= len(models):
                        return models[choice - 1]
                    else:
                        print(f"{Fore.RED}Invalid choice. Please select a number between 1 and {len(models)}.{Style.RESET_ALL}")
                except ValueError:
                    print(f"{Fore.RED}Please enter a valid number.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Failed to select model: {str(e)}{Style.RESET_ALL}")
            return "gemma:3b"

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

    def _get_cache_key(self, package_name: str, version: Optional[str] = None) -> str:
        """Generate a cache key for a package."""
        key = f"{package_name}:{version if version else 'latest'}"
        return hashlib.md5(key.encode()).hexdigest()

    def _get_cached_analysis(self, package_name: str, version: Optional[str] = None) -> Optional[Dict]:
        """Get cached analysis result if available and not expired."""
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
        cache_key = self._get_cache_key(package_name, version)
        self.cache[cache_key] = {
            'timestamp': time.time(),
            'analysis': analysis
        }
        self._save_cache()

    def _rate_limit(self, endpoint: str) -> None:
        """Implement rate limiting for API calls."""
        with self._rate_limit_lock:
            current_time = time.time()
            last_time = self._last_request_time.get(endpoint, 0)
            if current_time - last_time < self._min_request_interval:
                time.sleep(self._min_request_interval - (current_time - last_time))
            self._last_request_time[endpoint] = time.time()
    
    @lru_cache(maxsize=1000)
    def _get_package_metadata(self, package_name: str) -> Optional[Dict]:
        """Get package metadata with caching."""
        try:
            self._rate_limit("pypi")
            response = self.session.get(
                f"https://pypi.org/pypi/{package_name}/json",
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Failed to get package metadata: {str(e)}{Style.RESET_ALL}")
            return None
    
    def _resolve_package_name(self, dep_string: str) -> tuple[str, Optional[str]]:
        """Resolve package name and version from dependency string."""
        # Remove any environment markers
        dep_string = dep_string.split(';')[0].strip()
        
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
        
        return dep_string.strip(), None

    def _update_progress(self):
        """Update and display progress information."""
        if self.progress_bar is None:
            return
            
        # Calculate progress percentage
        progress = (self.stats.analyzed_packages / max(1, self.stats.total_packages)) * 100
        
        # Update progress bar description
        desc = f"Analyzing: {self.stats.current_package}"
        if self.stats.current_chain:
            desc += f" ({self.stats.current_chain})"
        
        self.progress_bar.set_description(desc)
        self.progress_bar.n = self.stats.analyzed_packages
        self.progress_bar.refresh()
        
        # Print summary every 10 packages or when progress is complete
        if self.stats.analyzed_packages % 10 == 0 or self.stats.analyzed_packages == self.stats.total_packages:
            self._print_summary()

    def _format_dependency_chain(self, chain: List[Dict]) -> str:
        """Format dependency chain for display."""
        formatted_chain = []
        for dep in chain:
            package_str = dep['package']
            if dep.get('version'):
                package_str += f" ({dep['version']})"
            formatted_chain.append(package_str)
        return " -> ".join(formatted_chain)

    def _print_summary(self):
        """Print current analysis summary."""
        print(f"\n{Fore.CYAN}Analysis Summary:{Style.RESET_ALL}")
        print(f"Progress: {self.stats.analyzed_packages}/{self.stats.total_packages} packages ({self.stats.analyzed_packages/max(1, self.stats.total_packages)*100:.1f}%)")
        print(f"Current Package: {self.stats.current_package}")
        if self.stats.current_chain:
            print(f"Dependency Chain: {self.stats.current_chain}")
        print(f"Vulnerable Packages: {self.stats.vulnerable_packages}")
        print(f"Security Issues: {self.stats.security_issues}")
        print(f"Typosquatting Detected: {self.stats.typosquatting_detected}")
        print(f"Packages Not Found: {self.stats.packages_not_found}")
        print("Severity Breakdown:")
        for severity, count in self.stats.by_severity.items():
            print(f"  {severity}: {count}")
        print("-" * 50)

    def analyze_package(self, package_name: str, version: Optional[str] = None, requested_by: Optional[str] = None) -> Dict:
        """Analyze a package for security issues."""
        # Check cache first
        cached_analysis = self._get_cached_analysis(package_name, version)
        if cached_analysis:
            # Update requested_by in cached analysis
            cached_analysis['requested_by'] = requested_by
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
            self.stats.analyzed_packages += 1
            self._update_progress()
            return {"package_name": package_name, "version": version, "status": "already_analyzed"}
        
        self.analyzed_packages.add(package_key)
        
        # Show dependency chain
        chain_str = self._format_dependency_chain(self.dependency_chain)
        print(f"\n{Fore.CYAN}Analyzing package: {chain_str}{Style.RESET_ALL}")
        
        # Get package metadata from PyPI
        try:
            response = self.session.get(f"https://pypi.org/pypi/{package_name}/json", timeout=10)
            if response.status_code != 200:
                print(f"{Fore.YELLOW}Warning: Package {package_name} not found on PyPI{Style.RESET_ALL}")
                self.stats.packages_not_found += 1
                
                # Try to resolve the package using pip
                try:
                    print(f"{Fore.CYAN}Attempting to resolve package using pip...{Style.RESET_ALL}")
                    result = subprocess.run(
                        ["pip", "download", "--no-deps", package_name],
                        capture_output=True,
                        text=True
                    )
                    if result.returncode == 0:
                        print(f"{Fore.GREEN}Package resolved successfully{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}Failed to resolve package: {result.stderr}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}Error resolving package: {str(e)}{Style.RESET_ALL}")
                
                self.stats.analyzed_packages += 1
                self._update_progress()
                return {
                    "package_name": package_name,
                    "version": version,
                    "error": "Package not found on PyPI",
                    "requested_by": requested_by
                }
            
            package_data = response.json()
            
            # Check for typosquatting
            if self._check_typosquatting(package_name):
                print(f"{Fore.YELLOW}Warning: Potential typosquatting detected{Style.RESET_ALL}")
                self.stats.typosquatting_detected += 1
            
            # Analyze dependencies
            dependencies = self._analyze_dependencies(package_data, package_name)
            
            # Check for known vulnerabilities
            vulnerabilities = self._check_vulnerabilities(package_name, version)
            if vulnerabilities:
                self.stats.vulnerable_packages += 1
                self.stats.security_issues += len(vulnerabilities)
                for vuln in vulnerabilities:
                    self.stats.by_severity[vuln.get("severity", "unknown")] += 1
            
            # Analyze package code using Ollama
            code_analysis = self._analyze_code_with_ollama(package_name, version)
            
            # Remove current package from dependency chain
            self.dependency_chain.pop()
            
            # Create analysis result
            analysis_result = {
                "package_name": package_name,
                "version": version,
                "dependencies": dependencies,
                "vulnerabilities": vulnerabilities,
                "code_analysis": code_analysis,
                "requested_by": requested_by
            }
            
            # Cache the analysis result
            self._cache_analysis(package_name, version, analysis_result)
            
            # Update report data if needed
            if self.generate_report:
                self._update_report_data(analysis_result)
            
            self.stats.analyzed_packages += 1
            self._update_progress()
            
            return analysis_result
            
        except Exception as e:
            print(f"{Fore.YELLOW}Warning during analysis: {str(e)}{Style.RESET_ALL}")
            # Remove current package from dependency chain
            self.dependency_chain.pop()
            
            self.stats.analyzed_packages += 1
            self._update_progress()
            
            return {
                "package_name": package_name,
                "version": version,
                "error": str(e),
                "requested_by": requested_by
            }
    
    def _check_typosquatting(self, package_name: str) -> bool:
        """Check for potential typosquatting using Ollama/Gemma."""
        if not self.ollama_available:
            print(f"{Fore.YELLOW}Warning: Skipping typosquatting check - Ollama not available{Style.RESET_ALL}")
            return False

        try:
            # Prepare prompt for typosquatting analysis
            prompt = f"""
            Analyze if the following Python package name could be a typosquatting attempt.
            Consider:
            - Common misspellings
            - Character substitutions
            - Missing/extra characters
            - Similar sounding names
            - Names of popular packages
            
            Package name to analyze: {package_name}
            
            Return a JSON response with:
            {{
                "is_typosquatting": boolean,
                "confidence": float (0.0 to 1.0),
                "potential_targets": list of strings (popular packages this might be targeting),
                "explanation": string (brief explanation of why this might be typosquatting)
            }}
            """
            
            # Call Ollama API
            response = requests.post(
                self.ollama_endpoint,
                json={
                    "model": self.ollama_model,
                    "prompt": prompt,
                    "stream": False
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                try:
                    # Try to parse the response as JSON
                    analysis = json.loads(result.get("response", "{}"))
                    if analysis.get("is_typosquatting", False):
                        print(f"{Fore.YELLOW}Warning: Potential typosquatting detected{Style.RESET_ALL}")
                        print(f"Confidence: {analysis.get('confidence', 0.0):.2f}")
                        print(f"Potential targets: {', '.join(analysis.get('potential_targets', []))}")
                        print(f"Explanation: {analysis.get('explanation', 'No explanation provided')}")
                        return True
                except json.JSONDecodeError:
                    # If response isn't valid JSON, use a simpler check
                    if "typosquatting" in result.get("response", "").lower():
                        print(f"{Fore.YELLOW}Warning: Potential typosquatting detected{Style.RESET_ALL}")
                        return True
            return False
                
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Failed to analyze typosquatting: {str(e)}{Style.RESET_ALL}")
            return False
    
    def _analyze_dependencies(self, package_data: Dict, parent_package: str) -> List[Dict]:
        """Analyze package dependencies."""
        dependencies = []
        if "info" in package_data and "requires_dist" in package_data["info"]:
            for dep in package_data["info"]["requires_dist"]:
                dep_name, dep_version = self._resolve_package_name(dep)
                if dep_name:
                    dep_analysis = self.analyze_package(dep_name, dep_version, requested_by=parent_package)
                    dependencies.append(dep_analysis)
        
        return dependencies
    
    def _check_vulnerabilities(self, package_name: str, version: Optional[str]) -> List[Dict]:
        """Check for known vulnerabilities from multiple sources in parallel."""
        vulnerabilities = []
        
        try:
            # Create a list of vulnerability check functions
            check_functions = [
                (self._check_pypi_advisory, (package_name, version)),
                (self._check_osv_database, (package_name, version)),
                (self._check_nvd_database, (package_name, version)),
                (self._analyze_vulnerabilities_with_llm, (package_name, version))
            ]
            
            # Execute checks in parallel
            with ThreadPoolExecutor(max_workers=4) as executor:
                future_to_check = {
                    executor.submit(func, *args): (func.__name__, args)
                    for func, args in check_functions
                }
                
                for future in as_completed(future_to_check):
                    check_name, _ = future_to_check[future]
                    try:
                        result = future.result()
                        vulnerabilities.extend(result)
                    except Exception as e:
                        print(f"{Fore.YELLOW}Warning: {check_name} failed: {str(e)}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Failed to check vulnerabilities: {str(e)}{Style.RESET_ALL}")
        
        return vulnerabilities
    
    def _check_pypi_advisory(self, package_name: str, version: Optional[str]) -> List[Dict]:
        """Check PyPI Advisory Database for vulnerabilities."""
        try:
            package_data = self._get_package_metadata(package_name)
            if not package_data:
                return []
            
            vulnerabilities = []
            
            # Check for advisory information
            if "info" in package_data and "classifiers" in package_data["info"]:
                for classifier in package_data["info"]["classifiers"]:
                    if "Development Status" in classifier and "Beta" in classifier:
                        vulnerabilities.append({
                            "source": "PyPI",
                            "type": "development_status",
                            "severity": "medium",
                            "description": "Package is in beta/development status",
                            "affected_versions": "all",
                            "url": f"https://pypi.org/project/{package_name}/"
                        })
            
            return vulnerabilities
            
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Failed to check PyPI advisory: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _check_osv_database(self, package_name: str, version: Optional[str]) -> List[Dict]:
        """Check OSV Database for vulnerabilities."""
        try:
            self._rate_limit("osv")
            url = "https://api.osv.dev/v1/query"
            
            query = {
                "package": {
                    "name": f"pypi:{package_name}",
                    "ecosystem": "PyPI"
                }
            }
            if version:
                query["version"] = version
            
            response = self.session.post(url, json=query, timeout=10)
            if response.status_code != 200:
                return []
            
            vulns = response.json()
            vulnerabilities = []
            
            if "vulns" in vulns:
                for vuln in vulns["vulns"]:
                    vulnerabilities.append({
                        "source": "OSV",
                        "type": vuln.get("type", "unknown"),
                        "severity": vuln.get("severity", "unknown"),
                        "description": vuln.get("summary", "No description available"),
                        "affected_versions": vuln.get("affected", []),
                        "url": vuln.get("references", [{}])[0].get("url", "")
                    })
            
            return vulnerabilities
            
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Failed to check OSV database: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _check_nvd_database(self, package_name: str, version: Optional[str]) -> List[Dict]:
        """Check NVD Database for vulnerabilities."""
        try:
            self._rate_limit("nvd")
            url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
            
            params = {
                "keyword": f"python {package_name}",
                "resultsPerPage": 20
            }
            
            response = self.session.get(url, params=params, timeout=10)
            if response.status_code != 200:
                return []
            
            nvd_data = response.json()
            vulnerabilities = []
            
            if "result" in nvd_data and "CVE_Items" in nvd_data["result"]:
                for cve in nvd_data["result"]["CVE_Items"]:
                    cve_id = cve["cve"]["CVE_data_meta"]["ID"]
                    description = cve["cve"]["description"]["description_data"][0]["value"]
                    
                    severity = "unknown"
                    if "baseMetricV3" in cve["impact"]:
                        cvss = cve["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                        if cvss >= 9.0:
                            severity = "critical"
                        elif cvss >= 7.0:
                            severity = "high"
                        elif cvss >= 4.0:
                            severity = "medium"
                        else:
                            severity = "low"
                    
                    vulnerabilities.append({
                        "source": "NVD",
                        "type": "CVE",
                        "severity": severity,
                        "description": description,
                        "affected_versions": "all",
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    })
            
            return vulnerabilities
            
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Failed to check NVD database: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _analyze_vulnerabilities_with_llm(self, package_name: str, version: Optional[str]) -> List[Dict]:
        """Use Ollama/Gemma to analyze potential vulnerabilities."""
        if not self.ollama_available:
            print(f"{Fore.YELLOW}Warning: Skipping LLM vulnerability analysis - Ollama not available{Style.RESET_ALL}")
            return []

        try:
            self._rate_limit("ollama")
            prompt = f"""
            Analyze the Python package '{package_name}' (version: {version if version else 'latest'}) for security vulnerabilities.
            Focus on:
            1. Known CVEs and security issues
            2. Common vulnerability patterns in Python packages
            3. Security best practices violations
            4. Potential attack vectors
            
            Return a concise JSON response with:
            {{
                "vulnerabilities": [
                    {{
                        "type": string,
                        "severity": "critical/high/medium/low",
                        "description": string,
                        "affected_versions": string,
                        "recommendation": string
                    }}
                ]
            }}
            """
            
            response = self.session.post(
                self.ollama_endpoint,
                json={
                    "model": self.ollama_model,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                try:
                    analysis = json.loads(result.get("response", "{}"))
                    vulns = analysis.get("vulnerabilities", [])
                    
                    for vuln in vulns:
                        vuln["source"] = "LLM Analysis"
                    
                    return vulns
                except json.JSONDecodeError:
                    return []
            return []
                
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Failed to analyze vulnerabilities with LLM: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _analyze_code_with_ollama(self, package_name: str, version: Optional[str]) -> Dict:
        """Analyze package code using Ollama/Gemma."""
        if not self.ollama_available:
            print(f"{Fore.YELLOW}Warning: Skipping code analysis - Ollama not available{Style.RESET_ALL}")
            return {"error": "Ollama not available"}

        try:
            # Download package source
            download_cmd = ["pip", "download", "--no-deps"]
            if version:
                download_cmd.extend([f"{package_name}=={version}"])
            else:
                download_cmd.append(package_name)
            
            subprocess.run(download_cmd, check=True, capture_output=True)
            
            # Prepare code analysis prompt
            prompt = f"""
            Analyze the following Python package for security issues:
            - Malicious code
            - Arbitrary code execution
            - Hidden payloads
            - Unsafe imports
            - Credential leakage
            - Privilege escalation
            - Weak integrity checking
            
            Package: {package_name}
            Version: {version}
            """
            
            # Call Ollama API
            response = requests.post(
                self.ollama_endpoint,
                json={
                    "model": self.ollama_model,
                    "prompt": prompt,
                    "stream": False
                }
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": "Failed to analyze code with Ollama"}
                
        except Exception as e:
            return {"error": str(e)}
    
    def install_package(self, package_name: str, version: Optional[str] = None, force: bool = False) -> bool:
        """Install a package after security analysis."""
        # Initialize progress bar
        self.progress_bar = tqdm(total=1, desc="Initializing analysis...")
        
        analysis = self.analyze_package(package_name, version)
        
        if "error" in analysis:
            print(f"{Fore.YELLOW}Warning: {analysis['error']}{Style.RESET_ALL}")
            if not force:
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
            
            if not force:
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

    def _generate_html_report(self):
        """Generate HTML report with analysis results."""
        if not self.generate_report:
            return

        # Create reports directory if it doesn't exist
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        # Generate timestamp for report files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Generate index.html
        index_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SecurePip Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .summary {{ background-color: #f5f5f5; padding: 20px; border-radius: 5px; }}
                .package {{ margin: 10px 0; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }}
                .vulnerable {{ background-color: #ffebee; }}
                .typosquatting {{ background-color: #fff3e0; }}
                .not-found {{ background-color: #e3f2fd; }}
                .severity-critical {{ color: #d32f2f; }}
                .severity-high {{ color: #f57c00; }}
                .severity-medium {{ color: #ffa000; }}
                .severity-low {{ color: #689f38; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f5f5f5; }}
            </style>
        </head>
        <body>
            <h1>SecurePip Analysis Report</h1>
            <div class="summary">
                <h2>Summary</h2>
                <p>Analysis completed at: {self.stats.end_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Total packages analyzed: {self.stats.total_packages}</p>
                <p>Vulnerable packages: {self.stats.vulnerable_packages}</p>
                <p>Typosquatting detected: {self.stats.typosquatting_detected}</p>
                <p>Packages not found: {self.stats.packages_not_found}</p>
                <p>Total security issues: {self.stats.security_issues}</p>
                <h3>Severity Breakdown</h3>
                <table>
                    <tr><th>Severity</th><th>Count</th></tr>
                    {''.join(f'<tr><td class="severity-{severity.lower()}">{severity}</td><td>{count}</td></tr>' 
                            for severity, count in self.stats.by_severity.items())}
                </table>
            </div>
            
            <h2>Package Analysis</h2>
            {self._generate_package_sections()}
        </body>
        </html>
        """
        
        # Write index.html
        with open(reports_dir / f"report_{timestamp}.html", "w") as f:
            f.write(index_html)
        
        # Generate individual package reports
        for package in self.report_data["packages"]:
            self._generate_package_report(package, reports_dir, timestamp)

    def _generate_package_sections(self) -> str:
        """Generate HTML sections for each package."""
        sections = []
        for package in self.report_data["packages"]:
            package_class = "package"
            if package.get("vulnerabilities"):
                package_class += " vulnerable"
            if package.get("typosquatting_detected"):
                package_class += " typosquatting"
            if package.get("not_found"):
                package_class += " not-found"
                
            sections.append(f"""
            <div class="{package_class}">
                <h3>{package['name']} {package.get('version', '')}</h3>
                <p>Requested by: {package.get('requested_by', 'direct')}</p>
                {self._generate_vulnerability_section(package)}
                {self._generate_typosquatting_section(package)}
                {self._generate_dependencies_section(package)}
            </div>
            """)
        return "\n".join(sections)

    def _generate_vulnerability_section(self, package: Dict) -> str:
        """Generate HTML section for package vulnerabilities."""
        if not package.get("vulnerabilities"):
            return ""
            
        vulns = []
        for vuln in package["vulnerabilities"]:
            vulns.append(f"""
            <div class="vulnerability severity-{vuln.get('severity', 'unknown').lower()}">
                <h4>{vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')}</h4>
                <p>{vuln.get('description', 'No description available')}</p>
                <p>Affected versions: {vuln.get('affected_versions', 'Unknown')}</p>
                <p>Source: {vuln.get('source', 'Unknown')}</p>
                {f'<p>Recommendation: {vuln.get("recommendation", "")}</p>' if vuln.get('recommendation') else ''}
            </div>
            """)
            
        return f"""
        <div class="vulnerabilities">
            <h4>Vulnerabilities</h4>
            {''.join(vulns)}
        </div>
        """

    def _generate_typosquatting_section(self, package: Dict) -> str:
        """Generate HTML section for typosquatting analysis."""
        if not package.get("typosquatting_detected"):
            return ""
            
        return f"""
        <div class="typosquatting">
            <h4>Typosquatting Analysis</h4>
            <p>Confidence: {package.get('typosquatting_confidence', 'Unknown')}</p>
            <p>Potential targets: {', '.join(package.get('potential_targets', []))}</p>
            <p>Explanation: {package.get('typosquatting_explanation', 'No explanation available')}</p>
        </div>
        """

    def _generate_dependencies_section(self, package: Dict) -> str:
        """Generate HTML section for package dependencies."""
        if not package.get("dependencies"):
            return ""
            
        deps = []
        for dep in package["dependencies"]:
            dep_class = "dependency"
            if dep.get("vulnerabilities"):
                dep_class += " vulnerable"
            if dep.get("typosquatting_detected"):
                dep_class += " typosquatting"
                
            deps.append(f"""
            <div class="{dep_class}">
                <h5>{dep['name']} {dep.get('version', '')}</h5>
                {self._generate_vulnerability_section(dep)}
            </div>
            """)
            
        return f"""
        <div class="dependencies">
            <h4>Dependencies</h4>
            {''.join(deps)}
        </div>
        """

    def _generate_package_report(self, package: Dict, reports_dir: Path, timestamp: str):
        """Generate individual HTML report for a package."""
        package_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{package['name']} Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .vulnerability {{ margin: 10px 0; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }}
                .severity-critical {{ background-color: #ffebee; }}
                .severity-high {{ background-color: #fff3e0; }}
                .severity-medium {{ background-color: #fff8e1; }}
                .severity-low {{ background-color: #f1f8e9; }}
                .code-block {{ background-color: #f5f5f5; padding: 10px; border-radius: 5px; font-family: monospace; }}
                .back-link {{ margin-top: 20px; }}
            </style>
        </head>
        <body>
            <h1>{package['name']} Analysis Report</h1>
            <p>Version: {package.get('version', 'Unknown')}</p>
            <p>Requested by: {package.get('requested_by', 'direct')}</p>
            
            {self._generate_vulnerability_section(package)}
            {self._generate_typosquatting_section(package)}
            {self._generate_dependencies_section(package)}
            
            <div class="back-link">
                <a href="report_{timestamp}.html">Back to Summary</a>
            </div>
        </body>
        </html>
        """
        
        # Write package report
        with open(reports_dir / f"package_{package['name']}_{timestamp}.html", "w") as f:
            f.write(package_html)

    def _update_report_data(self, analysis_result: Dict):
        """Update report data with analysis results."""
        if not self.generate_report:
            return
            
        package_data = {
            "name": analysis_result["package_name"],
            "version": analysis_result.get("version"),
            "requested_by": analysis_result.get("requested_by"),
            "vulnerabilities": analysis_result.get("vulnerabilities", []),
            "dependencies": []
        }
        
        if analysis_result.get("typosquatting_detected"):
            package_data.update({
                "typosquatting_detected": True,
                "typosquatting_confidence": analysis_result.get("typosquatting_confidence"),
                "potential_targets": analysis_result.get("potential_targets", []),
                "typosquatting_explanation": analysis_result.get("typosquatting_explanation")
            })
            
        if analysis_result.get("dependencies"):
            for dep in analysis_result["dependencies"]:
                dep_data = {
                    "name": dep["package_name"],
                    "version": dep.get("version"),
                    "vulnerabilities": dep.get("vulnerabilities", [])
                }
                package_data["dependencies"].append(dep_data)
                
        self.report_data["packages"].append(package_data)

def main():
    parser = argparse.ArgumentParser(description='Secure package installer with vulnerability analysis')
    parser.add_argument('package_name', help='Name of the package to install')
    parser.add_argument('--version', help='Specific version of the package to install')
    parser.add_argument('--report', action='store_true', help='Generate HTML report')
    parser.add_argument('--no-install', action='store_true', help='Only analyze, do not install')
    parser.add_argument('--force', action='store_true', help='Force installation despite warnings')
    
    args = parser.parse_args()
    
    secure_pip = SecurePip(generate_report=args.report)
    
    if args.no_install:
        analysis = secure_pip.analyze_package(args.package_name, args.version)
        if args.report:
            secure_pip._generate_html_report()
    else:
        secure_pip.install_package(args.package_name, args.version, force=args.force)
        if args.report:
            secure_pip._generate_html_report()

if __name__ == "__main__":
    main() 