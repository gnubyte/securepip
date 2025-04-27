#!/usr/bin/env python3

import sys
import argparse
from typing import List, Optional
from pathlib import Path
from colorama import init, Fore, Style
from .core import SecurePip

init(autoreset=True)

def parse_requirements_file(file_path: str) -> List[tuple[str, Optional[str]]]:
    """Parse requirements.txt file and return list of (package, version) tuples."""
    requirements = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Handle -r recursive requirements
                if line.startswith('-r'):
                    recursive_file = line[2:].strip()
                    base_dir = Path(file_path).parent
                    recursive_path = base_dir / recursive_file
                    requirements.extend(parse_requirements_file(str(recursive_path)))
                    continue
                
                # Handle package specifications
                if '==' in line:
                    package, version = line.split('==', 1)
                    requirements.append((package.strip(), version.strip()))
                elif '>=' in line:
                    package, version = line.split('>=', 1)
                    requirements.append((package.strip(), f">={version.strip()}"))
                elif '<=' in line:
                    package, version = line.split('<=', 1)
                    requirements.append((package.strip(), f"<={version.strip()}"))
                else:
                    requirements.append((line.strip(), None))
    except Exception as e:
        print(f"{Fore.RED}Error reading requirements file: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
    
    return requirements

def _log_error(message: str, error: Optional[Exception] = None) -> None:
    """Log an error message with line number and traceback if available."""
    import traceback
    import inspect
    import sys
    from colorama import Fore, Style
    
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

def analyze_packages(args):
    """Analyze packages from requirements file or command line."""
    secure_pip = SecurePip(
        no_cache=args.no_cache,
        generate_report=args.generate_report,
        model=args.model,
        report_dir=args.report_dir
    )
    
    if args.requirements:
        with open(args.requirements, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    package_name = line.split('==')[0].split('>=')[0].split('<=')[0]
                    version = None
                    if '==' in line:
                        version = line.split('==')[1]
                    secure_pip.analyze_package(package_name, version)
    else:
        for package in args.packages:
            secure_pip.analyze_package(package)

def install_packages(packages: List[tuple[str, Optional[str]]], args: argparse.Namespace):
    """Install multiple packages with their specified versions."""
    secure_pip = SecurePip(
        generate_report=args.report,
        force=args.force,
        no_cache=args.no_cache,
        model=args.model
    )
    
    for package, version in packages:
        print(f"\n{Fore.CYAN}Analyzing {package}{f'=={version}' if version else ''}{Style.RESET_ALL}")
        secure_pip.install_package(package, version)

def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(description='SecurePip - Security-focused package installer and analyzer')
    parser.add_argument('packages', nargs='*', help='Packages to analyze')
    parser.add_argument('-r', '--requirements', help='Requirements file to analyze')
    parser.add_argument('--no-cache', action='store_true', help='Disable caching')
    parser.add_argument('--generate-report', action='store_true', help='Generate HTML report')
    parser.add_argument('--model', help='Ollama model to use for analysis')
    parser.add_argument('--report-dir', help='Directory to save reports')
    
    args = parser.parse_args()
    
    if not args.packages and not args.requirements:
        parser.print_help()
        sys.exit(1)
        
    analyze_packages(args)

if __name__ == '__main__':
    main() 