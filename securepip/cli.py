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
    """Analyze packages for security issues."""
    try:
        # Initialize SecurePip with configuration
        secure_pip = SecurePip(
            no_cache=args.no_cache,
            generate_report=True,  # Always generate reports for analyze command
            model=args.model,
            report_dir=args.report_dir
        )
        
        # Read requirements file if specified
        if args.requirement:
            with open(args.requirement, 'r') as f:
                packages = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Handle both package names and version specifications
                        if '==' in line:
                            name, version = line.split('==', 1)
                            packages.append((name.strip(), version.strip()))
                        else:
                            packages.append((line.strip(), None))
        else:
            packages = [(pkg, None) for pkg in args.packages]
        
        if not packages:
            print(f"{Fore.RED}Error: No packages specified for analysis{Style.RESET_ALL}")
            return
        
        # Analyze each package
        print(f"{Fore.CYAN}Starting analysis of {len(packages)} packages...{Style.RESET_ALL}")
        
        for package_name, version in packages:
            print(f"\n{Fore.CYAN}Analyzing {package_name}{f'=={version}' if version else ''}...{Style.RESET_ALL}")
            try:
                analysis = secure_pip.analyze_package(package_name, version)
                
                # Print summary of findings
                if analysis.get('vulnerabilities'):
                    print(f"{Fore.RED}Vulnerabilities found:{Style.RESET_ALL}")
                    for vuln in analysis['vulnerabilities']:
                        print(f"  - {vuln.get('id', 'Unknown')}: {vuln.get('description', 'No description')}")
                
                if analysis.get('typosquatting_detected'):
                    print(f"{Fore.YELLOW}Typosquatting detected:{Style.RESET_ALL}")
                    print(f"  Confidence: {analysis.get('typosquatting_confidence', 'Unknown')}")
                    print(f"  Potential targets: {', '.join(analysis.get('potential_targets', []))}")
                
                if analysis.get('malware_analysis', {}).get('detected'):
                    print(f"{Fore.RED}Malware detected:{Style.RESET_ALL}")
                    print(f"  Type: {analysis['malware_analysis'].get('type', 'Unknown')}")
                    print(f"  Confidence: {analysis['malware_analysis'].get('confidence', 'Unknown')}")
                
                if analysis.get('privilege_analysis', {}).get('detected'):
                    print(f"{Fore.RED}Privilege escalation detected:{Style.RESET_ALL}")
                    print(f"  Type: {analysis['privilege_analysis'].get('type', 'Unknown')}")
                    print(f"  Confidence: {analysis['privilege_analysis'].get('confidence', 'Unknown')}")
                
                if analysis.get('embedded_code_analysis', {}).get('detected'):
                    print(f"{Fore.YELLOW}Embedded code detected:{Style.RESET_ALL}")
                    print(f"  Type: {analysis['embedded_code_analysis'].get('type', 'Unknown')}")
                    print(f"  Confidence: {analysis['embedded_code_analysis'].get('confidence', 'Unknown')}")
                
                if not any([
                    analysis.get('vulnerabilities'),
                    analysis.get('typosquatting_detected'),
                    analysis.get('malware_analysis', {}).get('detected'),
                    analysis.get('privilege_analysis', {}).get('detected'),
                    analysis.get('embedded_code_analysis', {}).get('detected')
                ]):
                    print(f"{Fore.GREEN}No security issues detected{Style.RESET_ALL}")
                
            except Exception as e:
                print(f"{Fore.RED}Error analyzing {package_name}: {str(e)}{Style.RESET_ALL}")
                continue
        
        # Print final summary
        print(f"\n{Fore.CYAN}Analysis complete!{Style.RESET_ALL}")
        print(f"Total packages analyzed: {len(packages)}")
        print(f"Vulnerable packages: {secure_pip.stats.vulnerable_packages}")
        print(f"Malware detected: {secure_pip.stats.malware}")
        print(f"Privilege escalation detected: {secure_pip.stats.privilege_escalation}")
        print(f"Embedded code detected: {secure_pip.stats.embedded_code}")
        print(f"Typosquatting detected: {secure_pip.stats.typosquatting_detected}")
        print(f"Security issues found: {secure_pip.stats.security_issues}")
        
        # Print severity breakdown
        print("\nSeverity breakdown:")
        for severity, count in secure_pip.stats.by_severity.items():
            print(f"  {severity}: {count}")
        
        # Print report location if generated
        if secure_pip.generate_report:
            report_path = secure_pip._generate_html_report()
            print(f"\n{Fore.CYAN}Detailed report has been generated at:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{report_path}{Style.RESET_ALL}")
            print(f"\nYou can open this file in your web browser to view the full analysis report.")
        
    except Exception as e:
        _log_error("Error during analysis", e)
        return

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
    parser = argparse.ArgumentParser(
        description='Secure package installer with vulnerability analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  securepip install requests
  securepip install requests==2.31.0
  securepip install -r requirements.txt
  securepip install --report --force requests
  securepip install --no-cache --model llama2:7b requests
  securepip analyze -r requirements.txt
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Common arguments for install and analyze commands
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument('-r', '--requirement', help='Install from the given requirements file')
    common_parser.add_argument('--force', action='store_true', help='Force operation despite warnings')
    common_parser.add_argument('--no-cache', action='store_true', help='Disable analysis cache')
    common_parser.add_argument('--model', help='Specify Ollama model to use')
    
    # Install command
    install_parser = subparsers.add_parser('install', help='Install packages', parents=[common_parser])
    install_parser.add_argument('packages', nargs='*', help='Package names to install')
    install_parser.add_argument('--version', help='Specific version of the package to install')
    install_parser.add_argument('--report', action='store_true', help='Generate HTML report')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze packages without installing (always generates report)', parents=[common_parser])
    analyze_parser.add_argument('packages', nargs='*', help='Package names to analyze')
    analyze_parser.add_argument('--version', help='Specific version of the package to analyze')
    analyze_parser.add_argument('--report-dir', help='Directory to store analysis reports (default: ./reports)')
    
    # Other pip-like commands
    subparsers.add_parser('list', help='List installed packages')
    subparsers.add_parser('show', help='Show information about installed packages')
    subparsers.add_parser('uninstall', help='Uninstall packages')
    subparsers.add_parser('freeze', help='Output installed packages in requirements format')
    
    args = parser.parse_args()
    
    if args.command in ['install', 'analyze']:
        packages_to_process = []
        
        if args.requirement:
            packages_to_process.extend(parse_requirements_file(args.requirement))
        
        if args.packages:
            for package in args.packages:
                if '==' in package:
                    pkg, ver = package.split('==', 1)
                    packages_to_process.append((pkg, ver))
                else:
                    packages_to_process.append((package, args.version))
        
        if not packages_to_process:
            print(f"{Fore.RED}Error: No packages specified for {args.command}{Style.RESET_ALL}")
            sys.exit(1)
        
        if args.command == 'install':
            install_packages(packages_to_process, args)
        else:  # analyze
            # For analyze command, always generate reports
            args.report = True
            analyze_packages(args)
    
    elif args.command == 'list':
        # TODO: Implement list command
        print("List command not yet implemented")
    
    elif args.command == 'show':
        # TODO: Implement show command
        print("Show command not yet implemented")
    
    elif args.command == 'uninstall':
        # TODO: Implement uninstall command
        print("Uninstall command not yet implemented")
    
    elif args.command == 'freeze':
        # TODO: Implement freeze command
        print("Freeze command not yet implemented")
    
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main() 