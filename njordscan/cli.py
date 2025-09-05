"""
🛡️ NjordScan v1.0.0 - The Ultimate Security Scanner CLI

Advanced command-line interface with AI-powered intelligence, community features,
and comprehensive security analysis for Next.js, React, and Vite applications.
"""

import click
import sys
import os
import asyncio
from pathlib import Path
from typing import Dict, Any
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from .scanner import ScanOrchestrator
from .config import Config
from .utils import validate_target, display_banner, explain_vulnerability
from .cache import CacheManager
from .plugins import PluginManager

# Optional imports for advanced features
try:
    from .data_updater import VulnerabilityDataManager
    DATA_UPDATER_AVAILABLE = True
except ImportError:
    DATA_UPDATER_AVAILABLE = False
    VulnerabilityDataManager = None

# Import new orchestrators and engines
try:
    from .core.scan_orchestrator_enhanced import EnhancedScanOrchestrator
    from .intelligence.intelligence_orchestrator import IntelligenceOrchestrator
    from .ai.ai_orchestrator import AISecurityOrchestrator
    from .performance.performance_orchestrator import PerformanceOrchestrator
    from .developer_experience.dx_orchestrator import DeveloperExperienceOrchestrator as DXOrchestrator
    from .community.community_orchestrator import CommunityOrchestrator
    ADVANCED_FEATURES = True
except ImportError:
    ADVANCED_FEATURES = False
    
from . import __version__, BANNER, FEATURES

console = Console()

def show_pentest_warning() -> bool:
    """Show ethical warning for pentest mode."""
    warning_text = Text()
    warning_text.append("⚠️  PENTEST MODE WARNING ⚠️\n\n", style="bold red")
    warning_text.append("Pentest mode enables aggressive security testing that may:\n", style="yellow")
    warning_text.append("• Generate significant network traffic\n", style="white")
    warning_text.append("• Test for vulnerabilities that could affect system stability\n", style="white")
    warning_text.append("• Trigger security monitoring systems\n", style="white")
    warning_text.append("\nOnly use pentest mode on systems you own or have explicit permission to test.\n\n", style="red")
    warning_text.append("Do you have permission to test this target? (y/N): ", style="bold white")
    
    panel = Panel(warning_text, title="Ethical Usage Agreement", border_style="red")
    console.print(panel)
    
    response = input().strip().lower()
    return response in ['y', 'yes']

def _get_topic_info(topic: str) -> str:
    """Get detailed information about a specific security topic."""
    topic_info = {
        'xss': """
🔴 Cross-Site Scripting (XSS) - A Beginner's Guide

What is XSS?
XSS allows attackers to inject malicious scripts into your website that run in your users' browsers.

Real-World Example:
Imagine a comment system where users can post HTML. An attacker posts:
<script>alert('Hacked!')</script>

This could:
• Steal user cookies and login sessions
• Redirect users to fake login pages
• Monitor user keystrokes
• Display fake content

How to Fix:
✅ Use React's built-in XSS protection (automatic)
✅ Never use dangerouslySetInnerHTML
✅ Sanitize user input with libraries like DOMPurify
✅ Implement Content Security Policy (CSP) headers

Why This Matters:
XSS is one of the most common web vulnerabilities and can lead to complete account takeover!
        """,
        'headers': """
🔒 HTTP Security Headers - Your Website's Security Shield

What are Security Headers?
HTTP headers that tell browsers how to behave securely when visiting your site.

Key Headers You Need:

1. Content-Security-Policy (CSP)
   • Prevents XSS attacks
   • Controls which resources can load
   • Example: script-src 'self' https://trusted-cdn.com

2. X-Frame-Options
   • Prevents clickjacking attacks
   • Options: DENY, SAMEORIGIN
   • Example: X-Frame-Options: DENY

3. Strict-Transport-Security (HSTS)
   • Forces HTTPS connections
   • Prevents downgrade attacks
   • Example: max-age=31536000; includeSubDomains

4. X-Content-Type-Options
   • Prevents MIME type sniffing
   • Example: nosniff

Quick Implementation:
Add these headers to your Next.js app in next.config.js or middleware.
        """,
        'authentication': """
🔑 Authentication Security - Protecting User Accounts

Common Authentication Mistakes:

❌ Don't store passwords in plain text
❌ Don't use weak password requirements
❌ Don't expose user IDs in URLs
❌ Don't forget to implement rate limiting

✅ Do implement:
• Strong password hashing (bcrypt, Argon2)
• Multi-factor authentication (MFA)
• Session management with secure cookies
• Account lockout after failed attempts
• Password reset with secure tokens

Next.js Best Practices:
• Use NextAuth.js for authentication
• Implement proper session handling
• Use environment variables for secrets
• Add rate limiting to login endpoints
        """
    }
    
    return topic_info.get(topic, f"📚 Information about {topic} coming soon!")

def _has_critical_issues(results: dict) -> bool:
    """Check if scan results contain critical or high severity issues."""
    summary = results.get('summary', {})
    severity_breakdown = summary.get('severity_breakdown', {})
    return severity_breakdown.get('critical', 0) > 0 or severity_breakdown.get('high', 0) > 0

def display_scan_results(results: Dict[str, Any], config: Config, verbose: bool = False):
    """Display scan results in a formatted way."""
    from rich.table import Table
    from rich.panel import Panel
    
    # Extract key information
    summary = results.get('summary', {})
    vulnerabilities = results.get('vulnerabilities', [])
    scan_info = results.get('scan_info', {})
    
    # Display scan summary
    if summary:
        summary_table = Table(title="📊 Scan Summary", show_header=True, header_style="bold magenta")
        summary_table.add_column("Metric", style="cyan", width=20)
        summary_table.add_column("Value", style="green", width=15)
        
        total_issues = summary.get('total_issues', 0)
        severity_breakdown = summary.get('severity_breakdown', {})
        
        summary_table.add_row("Total Issues", str(total_issues))
        summary_table.add_row("Scan Duration", f"{scan_info.get('duration', 'N/A')}")
        summary_table.add_row("Files Scanned", str(scan_info.get('files_scanned', 0)))
        
        if severity_breakdown:
            for severity, count in severity_breakdown.items():
                if count > 0:
                    summary_table.add_row(f"{severity.title()} Issues", str(count))
        
        console.print(summary_table)
    
    # Display vulnerabilities if any
    if vulnerabilities:
        # Handle both flat list and grouped vulnerabilities
        if isinstance(vulnerabilities, dict):
            # Grouped by module
            total_vulns = sum(len(vuln_list) for vuln_list in vulnerabilities.values())
            
            vuln_table = Table(title="🚨 Security Vulnerabilities by Module", show_header=True, header_style="bold red")
            vuln_table.add_column("Module", style="cyan", width=15)
            vuln_table.add_column("Count", style="yellow", width=10)
            vuln_table.add_column("Severities", style="green", width=30)
            
            for module_name, vuln_list in vulnerabilities.items():
                if vuln_list:
                    # Count severities for this module
                    severity_counts = {}
                    for vuln in vuln_list:
                        sev = vuln.get('severity', 'unknown')
                        severity_counts[sev] = severity_counts.get(sev, 0) + 1
                    
                    severity_str = ", ".join([f"{sev}:{count}" for sev, count in severity_counts.items()])
                    vuln_table.add_row(module_name, str(len(vuln_list)), severity_str)
            
            console.print(vuln_table)
            
            # Show detailed vulnerabilities for first few modules
            if verbose:
                console.print(f"\n📋 Detailed findings:")
                for module_name, vuln_list in list(vulnerabilities.items())[:3]:  # Show first 3 modules
                    if vuln_list:
                        module_table = Table(title=f"🔍 {module_name.title()} Module Findings", show_header=True, header_style="bold blue")
                        module_table.add_column("Severity", style="red", width=10)
                        module_table.add_column("Type", style="yellow", width=20)
                        module_table.add_column("Description", style="white", width=50)
                        
                        for vuln in vuln_list[:5]:  # Show first 5 per module
                            severity = vuln.get('severity', 'unknown').upper()
                            vuln_type = vuln.get('vuln_type', 'unknown')
                            description = vuln.get('description', 'No description')[:47] + "..." if len(vuln.get('description', '')) > 50 else vuln.get('description', 'No description')
                            
                            module_table.add_row(severity, vuln_type, description)
                        
                        console.print(module_table)
                        if len(vuln_list) > 5:
                            console.print(f"... and {len(vuln_list) - 5} more in {module_name}")
                        console.print()
                
                if verbose:
                    console.print(f"\n📋 Total vulnerabilities found: {total_vulns}")
        else:
            # Flat list (fallback)
            vuln_table = Table(title="🚨 Security Vulnerabilities", show_header=True, header_style="bold red")
            vuln_table.add_column("Severity", style="red", width=10)
            vuln_table.add_column("Type", style="yellow", width=20)
            vuln_table.add_column("Location", style="cyan", width=30)
            vuln_table.add_column("Description", style="white", width=40)
            
            for vuln in vulnerabilities[:10]:  # Show first 10
                severity = vuln.get('severity', 'unknown').upper()
                vuln_type = vuln.get('vuln_type', 'unknown')
                location = vuln.get('location', 'unknown')
                description = vuln.get('description', 'No description')
                
                vuln_table.add_row(severity, vuln_type, location, description)
            
            if len(vulnerabilities) > 10:
                vuln_table.add_row("...", "...", "...", f"... and {len(vulnerabilities) - 10} more")
            
            console.print(vuln_table)
            
            if verbose:
                console.print(f"\n📋 Full results: {len(vulnerabilities)} vulnerabilities found")
    else:
        console.print("✅ No security vulnerabilities found!", style="green")
    
    # Display scan configuration
    if verbose:
        config_panel = Panel(
            f"Target: {config.target}\n"
            f"Mode: {config.mode}\n"
            f"Framework: {config.framework or 'auto-detected'}\n"
            f"AI Enhanced: {'✅' if config.ai_enhanced else '❌'}\n"
            f"Behavioral Analysis: {'✅' if config.behavioral_analysis else '❌'}",
            title="⚙️ Scan Configuration",
            border_style="blue"
        )
        console.print(config_panel)

def show_banner():
    """Display the NjordScan banner."""
    console.print(BANNER, style="bold cyan")

@click.group(context_settings=dict(help_option_names=['-h', '--help']))
@click.pass_context
def main(ctx):
    """🛡️ NjordScan - The Ultimate Security Scanner for Next.js, React, and Vite applications."""
    
    # Handle version display
    if ctx.invoked_subcommand is None:
        # Show help if no subcommand
        ctx.get_help()
        return

@main.command()
@click.argument('target', default='.')
@click.option('--format', 'output_format', type=click.Choice(['terminal', 'html', 'json', 'sarif', 'csv', 'xml']), 
              default='terminal', help='Output format')
@click.option('--output', '-o', help='Output file path')
@click.option('--mode', type=click.Choice(['quick', 'standard', 'deep', 'enterprise']), 
              default='standard', help='Scanning mode')
@click.option('--framework', type=click.Choice(['auto', 'nextjs', 'react', 'vite']), 
              default='auto', help='Force framework detection')
@click.option('--severity', type=click.Choice(['info', 'low', 'medium', 'high', 'critical']), 
              default='info', help='Minimum severity level')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode (errors only)')
@click.option('--no-cache', is_flag=True, help='Disable caching')
@click.option('--pentest', is_flag=True, help='Enable pentest mode (requires ethical consent)')
@click.option('--explain', help='Explain a specific vulnerability by ID')
@click.option('--interactive', is_flag=True, help='Launch interactive mode with setup wizard')
@click.option('--theme', default='default', 
              type=click.Choice(['default', 'dark', 'cyberpunk', 'hacker', 'professional']),
              help='UI theme')
@click.option('--ai-enhanced', is_flag=True, help='Enable AI-powered analysis')
@click.option('--behavioral-analysis', is_flag=True, help='Enable behavioral anomaly detection')
@click.option('--threat-intel', is_flag=True, help='Enable real-time threat intelligence')
@click.option('--community-rules', is_flag=True, help='Use community security rules')
@click.option('--web', is_flag=True, help='Enable web scanning mode (auto-sets mode to dynamic for URLs)')
@click.option('--threads', type=int, help='Number of scanning threads (auto for optimal)')
@click.option('--cache-strategy', type=click.Choice(['off', 'basic', 'intelligent', 'aggressive']), 
              default='intelligent', help='Caching strategy')
@click.option('--fail-on', type=click.Choice(['critical', 'high', 'medium', 'low']), 
              help='Fail build on severity level')
@click.option('--quality-gate', help='Quality gate policy file')
@click.option('--ci', is_flag=True, help='CI/CD mode (non-interactive)')
@click.option('--show-progress', is_flag=True, help='Show real-time progress')
@click.option('--include-remediation', is_flag=True, help='Include fix suggestions')
@click.option('--executive-summary', is_flag=True, help='Generate executive summary')
@click.option('--skip', multiple=True, help='Skip specific modules (e.g., --skip runtime --skip ai)')
@click.option('--only', multiple=True, help='Run only specific modules')
@click.option('--timeout', type=int, default=300, help='Scan timeout in seconds')
@click.option('--memory-limit', type=int, help='Memory limit in MB')
@click.option('--no-color', is_flag=True, help='Disable colored output')
@click.option('--enhanced', '-e', is_flag=True, help='Use enhanced scanner with advanced features')
@click.option('--custom-rules', is_flag=True, help='Enable custom security rules')
@click.option('--false-positive-filter', is_flag=True, help='Enable false positive filtering')
@click.option('--trend-analysis', is_flag=True, help='Enable trend analysis')
@click.pass_context
def scan(ctx, target, output_format, output, mode, framework, severity, verbose, quiet, 
         no_cache, pentest, explain, interactive, theme, ai_enhanced, behavioral_analysis,
         threat_intel, community_rules, web, threads, cache_strategy, fail_on, quality_gate,
         ci, show_progress, include_remediation, executive_summary, skip, only, timeout,
         memory_limit, no_color, enhanced, custom_rules, false_positive_filter, trend_analysis):
    """🔍 Scan a target for security vulnerabilities."""
    # Show banner unless in quiet mode
    if not quiet and not ci:
        show_banner()
    
    # Handle explain mode
    if explain:
        explain_vulnerability(explain)
        return
    
    # Handle interactive mode
    if interactive:
        if ADVANCED_FEATURES:
            from .developer_experience.interactive_cli import InteractiveCLI
            interactive_cli = InteractiveCLI(theme=theme)
            asyncio.run(interactive_cli.run())
            return
        else:
            console.print("❌ Interactive mode requires advanced features. Please check installation.", style="red")
            return
    
    # Auto-detect web mode for URLs
    if web or (target and target.startswith(('http://', 'https://'))):
        if mode not in ['deep', 'enterprise']:
            mode = 'dynamic'
            if verbose:
                console.print(f"[blue]Auto-detected web target, switching to dynamic mode[/blue]")
    
    # Handle pentest mode warning
    if pentest and not show_pentest_warning():
        console.print("❌ Pentest mode cancelled - ethical consent required.", style="red")
        return
    
    # Create configuration
    config = Config(
        target=target,
        mode=mode,
        framework=framework,
        report_format=output_format,
        output_file=output,
        min_severity=severity,
        verbose=verbose,
        use_cache=not no_cache,
        pentest_mode=pentest,
        theme=theme,
        ai_enhanced=ai_enhanced,
        behavioral_analysis=behavioral_analysis,
        threat_intel=threat_intel,
        community_rules=community_rules,
        threads=threads,
        cache_strategy=cache_strategy,
        ci_mode=ci,
        show_progress=show_progress,
        include_remediation=include_remediation,
        executive_summary=executive_summary,
        timeout=timeout,
        memory_limit=memory_limit,
        no_color=no_color,
        skip_modules=list(skip),
        only_modules=list(only)
    )
    
    try:
        # Run the scan
        if enhanced or ADVANCED_FEATURES and (ai_enhanced or behavioral_analysis or mode == 'enterprise'):
            # Use enhanced scanner for advanced features
            from .scanner_enhanced import EnhancedScanner
            enhanced_scanner = EnhancedScanner(config)
            
            # Configure enhanced options
            enhanced_options = {
                'enable_custom_rules': custom_rules,
                'enable_filtering': false_positive_filter,
                'enable_trends': trend_analysis,
                'verbose': verbose,
                'no_cache': no_cache,
                'pentest': pentest
            }
            
            results = asyncio.run(enhanced_scanner.scan_target(target, mode, enhanced_options))
            
            # Convert to expected format
            results = {
                'success': True,
                'vulnerabilities': results.get('vulnerabilities', []),
                'summary': results.get('summary', {}),
                'scan_info': {
                    'duration': results.get('duration', 'N/A'),
                    'files_scanned': 0
                },
                'data': {
                    'vulnerabilities': results.get('vulnerabilities', []),
                    'summary': results.get('summary', {}),
                    'trends': results.get('trends', {}),
                    'false_positives': results.get('false_positives', []),
                    'custom_rule_matches': results.get('custom_rule_matches', [])
                }
            }
        else:
            # Use standard orchestrator
            if verbose:
                console.print("[blue]Using standard ScanOrchestrator[/blue]")
            orchestrator = ScanOrchestrator(config)
            results = asyncio.run(orchestrator.scan())
        
        # Handle CI/CD exit codes
        if ci and fail_on:
            severity_levels = ['info', 'low', 'medium', 'high', 'critical']
            fail_level_index = severity_levels.index(fail_on)
            
            summary = results.get('summary', {})
            severity_breakdown = summary.get('severity_breakdown', {})
            
            for i in range(fail_level_index, len(severity_levels)):
                if severity_breakdown.get(severity_levels[i], 0) > 0:
                    console.print(f"❌ Build failed: Found {severity_levels[i]} severity issues", style="red")
                    sys.exit(1)
        
        # Display scan results
        if not quiet and not ci:
            # Use orchestrator's display method which includes report saving
            orchestrator.display_results(results)
        else:
            # For quiet/CI mode, still save the report but don't display
            if hasattr(orchestrator, 'display_results'):
                # Save report without displaying
                orchestrator.display_results(results)
        
        console.print("✅ Security scan completed successfully!", style="green")
        
    except KeyboardInterrupt:
        console.print("\n❌ Scan interrupted by user", style="yellow")
        sys.exit(1)
    except ImportError as e:
        console.print(f"❌ Missing dependency: {str(e)}", style="red")
        console.print("💡 Try: pip install njordscan[all]", style="yellow")
        sys.exit(1)
    except FileNotFoundError as e:
        console.print(f"❌ File not found: {str(e)}", style="red")
        console.print("💡 Check if the target path exists and is accessible", style="yellow")
        sys.exit(1)
    except PermissionError as e:
        console.print(f"❌ Permission denied: {str(e)}", style="red")
        console.print("💡 Check file permissions or run with appropriate privileges", style="yellow")
        sys.exit(1)
    except ConnectionError as e:
        console.print(f"❌ Network error: {str(e)}", style="red")
        console.print("💡 Check your internet connection and target accessibility", style="yellow")
        sys.exit(1)
    except TimeoutError as e:
        console.print(f"❌ Operation timed out: {str(e)}", style="red")
        console.print("💡 Try increasing timeout with --timeout option", style="yellow")
        sys.exit(1)
    except Exception as e:
        console.print(f"❌ Scan failed: {str(e)}", style="red")
        if verbose:
            console.print_exception()
        else:
            console.print("💡 Run with --verbose for detailed error information", style="yellow")
        sys.exit(1)

@main.command()
@click.option('--ide', type=click.Choice(['vscode', 'intellij', 'vim', 'lsp']), help='IDE to setup')
@click.option('--ci', type=click.Choice(['github', 'gitlab', 'azure', 'jenkins']), help='CI/CD platform to setup')
@click.option('--framework', type=click.Choice(['nextjs', 'react', 'vite']), help='Framework preset')
@click.option('--level', type=click.Choice(['basic', 'standard', 'advanced', 'enterprise']), 
              default='standard', help='Security level')
def setup(ide, ci, framework, level):
    """🧙‍♂️ Interactive setup wizard for first-time configuration."""
    if ADVANCED_FEATURES:
        from .developer_experience.interactive_cli import setup_wizard
        asyncio.run(setup_wizard(ide=ide, ci=ci, framework=framework, level=level))
    else:
        console.print("❌ Setup wizard requires advanced features. Please check installation.", style="red")

@main.command()
@click.option('--interactive', is_flag=True, help='Interactive configuration editor')
@click.option('--init', is_flag=True, help='Initialize configuration file')
@click.option('--validate', is_flag=True, help='Validate current configuration')
@click.option('--show', is_flag=True, help='Show current configuration')
@click.option('--export', help='Export configuration to file')
@click.option('--framework', type=click.Choice(['nextjs', 'react', 'vite']), help='Framework preset')
def configure(interactive, init, validate, show, export, framework):
    """⚙️ Configuration management and validation."""
    if interactive and ADVANCED_FEATURES:
        from .developer_experience.interactive_cli import interactive_configure
        asyncio.run(interactive_configure())
    elif init:
        config = Config()
        config.save_to_file('.njordscan.json')
        console.print("✅ Configuration file created: .njordscan.json", style="green")
    elif validate:
        try:
            config = Config.load_from_file('.njordscan.json')
            console.print("✅ Configuration is valid", style="green")
        except Exception as e:
            console.print(f"❌ Configuration error: {e}", style="red")
    elif show:
        try:
            config = Config.load_from_file('.njordscan.json')
            config.display()
        except FileNotFoundError:
            console.print("❌ No configuration file found. Run 'njordscan configure --init'", style="red")
    elif export:
        config = Config()
        config.save_to_file(export)
        console.print(f"✅ Configuration exported to: {export}", style="green")
    else:
        console.print("❌ Please specify an action. Use --help for options.", style="red")

@main.command()
@click.option('--interactive', is_flag=True, help='Interactive results browser')
@click.option('--list', 'list_scans', is_flag=True, help='List recent scans')
@click.option('--compare', nargs=2, help='Compare two scan results')
@click.option('--export', help='Export results to file')
@click.option('--format', 'export_format', type=click.Choice(['csv', 'json', 'html']), 
              default='json', help='Export format')
@click.option('--trends', is_flag=True, help='Show security trends')
def results(interactive, list_scans, compare, export, export_format, trends):
    """📊 Browse and analyze scan results."""
    if interactive and ADVANCED_FEATURES:
        from .developer_experience.interactive_cli import interactive_results
        asyncio.run(interactive_results())
    elif list_scans:
        # List recent scans
        cache_manager = CacheManager()
        recent_scans = cache_manager.list_recent_scans()
        
        if not recent_scans:
            console.print("No recent scans found.", style="yellow")
            return
        
        table = Table(title="Recent Scans")
        table.add_column("Date", style="cyan")
        table.add_column("Target", style="green")
        table.add_column("Framework", style="blue")
        table.add_column("Issues", style="red")
        
        for scan in recent_scans[:10]:  # Show last 10
            table.add_row(
                scan.get('date', 'Unknown'),
                scan.get('target', 'Unknown'),
                scan.get('framework', 'Unknown'),
                str(scan.get('total_issues', 0))
            )
        
        console.print(table)
    else:
        console.print("❌ Please specify an action. Use --help for options.", style="red")

@main.command()
@click.option('--interactive', is_flag=True, help='Interactive fix mode')
@click.option('--issue', help='Fix specific issue by ID')
@click.option('--dry-run', is_flag=True, help='Show what would be fixed without applying')
@click.option('--safe-only', is_flag=True, help='Only apply safe fixes')
@click.option('--all', 'fix_all', is_flag=True, help='Fix all auto-fixable issues')
def fix(interactive, issue, dry_run, safe_only, fix_all):
    """🛠️ Interactive fix suggestions and automated remediation."""
    if interactive and ADVANCED_FEATURES:
        from .developer_experience.interactive_cli import interactive_fix
        asyncio.run(interactive_fix())
    else:
        console.print("❌ Fix functionality requires recent scan results.", style="red")

@main.command()
@click.option('--check', is_flag=True, help='Check for updates')
@click.option('--force', is_flag=True, help='Force update (ignore cache)')
@click.option('--source', type=click.Choice(['official', 'community', 'all']), 
              default='official', help='Update source')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def update(check, force, source, verbose):
    """🔄 Update vulnerability database and rules."""
    if not DATA_UPDATER_AVAILABLE:
        console.print("❌ Update functionality requires additional dependencies.", style="red")
        console.print("Install with: pip install njordscan[all]", style="yellow")
        return
    
    try:
        # Create a basic config for the update command
        config = Config(
            target='.',
            mode='standard',
            framework='auto',
            report_format='terminal',
            output_file=None,
            min_severity='info',
            verbose=False,
            use_cache=True,
            pentest_mode=False,
            theme='default',
            ai_enhanced=False,
            behavioral_analysis=False,
            threat_intel=False,
            community_rules=False,
            threads=None,
            cache_strategy='intelligent',
            ci_mode=False,
            show_progress=False,
            include_remediation=False,
            executive_summary=False,
            timeout=300,
            memory_limit=None,
            no_color=False,
            skip_modules=[],
            only_modules=[]
        )
        
        data_manager = VulnerabilityDataManager(config)
        
        if check:
            console.print("🔍 Checking for updates...", style="blue")
            updates_available = asyncio.run(data_manager.check_for_updates())
            
            if any(updates_available.values()):
                console.print("✅ Updates available for the following sources:", style="green")
                for source, needs_update in updates_available.items():
                    if needs_update:
                        console.print(f"  • {source}", style="yellow")
            else:
                console.print("✅ All data sources are up to date", style="green")
        else:
            console.print("🔄 Updating vulnerability database...", style="blue")
            console.print("📡 Fetching data from multiple sources:", style="blue")
            console.print("  • NIST CVE Database", style="cyan")
            console.print("  • MITRE ATT&CK Framework", style="cyan")
            console.print("  • GitHub Security Advisories", style="cyan")
            console.print("  • NPM Security Advisories", style="cyan")
            console.print("  • Framework-specific security data", style="cyan")
            
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
                task = progress.add_task("Updating...", total=None)
                results = asyncio.run(data_manager.update_all_sources(force=force))
            
            # Process and display results
            successful_updates = 0
            failed_updates = 0
            
            console.print("\n📊 Update Results:", style="blue")
            for source, result in results.items():
                if result.get('success', False):
                    if result.get('updated', False):
                        records = result.get('records', 0)
                        console.print(f"  ✅ {source}: {records} records updated", style="green")
                        successful_updates += 1
                    else:
                        console.print(f"  ℹ️ {source}: No changes (up to date)", style="blue")
                else:
                    error = result.get('error', 'Unknown error')
                    console.print(f"  ❌ {source}: {error}", style="red")
                    failed_updates += 1
            
            # Summary
            if successful_updates > 0:
                console.print(f"\n✅ Update completed! {successful_updates} sources updated successfully", style="green")
                if failed_updates > 0:
                    console.print(f"⚠️ {failed_updates} sources had issues", style="yellow")
            else:
                console.print("\n❌ Update failed for all sources", style="red")
                console.print("💡 Try running with --force to ignore cache", style="yellow")
                
    except Exception as e:
        console.print(f"❌ Update error: {str(e)}", style="red")

@main.command()
@click.argument('action', type=click.Choice(['list', 'browse', 'install', 'remove', 'create', 'publish', 'validate', 'test']))
@click.argument('plugin_name', required=False)
@click.option('--template', type=click.Choice(['scanner', 'reporter', 'framework']), help='Plugin template')
@click.option('--marketplace', is_flag=True, help='Use community marketplace')
def plugins(action, plugin_name, template, marketplace):
    """🔌 Plugin management and development."""
    plugin_manager = PluginManager()
    
    try:
        if action == 'list':
            plugins_list = plugin_manager.list_plugins()
            if not plugins_list:
                console.print("No plugins installed.", style="yellow")
                return
            
            table = Table(title="Installed Plugins")
            table.add_column("Name", style="cyan")
            table.add_column("Version", style="green")
            table.add_column("Type", style="blue")
            table.add_column("Status", style="yellow")
            
            for plugin in plugins_list:
                table.add_row(
                    plugin.get('name', 'Unknown'),
                    plugin.get('version', 'Unknown'),
                    plugin.get('type', 'Unknown'),
                    plugin.get('status', 'Unknown')
                )
            
            console.print(table)
            
        elif action == 'browse':
            if marketplace and ADVANCED_FEATURES:
                from .plugins_v2.plugin_marketplace import PluginMarketplace
                marketplace_client = PluginMarketplace()
                asyncio.run(marketplace_client.browse_plugins())
            else:
                console.print("Available plugins:", style="bold")
                console.print("• nextjs-advanced-security - Advanced Next.js security patterns")
                console.print("• react-security-pro - Professional React security analysis")
                console.print("• vite-security-plus - Enhanced Vite security scanning")
                
        elif action == 'install' and plugin_name:
            console.print(f"🔄 Installing plugin: {plugin_name}", style="blue")
            success = plugin_manager.install_plugin(plugin_name)
            if success:
                console.print("✅ Plugin installed successfully!", style="green")
            else:
                console.print("❌ Plugin installation failed", style="red")
                
        elif action == 'create' and plugin_name:
            if template and ADVANCED_FEATURES:
                # Create plugin template using the plugin creator
                from .plugin_creator import create_plugin_template
                try:
                    create_plugin_template(plugin_name, template)
                    console.print(f"✅ Plugin template created: {plugin_name}", style="green")
                except Exception as e:
                    console.print(f"❌ Failed to create plugin template: {e}", style="red")
            else:
                console.print("❌ Plugin creation requires template type", style="red")
                
        else:
            console.print("❌ Invalid plugin action or missing arguments", style="red")
            
    except Exception as e:
        console.print(f"❌ Plugin error: {str(e)}", style="red")

@main.command()
@click.argument('action', type=click.Choice(['register', 'browse', 'challenges', 'mentorship', 'share-rule', 'download-rules']))
@click.option('--category', help='Rule category or challenge type')
@click.option('--file', help='File to share or download to')
def community(action, category, file):
    """🌟 Community features and collaboration."""
    if not ADVANCED_FEATURES:
        console.print("❌ Community features require advanced installation", style="red")
        return
        
    try:
        from .community.community_orchestrator import CommunityOrchestrator
        community_orch = CommunityOrchestrator()
        
        if action == 'register':
            console.print("🌟 Welcome to NjordScan Community!", style="bold cyan")
            console.print("\n🚀 Benefits:")
            console.print("• Access to community security rules")
            console.print("• Share and discover security patterns")
            console.print("• Connect with security experts")
            console.print("• Early access to new features")
            console.print("\n🌐 Visit: https://community.njordscan.dev/register")
            console.print("✅ Community registration information displayed")
        elif action == 'browse':
            console.print("🔍 Community Security Rules Browser", style="bold cyan")
            console.print("\n📚 Available Categories:")
            console.print("• Next.js Security Patterns")
            console.print("• React Security Best Practices")
            console.print("• API Security Rules")
            console.print("• Authentication Patterns")
            console.print("\n🌐 Browse: https://community.njordscan.dev/rules")
            console.print("✅ Community browsing information displayed")
        elif action == 'challenges':
            console.print("🏆 Security Challenges", style="bold cyan")
            console.print("\n🎯 Current Challenges:")
            console.print("• Find XSS in sample applications")
            console.print("• Implement secure authentication")
            console.print("• Create secure API endpoints")
            console.print("• Design secure user interfaces")
            console.print("\n🌐 Join: https://community.njordscan.dev/challenges")
            console.print("✅ Security challenges information displayed")
        elif action == 'mentorship':
            console.print("👥 Security Mentorship Program", style="bold cyan")
            console.print("\n🤝 Available Mentors:")
            console.print("• Web Security Experts")
            console.print("• Next.js Security Specialists")
            console.print("• React Security Consultants")
            console.print("• API Security Architects")
            console.print("\n🌐 Connect: https://community.njordscan.dev/mentorship")
            console.print("✅ Mentorship program information displayed")
        elif action == 'share-rule' and file:
            console.print("📤 Share Security Rule", style="bold cyan")
            console.print("\n📝 What to Share:")
            console.print("• Custom security patterns")
            console.print("• Framework-specific rules")
            console.print("• Vulnerability prevention tips")
            console.print("• Security testing strategies")
            console.print("\n🌐 Submit: https://community.njordscan.dev/share")
            console.print("✅ Security rule sharing information displayed")
        elif action == 'download-rules':
            console.print("⬇️ Download Community Rules", style="bold cyan")
            console.print("\n📦 Available Downloads:")
            console.print("• Next.js Security Rules Pack")
            console.print("• React Security Guidelines")
            console.print("• API Security Standards")
            console.print("• Authentication Best Practices")
            console.print("\n🌐 Download: https://community.njordscan.dev/download")
            console.print("✅ Community rules download information displayed")
        else:
            console.print("❌ Invalid community action or missing arguments", style="red")
            
    except Exception as e:
        console.print(f"❌ Community error: {str(e)}", style="red")

@main.command()
@click.option('--topic', type=click.Choice(['xss', 'sql-injection', 'csrf', 'ssrf', 'nextjs', 'react', 'vite', 'headers', 'authentication']))
@click.option('--framework', type=click.Choice(['nextjs', 'react', 'vite']))
@click.option('--interactive', is_flag=True, help='Interactive learning mode')
def learn(topic, framework, interactive):
    """🎓 Interactive security tutorials and learning."""
    if interactive and ADVANCED_FEATURES:
        from .developer_experience.interactive_cli import interactive_learning
        asyncio.run(interactive_learning(topic=topic, framework=framework))
    else:
        console.print("📚 NjordScan Learning Resources", style="bold cyan")
        
        # Enhanced topic explanations
        if topic:
            console.print(f"\n🎯 Learning about: {topic.upper()}", style="bold yellow")
            topic_info = _get_topic_info(topic)
            console.print(topic_info)
        else:
            console.print("\n🚀 Choose a topic to learn about:")
            topics_table = Table(title="📖 Available Security Topics", show_header=True, header_style="bold green")
            topics_table.add_column("Topic", style="cyan", width=20)
            topics_table.add_column("Description", style="white", width=50)
            topics_table.add_column("Difficulty", style="yellow", width=15)
            
            topics_data = [
                ("XSS", "Cross-Site Scripting attacks and prevention", "Beginner"),
                ("SQL Injection", "Database security and query protection", "Intermediate"),
                ("CSRF", "Cross-Site Request Forgery protection", "Beginner"),
                ("SSRF", "Server-Side Request Forgery prevention", "Advanced"),
                ("Headers", "HTTP security headers and configuration", "Beginner"),
                ("Authentication", "User authentication and session security", "Intermediate"),
                ("Next.js", "Next.js specific security best practices", "Beginner"),
                ("React", "React application security guidelines", "Beginner"),
                ("Vite", "Vite build tool security considerations", "Beginner")
            ]
            
            for topic_name, description, difficulty in topics_data:
                topics_table.add_row(topic_name, description, difficulty)
            
            console.print(topics_table)
        
        console.print("\n🌐 Online Resources:")
        console.print("• Documentation: https://njordscan.dev/docs")
        console.print("• Tutorials: https://njordscan.dev/learn")
        console.print("• Community: https://discord.gg/njordscan")
        console.print("• Interactive Mode: Use --interactive flag for hands-on learning")

@main.command()
@click.argument('vuln_id')
def explain(vuln_id):
    """💡 Get detailed explanation of a vulnerability."""
    explain_vulnerability(vuln_id, console)

@main.group()
def cache():
    """💾 Cache management and statistics."""
    pass

@cache.command()
def stats():
    """📊 Show cache statistics."""
    cache_manager = CacheManager()
    stats = cache_manager.get_stats()
    
    table = Table(title="💾 Cache Statistics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    for key, value in stats.items():
        if key != 'status':
            table.add_row(key.replace('_', ' ').title(), str(value))
    
    console.print(table)
    
    # Show cache status
    status = stats.get('status', 'Unknown')
    if status == 'enabled':
        console.print("✅ Cache is enabled and working", style="green")
    else:
        console.print(f"⚠️ Cache status: {status}", style="yellow")

@cache.command()
def clear():
    """🗑️ Clear all cached data."""
    cache_manager = CacheManager()
    try:
        cache_manager.clear_cache()
        console.print("✅ Cache cleared successfully!", style="green")
    except Exception as e:
        console.print(f"❌ Error clearing cache: {e}", style="red")

@main.command()
def version():
    """📋 Show version information."""
    from . import get_version_info
    
    info = get_version_info()
    
    table = Table(title=f"NjordScan v{info['version']}")
    table.add_column("Component", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Version", info['version'])
    table.add_row("Status", info['status'])
    table.add_row("Author", info['author'])
    table.add_row("License", info['license'])
    table.add_row("Homepage", info['url'])
    table.add_row("Repository", info['repository'])
    table.add_row("Documentation", info['documentation'])
    
    console.print(table)
    
    # Show feature availability
    console.print("\n🚀 Features:", style="bold cyan")
    for feature, enabled in FEATURES.items():
        status = "✅ Enabled" if enabled else "❌ Disabled"
        feature_name = feature.replace('_', ' ').title()
        console.print(f"• {feature_name}: {status}")

@main.command()
def doctor():
    """🩺 System diagnostics and health check."""
    console.print("🩺 NjordScan System Diagnostics", style="bold cyan")
    
    # Check Python version
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    console.print(f"✅ Python Version: {py_version}")
    
    # Check dependencies
    console.print("\n📦 Dependencies:")
    try:
        import click, rich, aiohttp, requests, yaml
        console.print("✅ Core dependencies: OK")
    except ImportError as e:
        console.print(f"❌ Missing core dependency: {e}")
    
    # Check advanced features
    console.print(f"\n🚀 Advanced Features: {'✅ Available' if ADVANCED_FEATURES else '❌ Not Available'}")
    
    # Check configuration
    console.print("\n⚙️ Configuration:")
    if Path('.njordscan.json').exists():
        console.print("✅ Configuration file: Found")
    else:
        console.print("⚠️ Configuration file: Not found (using defaults)")
    
    # Check cache
    cache_manager = CacheManager()
    cache_stats = cache_manager.get_stats()
    console.print(f"💾 Cache: {cache_stats.get('status', 'Unknown')}")
    
    console.print("\n✅ System check complete!")

if __name__ == '__main__':
    main()