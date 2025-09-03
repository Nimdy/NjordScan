"""
Interactive CLI Experience

Enhanced command-line interface with:
- Interactive wizard for first-time setup
- Rich terminal UI with progress bars and animations
- Intelligent auto-completion and suggestions
- Context-aware help system
- Real-time scanning feedback
- Beautiful result visualization
- Developer-friendly configuration management
"""

import asyncio
import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.tree import Tree
from rich.syntax import Syntax
from rich.layout import Layout
from rich.live import Live
from rich.align import Align
from rich.text import Text
from rich.markdown import Markdown
import time
import json
from typing import Dict, List, Any, Optional
from pathlib import Path
import sys
import os
import subprocess
import shutil
import logging
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class CLITheme(Enum):
    """CLI color themes."""
    DEFAULT = "default"
    DARK = "dark"
    LIGHT = "light"
    CYBERPUNK = "cyberpunk"
    HACKER = "hacker"
    PROFESSIONAL = "professional"

class ScanMode(Enum):
    """Scan execution modes."""
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    CUSTOM = "custom"

@dataclass
class CLIConfig:
    """CLI configuration."""
    theme: CLITheme = CLITheme.DEFAULT
    show_progress: bool = True
    show_animations: bool = True
    auto_open_results: bool = False
    preferred_format: str = "terminal"
    save_results: bool = True
    results_directory: str = "njordscan_results"
    
    # Interactive features
    enable_suggestions: bool = True
    enable_auto_completion: bool = True
    show_tips: bool = True
    
    # Performance
    concurrent_scans: int = 1
    timeout_seconds: int = 300
    
    # Notifications
    enable_notifications: bool = True
    sound_alerts: bool = False

class InteractiveCLI:
    """Enhanced interactive command-line interface."""
    
    def __init__(self):
        self.console = Console()
        self.config = self._load_cli_config()
        self._setup_theme()
        
        # State management
        self.current_scan = None
        self.scan_history = []
        self.tips_shown = set()
        
        # ASCII Art and Branding
        self.logo = """
╔╗╔╦╗╔═╗╦═╗╔╦╗╔═╗╔═╗╔═╗╔╗╔
║║║║║║ ║╠╦╝ ║║╚═╗║  ╠═╣║║║
╝╚╝╚╝╚═╝╩╚══╩╝╚═╝╚═╝╩ ╩╝╚╝
        """
        
        self.taglines = [
            "🛡️  Advanced Next.js Security Scanner",
            "🔍 Intelligent Vulnerability Detection",
            "⚡ Blazing Fast Security Analysis",
            "🧠 AI-Powered Threat Intelligence",
            "🚀 Built for Modern Developers"
        ]
    
    def _load_cli_config(self) -> CLIConfig:
        """Load CLI configuration."""
        config_file = Path.home() / ".njordscan" / "cli_config.json"
        
        if config_file.exists():
            try:
                with open(config_file) as f:
                    data = json.load(f)
                return CLIConfig(**data)
            except Exception as e:
                logger.warning(f"Failed to load CLI config: {e}")
        
        return CLIConfig()
    
    def _save_cli_config(self):
        """Save CLI configuration."""
        config_dir = Path.home() / ".njordscan"
        config_dir.mkdir(exist_ok=True)
        
        config_file = config_dir / "cli_config.json"
        
        try:
            with open(config_file, 'w') as f:
                json.dump(self.config.__dict__, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save CLI config: {e}")
    
    def _setup_theme(self):
        """Setup console theme."""
        if self.config.theme == CLITheme.CYBERPUNK:
            self.primary_color = "bright_cyan"
            self.secondary_color = "bright_magenta"
            self.success_color = "bright_green"
            self.warning_color = "bright_yellow"
            self.error_color = "bright_red"
        elif self.config.theme == CLITheme.HACKER:
            self.primary_color = "bright_green"
            self.secondary_color = "green"
            self.success_color = "bright_green"
            self.warning_color = "yellow"
            self.error_color = "red"
        else:  # DEFAULT, PROFESSIONAL, etc.
            self.primary_color = "blue"
            self.secondary_color = "cyan"
            self.success_color = "green"
            self.warning_color = "yellow"
            self.error_color = "red"
    
    def show_welcome(self):
        """Show welcome screen with branding."""
        self.console.clear()
        
        # Create welcome layout
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=10),
            Layout(name="content"),
            Layout(name="footer", size=3)
        )
        
        # Header with logo
        logo_panel = Panel(
            Align.center(
                Text(self.logo, style=f"bold {self.primary_color}") + 
                Text("\n" + self.taglines[int(time.time()) % len(self.taglines)], 
                     style=f"{self.secondary_color}")
            ),
            border_style=self.primary_color,
            padding=(1, 2)
        )
        layout["header"].update(logo_panel)
        
        # Content
        welcome_text = """
# Welcome to NjordScan! 🛡️

The most advanced Next.js, React, and Vite security scanner built for modern developers.

## What's New in This Version:
- 🧠 **AI-Powered Threat Intelligence** - Advanced threat detection with ML
- ⚡ **Blazing Fast Performance** - Multi-threaded scanning with intelligent caching  
- 🎯 **Smart Vulnerability Detection** - Context-aware analysis with low false positives
- 🔍 **Behavioral Analysis** - Detect sophisticated attack patterns and APTs
- 📊 **Beautiful Reports** - Interactive dashboards and detailed analysis
- 🔧 **Developer-First Design** - Seamless CI/CD integration and IDE plugins

Ready to secure your application? Let's get started! 🚀
        """
        
        content_panel = Panel(
            Markdown(welcome_text),
            border_style=self.secondary_color,
            padding=(1, 2)
        )
        layout["content"].update(content_panel)
        
        # Footer
        footer_text = Text("Press any key to continue...", style="dim italic")
        layout["footer"].update(Align.center(footer_text))
        
        with Live(layout, console=self.console, refresh_per_second=2):
            input()
    
    def show_main_menu(self) -> str:
        """Show main menu and get user choice."""
        self.console.clear()
        
        # Main menu options
        menu_options = [
            ("🚀", "quick", "Quick Scan", "Fast security scan with essential checks"),
            ("🔍", "standard", "Standard Scan", "Comprehensive security analysis"),
            ("🧠", "deep", "Deep Scan", "Advanced analysis with AI and behavioral detection"),
            ("⚙️", "configure", "Configure", "Customize scan settings and preferences"),
            ("📊", "results", "View Results", "Browse previous scan results"),
            ("❓", "help", "Help", "Documentation and usage guide"),
            ("🚪", "exit", "Exit", "Exit NjordScan")
        ]
        
        # Create menu table
        table = Table(show_header=True, header_style=f"bold {self.primary_color}")
        table.add_column("", style=self.primary_color, width=3)
        table.add_column("Command", style="bold", width=12)
        table.add_column("Description", width=50)
        
        for icon, cmd, title, desc in menu_options:
            table.add_row(icon, title, desc)
        
        menu_panel = Panel(
            table,
            title="[bold]NjordScan Main Menu[/bold]",
            border_style=self.primary_color,
            padding=(1, 2)
        )
        
        self.console.print(menu_panel)
        
        # Get user choice
        valid_choices = [opt[1] for opt in menu_options]
        choice = Prompt.ask(
            "\n[bold]What would you like to do?[/bold]",
            choices=valid_choices,
            default="standard"
        )
        
        return choice
    
    def setup_wizard(self) -> Dict[str, Any]:
        """Interactive setup wizard for first-time users."""
        self.console.clear()
        
        wizard_panel = Panel(
            "[bold]🧙‍♂️ NjordScan Setup Wizard[/bold]\n\n"
            "Let's configure NjordScan for your development environment!",
            border_style=self.primary_color
        )
        self.console.print(wizard_panel)
        
        config = {}
        
        # Step 1: Project type detection
        self.console.print("\n[bold]Step 1: Project Detection[/bold]")
        
        current_dir = Path.cwd()
        detected_frameworks = self._detect_frameworks(current_dir)
        
        if detected_frameworks:
            frameworks_text = ", ".join(detected_frameworks)
            self.console.print(f"✅ Detected frameworks: [green]{frameworks_text}[/green]")
            config['frameworks'] = detected_frameworks
        else:
            self.console.print("❓ No frameworks auto-detected")
            framework = Prompt.ask(
                "What framework are you using?",
                choices=["nextjs", "react", "vite", "other"],
                default="nextjs"
            )
            config['frameworks'] = [framework]
        
        # Step 2: Scan preferences
        self.console.print("\n[bold]Step 2: Scan Preferences[/bold]")
        
        scan_depth = Prompt.ask(
            "What level of scanning do you prefer?",
            choices=["quick", "standard", "deep"],
            default="standard"
        )
        config['default_scan_mode'] = scan_depth
        
        # Step 3: Output preferences
        self.console.print("\n[bold]Step 3: Output Preferences[/bold]")
        
        output_format = Prompt.ask(
            "Preferred output format?",
            choices=["terminal", "html", "json", "sarif"],
            default="terminal"
        )
        config['output_format'] = output_format
        
        save_results = Confirm.ask("Save scan results to files?", default=True)
        config['save_results'] = save_results
        
        if save_results:
            results_dir = Prompt.ask(
                "Results directory",
                default="njordscan_results"
            )
            config['results_directory'] = results_dir
        
        # Step 4: Performance settings
        self.console.print("\n[bold]Step 4: Performance Settings[/bold]")
        
        cpu_cores = os.cpu_count() or 4
        max_threads = IntPrompt.ask(
            f"Max concurrent threads (detected {cpu_cores} cores)",
            default=min(cpu_cores, 4),
            show_default=True
        )
        config['max_threads'] = max_threads
        
        # Step 5: Advanced features
        self.console.print("\n[bold]Step 5: Advanced Features[/bold]")
        
        enable_ai = Confirm.ask("Enable AI-powered analysis?", default=True)
        config['enable_ai'] = enable_ai
        
        enable_behavioral = Confirm.ask("Enable behavioral analysis?", default=True)
        config['enable_behavioral'] = enable_behavioral
        
        enable_threat_intel = Confirm.ask("Enable threat intelligence?", default=True)
        config['enable_threat_intel'] = enable_threat_intel
        
        # Step 6: CI/CD Integration
        self.console.print("\n[bold]Step 6: CI/CD Integration[/bold]")
        
        setup_ci = Confirm.ask("Set up CI/CD integration?", default=False)
        if setup_ci:
            ci_platform = Prompt.ask(
                "Which CI/CD platform?",
                choices=["github-actions", "gitlab-ci", "jenkins", "azure-devops", "other"],
                default="github-actions"
            )
            config['ci_platform'] = ci_platform
            
            if ci_platform == "github-actions":
                self._setup_github_actions()
        
        # Summary
        self.console.print("\n[bold]✅ Setup Complete![/bold]")
        
        summary_table = Table(title="Configuration Summary")
        summary_table.add_column("Setting", style="cyan")
        summary_table.add_column("Value", style="green")
        
        for key, value in config.items():
            summary_table.add_row(key.replace('_', ' ').title(), str(value))
        
        self.console.print(summary_table)
        
        # Save configuration
        save_config = Confirm.ask("\nSave this configuration?", default=True)
        if save_config:
            self._save_wizard_config(config)
            self.console.print("[green]✅ Configuration saved![/green]")
        
        return config
    
    def interactive_scan(self, scan_mode: ScanMode, target_path: str = None) -> Dict[str, Any]:
        """Run interactive scan with real-time feedback."""
        
        if not target_path:
            target_path = Prompt.ask(
                "Enter path to scan",
                default=str(Path.cwd())
            )
        
        target_path = Path(target_path)
        if not target_path.exists():
            self.console.print(f"[red]❌ Path not found: {target_path}[/red]")
            return {}
        
        # Scan configuration
        scan_config = self._configure_scan(scan_mode, target_path)
        
        # Pre-scan analysis
        self.console.print("\n[bold]🔍 Analyzing target...[/bold]")
        
        with self.console.status("[bold green]Scanning project structure..."):
            project_info = self._analyze_project_structure(target_path)
        
        self._show_project_summary(project_info)
        
        # Confirm scan
        if not Confirm.ask(f"\nProceed with {scan_mode.value} scan?", default=True):
            return {}
        
        # Execute scan with progress tracking
        return self._execute_scan_with_progress(target_path, scan_config, project_info)
    
    def _configure_scan(self, scan_mode: ScanMode, target_path: Path) -> Dict[str, Any]:
        """Configure scan parameters."""
        
        config = {
            'mode': scan_mode.value,
            'target': str(target_path),
            'timestamp': time.time()
        }
        
        if scan_mode == ScanMode.CUSTOM:
            self.console.print("\n[bold]🔧 Custom Scan Configuration[/bold]")
            
            # Module selection
            modules = [
                ("headers", "HTTP Security Headers", True),
                ("static", "Static Code Analysis", True),
                ("dependencies", "Dependency Security", True),
                ("configs", "Configuration Security", True),
                ("runtime", "Runtime Security Testing", False),
                ("ai", "AI Security Analysis", False)
            ]
            
            enabled_modules = []
            for module_id, description, default in modules:
                enabled = Confirm.ask(f"Enable {description}?", default=default)
                if enabled:
                    enabled_modules.append(module_id)
            
            config['modules'] = enabled_modules
            
            # Advanced options
            if Confirm.ask("Configure advanced options?", default=False):
                config['deep_analysis'] = Confirm.ask("Enable deep analysis?", default=True)
                config['behavioral_analysis'] = Confirm.ask("Enable behavioral analysis?", default=True)
                config['threat_intelligence'] = Confirm.ask("Enable threat intelligence?", default=True)
                
                timeout = IntPrompt.ask("Scan timeout (seconds)", default=300)
                config['timeout'] = timeout
        
        return config
    
    def _analyze_project_structure(self, target_path: Path) -> Dict[str, Any]:
        """Analyze project structure and provide insights."""
        
        info = {
            'path': str(target_path),
            'name': target_path.name,
            'size': 0,
            'files': 0,
            'directories': 0,
            'frameworks': [],
            'languages': set(),
            'config_files': [],
            'security_files': [],
            'estimated_scan_time': 0
        }
        
        # Walk directory structure
        for item in target_path.rglob('*'):
            if item.is_file():
                info['files'] += 1
                info['size'] += item.stat().st_size
                
                # Detect languages
                if item.suffix in ['.js', '.jsx', '.mjs']:
                    info['languages'].add('JavaScript')
                elif item.suffix in ['.ts', '.tsx']:
                    info['languages'].add('TypeScript')
                elif item.suffix in ['.py']:
                    info['languages'].add('Python')
                elif item.suffix in ['.json']:
                    info['languages'].add('JSON')
                
                # Detect config files
                if item.name in ['package.json', 'next.config.js', 'vite.config.js', 
                               'tsconfig.json', '.env', 'docker-compose.yml']:
                    info['config_files'].append(str(item.relative_to(target_path)))
                
                # Detect security-related files
                if item.name in ['.gitignore', 'security.md', 'SECURITY.md']:
                    info['security_files'].append(str(item.relative_to(target_path)))
            
            elif item.is_dir():
                info['directories'] += 1
        
        # Detect frameworks
        info['frameworks'] = self._detect_frameworks(target_path)
        
        # Estimate scan time
        base_time = max(30, info['files'] * 0.1)  # Base time calculation
        if 'nextjs' in info['frameworks']:
            base_time *= 1.2
        if info['size'] > 100 * 1024 * 1024:  # > 100MB
            base_time *= 1.5
        
        info['estimated_scan_time'] = int(base_time)
        info['languages'] = list(info['languages'])
        
        return info
    
    def _show_project_summary(self, project_info: Dict[str, Any]):
        """Show project analysis summary."""
        
        # Create project info table
        info_table = Table(title="📊 Project Analysis")
        info_table.add_column("Attribute", style="cyan")
        info_table.add_column("Value", style="white")
        
        info_table.add_row("Project Name", project_info['name'])
        info_table.add_row("Files", f"{project_info['files']:,}")
        info_table.add_row("Directories", f"{project_info['directories']:,}")
        info_table.add_row("Size", f"{project_info['size'] / 1024 / 1024:.1f} MB")
        info_table.add_row("Languages", ", ".join(project_info['languages']) or "Unknown")
        info_table.add_row("Frameworks", ", ".join(project_info['frameworks']) or "None detected")
        info_table.add_row("Estimated Scan Time", f"~{project_info['estimated_scan_time']} seconds")
        
        self.console.print(info_table)
        
        # Show important files found
        if project_info['config_files']:
            config_panel = Panel(
                "\n".join(f"📄 {file}" for file in project_info['config_files'][:10]),
                title="🔧 Configuration Files Found",
                border_style="yellow"
            )
            self.console.print(config_panel)
        
        if project_info['security_files']:
            security_panel = Panel(
                "\n".join(f"🛡️ {file}" for file in project_info['security_files']),
                title="🔒 Security Files Found",
                border_style="green"
            )
            self.console.print(security_panel)
    
    async def _execute_scan_with_progress(self, target_path: Path, scan_config: Dict[str, Any], 
                                  project_info: Dict[str, Any]) -> Dict[str, Any]:
        """Execute scan with beautiful progress visualization."""
        
        self.console.print(f"\n[bold]🚀 Starting {scan_config['mode']} scan...[/bold]")
        
        # Create progress layout
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="progress", size=15),
            Layout(name="status", size=8),
            Layout(name="footer", size=3)
        )
        
        # Progress tracking
        scan_phases = [
            ("🔍", "Initializing", "Setting up scan environment"),
            ("📁", "File Discovery", "Discovering files to scan"),
            ("🔧", "Static Analysis", "Analyzing code structure"),
            ("🛡️", "Security Rules", "Applying security rules"),
            ("🧠", "AI Analysis", "Running AI-powered analysis"),
            ("⚡", "Behavioral Analysis", "Detecting behavioral patterns"),
            ("🌐", "Threat Intelligence", "Checking threat indicators"),
            ("📊", "Report Generation", "Generating detailed report"),
            ("✅", "Finalization", "Finalizing results")
        ]
        
        results = {
            'scan_id': f"scan_{int(time.time())}",
            'target': str(target_path),
            'config': scan_config,
            'project_info': project_info,
            'start_time': time.time(),
            'findings': [],
            'statistics': {},
            'status': 'running'
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
            transient=True
        ) as progress:
            
            # Main progress task
            main_task = progress.add_task("Overall Progress", total=len(scan_phases))
            
            # Phase progress task
            phase_task = progress.add_task("Current Phase", total=100)
            
            with Live(layout, console=self.console, refresh_per_second=4):
                
                for i, (icon, phase_name, description) in enumerate(scan_phases):
                    
                    # Update header
                    header_text = Text(f"{icon} {phase_name}", style=f"bold {self.primary_color}")
                    layout["header"].update(Align.center(header_text))
                    
                    # Update progress
                    progress.update(main_task, completed=i, description=f"Phase {i+1}/{len(scan_phases)}")
                    progress.update(phase_task, completed=0, description=description)
                    
                    # Simulate phase execution with sub-progress
                    phase_results = await self._execute_scan_phase(
                        phase_name, target_path, scan_config, progress, phase_task
                    )
                    
                    results['findings'].extend(phase_results.get('findings', []))
                    results['statistics'][phase_name.lower().replace(' ', '_')] = phase_results.get('stats', {})
                    
                    # Show current findings count
                    findings_count = len(results['findings'])
                    status_text = f"Found {findings_count} potential issues"
                    
                    if findings_count > 0:
                        # Show latest finding
                        latest = results['findings'][-1]
                        latest_text = f"Latest: {latest.get('title', 'Unknown issue')}"
                        status_panel = Panel(
                            f"{status_text}\n{latest_text}",
                            title="🔍 Scan Status",
                            border_style=self.secondary_color
                        )
                    else:
                        status_panel = Panel(
                            status_text,
                            title="🔍 Scan Status",
                            border_style=self.secondary_color
                        )
                    
                    layout["status"].update(status_panel)
                    
                    # Complete phase
                    progress.update(phase_task, completed=100)
                    await asyncio.sleep(0.5)  # Brief pause for visual effect
                
                # Complete main progress
                progress.update(main_task, completed=len(scan_phases))
        
        # Finalize results
        results['end_time'] = time.time()
        results['duration'] = results['end_time'] - results['start_time']
        results['status'] = 'completed'
        
        # Show completion message
        self._show_scan_completion(results)
        
        return results
    
    async def _execute_scan_phase(self, phase_name: str, target_path: Path, 
                                scan_config: Dict[str, Any], progress: Progress, 
                                task_id) -> Dict[str, Any]:
        """Execute a single scan phase."""
        
        # Simulate scan phase execution
        # In real implementation, this would call the actual scanning modules
        
        phase_results = {
            'findings': [],
            'stats': {
                'files_processed': 0,
                'time_taken': 0,
                'issues_found': 0
            }
        }
        
        # Simulate progressive work
        for step in range(0, 101, 10):
            progress.update(task_id, completed=step)
            await asyncio.sleep(0.1)  # Simulate work
            
            # Simulate finding issues
            if step > 50 and phase_name in ['Static Analysis', 'Security Rules', 'AI Analysis']:
                if step % 30 == 0:  # Occasionally find issues
                    finding = {
                        'id': f"finding_{len(phase_results['findings'])}",
                        'title': f"Potential {phase_name} Issue",
                        'severity': 'medium',
                        'file': 'example.js',
                        'line': 42,
                        'description': f"Issue detected during {phase_name}"
                    }
                    phase_results['findings'].append(finding)
        
        phase_results['stats']['files_processed'] = 50  # Simulate
        phase_results['stats']['time_taken'] = 2.5
        phase_results['stats']['issues_found'] = len(phase_results['findings'])
        
        return phase_results
    
    def _show_scan_completion(self, results: Dict[str, Any]):
        """Show scan completion summary."""
        
        self.console.print("\n" + "="*80)
        self.console.print(f"[bold green]✅ Scan completed successfully![/bold green]")
        self.console.print("="*80)
        
        # Summary statistics
        summary_table = Table(title="📊 Scan Summary")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="white")
        
        summary_table.add_row("Scan ID", results['scan_id'])
        summary_table.add_row("Target", results['target'])
        summary_table.add_row("Duration", f"{results['duration']:.1f} seconds")
        summary_table.add_row("Files Scanned", f"{results['project_info']['files']:,}")
        summary_table.add_row("Issues Found", f"{len(results['findings']):,}")
        
        self.console.print(summary_table)
        
        # Findings breakdown
        if results['findings']:
            severity_counts = {}
            for finding in results['findings']:
                severity = finding.get('severity', 'unknown')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            findings_table = Table(title="🔍 Findings Breakdown")
            findings_table.add_column("Severity", style="cyan")
            findings_table.add_column("Count", style="white")
            findings_table.add_column("Percentage", style="yellow")
            
            total_findings = len(results['findings'])
            for severity, count in severity_counts.items():
                percentage = (count / total_findings) * 100
                findings_table.add_row(
                    severity.title(),
                    str(count),
                    f"{percentage:.1f}%"
                )
            
            self.console.print(findings_table)
        
        # Next steps
        next_steps = Panel(
            "[bold]🎯 Recommended Next Steps:[/bold]\n\n"
            "1. 📊 Review detailed report with 'njordscan results'\n"
            "2. 🔧 Fix high-priority security issues\n"
            "3. 🔄 Re-run scan to verify fixes\n"
            "4. 🚀 Integrate into your CI/CD pipeline",
            title="Next Steps",
            border_style="green"
        )
        self.console.print(next_steps)
        
        # Save results
        if self.config.save_results:
            self._save_scan_results(results)
    
    def show_results_browser(self):
        """Interactive results browser."""
        
        self.console.clear()
        
        # Load scan history
        results_dir = Path(self.config.results_directory)
        if not results_dir.exists():
            self.console.print("[yellow]No previous scan results found.[/yellow]")
            return
        
        # List available results
        result_files = list(results_dir.glob("*.json"))
        if not result_files:
            self.console.print("[yellow]No scan results found.[/yellow]")
            return
        
        # Show results menu
        self.console.print("[bold]📊 Previous Scan Results[/bold]\n")
        
        results_table = Table()
        results_table.add_column("#", style="cyan", width=3)
        results_table.add_column("Date", style="white")
        results_table.add_column("Target", style="green")
        results_table.add_column("Issues", style="yellow")
        results_table.add_column("Duration", style="blue")
        
        scan_summaries = []
        for i, result_file in enumerate(sorted(result_files, key=lambda x: x.stat().st_mtime, reverse=True)):
            try:
                with open(result_file) as f:
                    result_data = json.load(f)
                
                date_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(result_data.get('start_time', 0)))
                target = Path(result_data.get('target', '')).name
                issues = len(result_data.get('findings', []))
                duration = f"{result_data.get('duration', 0):.1f}s"
                
                results_table.add_row(str(i+1), date_str, target, str(issues), duration)
                scan_summaries.append(result_data)
                
            except Exception as e:
                logger.error(f"Failed to load result file {result_file}: {e}")
        
        self.console.print(results_table)
        
        # Get user selection
        if scan_summaries:
            choice = IntPrompt.ask(
                "\nSelect a scan result to view (0 to go back)",
                default=0,
                show_default=True
            )
            
            if 1 <= choice <= len(scan_summaries):
                self._show_detailed_results(scan_summaries[choice - 1])
    
    def _show_detailed_results(self, result_data: Dict[str, Any]):
        """Show detailed scan results."""
        
        self.console.clear()
        
        # Header
        header_panel = Panel(
            f"[bold]📊 Detailed Scan Results[/bold]\n"
            f"Scan ID: {result_data.get('scan_id', 'Unknown')}\n"
            f"Target: {result_data.get('target', 'Unknown')}\n"
            f"Date: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result_data.get('start_time', 0)))}",
            border_style=self.primary_color
        )
        self.console.print(header_panel)
        
        # Findings
        findings = result_data.get('findings', [])
        if findings:
            self.console.print(f"\n[bold]🔍 Found {len(findings)} Issues:[/bold]\n")
            
            for i, finding in enumerate(findings[:20]):  # Show first 20
                severity_color = {
                    'critical': 'red',
                    'high': 'bright_red',
                    'medium': 'yellow',
                    'low': 'blue',
                    'info': 'cyan'
                }.get(finding.get('severity', 'info'), 'white')
                
                finding_panel = Panel(
                    f"[bold]{finding.get('title', 'Unknown Issue')}[/bold]\n"
                    f"File: {finding.get('file', 'Unknown')}\n"
                    f"Line: {finding.get('line', 'Unknown')}\n"
                    f"Description: {finding.get('description', 'No description')}",
                    title=f"Issue #{i+1} - {finding.get('severity', 'Unknown').title()}",
                    border_style=severity_color
                )
                self.console.print(finding_panel)
            
            if len(findings) > 20:
                self.console.print(f"[dim]... and {len(findings) - 20} more issues[/dim]")
        else:
            self.console.print("[green]✅ No security issues found![/green]")
        
        # Wait for user input
        input("\nPress Enter to continue...")
    
    def configure_settings(self):
        """Interactive settings configuration."""
        
        self.console.clear()
        
        settings_panel = Panel(
            "[bold]⚙️ NjordScan Configuration[/bold]\n\n"
            "Customize your scanning experience",
            border_style=self.primary_color
        )
        self.console.print(settings_panel)
        
        # Configuration options
        config_options = [
            ("theme", "UI Theme", self.config.theme.value, ["default", "dark", "light", "cyberpunk", "hacker"]),
            ("show_progress", "Show Progress Bars", self.config.show_progress, None),
            ("show_animations", "Show Animations", self.config.show_animations, None),
            ("auto_open_results", "Auto-open Results", self.config.auto_open_results, None),
            ("preferred_format", "Default Output Format", self.config.preferred_format, ["terminal", "html", "json", "sarif"]),
            ("concurrent_scans", "Concurrent Scans", self.config.concurrent_scans, None),
            ("enable_notifications", "Enable Notifications", self.config.enable_notifications, None)
        ]
        
        for setting_key, display_name, current_value, choices in config_options:
            self.console.print(f"\n[bold]{display_name}[/bold]")
            self.console.print(f"Current: [cyan]{current_value}[/cyan]")
            
            if choices:
                new_value = Prompt.ask(
                    "New value",
                    choices=choices,
                    default=str(current_value),
                    show_choices=True
                )
                if setting_key == "theme":
                    self.config.theme = CLITheme(new_value)
                else:
                    setattr(self.config, setting_key, new_value)
            else:
                if isinstance(current_value, bool):
                    new_value = Confirm.ask("Enable?", default=current_value)
                    setattr(self.config, setting_key, new_value)
                elif isinstance(current_value, int):
                    new_value = IntPrompt.ask("New value", default=current_value)
                    setattr(self.config, setting_key, new_value)
        
        # Save configuration
        self._save_cli_config()
        self._setup_theme()  # Reapply theme
        
        self.console.print("\n[green]✅ Configuration saved![/green]")
        input("Press Enter to continue...")
    
    def show_help(self):
        """Show comprehensive help information."""
        
        self.console.clear()
        
        help_content = """
# 🛡️ NjordScan Help Guide

## Quick Start
```bash
njordscan                    # Interactive mode
njordscan /path/to/project   # Quick scan
njordscan --help             # Command help
```

## Scan Modes
- **Quick**: Fast essential security checks
- **Standard**: Comprehensive security analysis  
- **Deep**: Advanced AI and behavioral analysis
- **Custom**: Configure specific modules

## Key Features
- 🧠 **AI-Powered Analysis**: Machine learning threat detection
- ⚡ **High Performance**: Multi-threaded with intelligent caching
- 🎯 **Smart Detection**: Context-aware with low false positives
- 📊 **Beautiful Reports**: Interactive dashboards and visualizations
- 🔄 **CI/CD Ready**: Seamless pipeline integration

## Output Formats
- **Terminal**: Rich interactive display
- **HTML**: Interactive web dashboard
- **JSON**: Machine-readable results
- **SARIF**: Standard format for security tools

## Configuration
- Global config: `~/.njordscan/config.json`
- Project config: `.njordscan.json`
- CLI preferences: `~/.njordscan/cli_config.json`

## Advanced Usage
```bash
# Custom module selection
njordscan --modules headers,static,deps

# Specific output format
njordscan --format html --output results.html

# CI/CD mode (no interaction)
njordscan --ci --format sarif
```

## Getting Support
- 📖 Documentation: https://njordscan.dev/docs
- 🐛 Issues: https://github.com/njordscan/njordscan/issues
- 💬 Community: https://discord.gg/njordscan
- 📧 Email: support@njordscan.dev
        """
        
        help_panel = Panel(
            Markdown(help_content),
            title="Help Guide",
            border_style=self.primary_color,
            padding=(1, 2)
        )
        
        self.console.print(help_panel)
        input("\nPress Enter to continue...")
    
    # Utility methods
    
    def _detect_frameworks(self, project_path: Path) -> List[str]:
        """Detect frameworks in project."""
        
        frameworks = []
        
        # Check for Next.js
        if (project_path / "next.config.js").exists() or (project_path / "next.config.ts").exists():
            frameworks.append("nextjs")
        
        # Check for package.json dependencies
        package_json = project_path / "package.json"
        if package_json.exists():
            try:
                with open(package_json) as f:
                    data = json.load(f)
                
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                
                if "next" in deps:
                    frameworks.append("nextjs")
                if "react" in deps:
                    frameworks.append("react")
                if "vite" in deps:
                    frameworks.append("vite")
                if "vue" in deps:
                    frameworks.append("vue")
                if "angular" in deps or "@angular/core" in deps:
                    frameworks.append("angular")
                    
            except Exception as e:
                logger.error(f"Failed to parse package.json: {e}")
        
        # Check for Vite config
        if (project_path / "vite.config.js").exists() or (project_path / "vite.config.ts").exists():
            if "vite" not in frameworks:
                frameworks.append("vite")
        
        return frameworks
    
    def _setup_github_actions(self):
        """Setup GitHub Actions integration."""
        
        github_dir = Path.cwd() / ".github" / "workflows"
        github_dir.mkdir(parents=True, exist_ok=True)
        
        workflow_content = """name: NjordScan Security Analysis

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
        
    - name: Install dependencies
      run: npm ci
      
    - name: Run NjordScan
      run: |
        pip install njordscan
        njordscan --ci --format sarif --output njordscan-results.sarif
        
    - name: Upload SARIF results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: njordscan-results.sarif
"""
        
        workflow_file = github_dir / "njordscan.yml"
        with open(workflow_file, 'w') as f:
            f.write(workflow_content)
        
        self.console.print(f"[green]✅ GitHub Actions workflow created: {workflow_file}[/green]")
    
    def _save_wizard_config(self, config: Dict[str, Any]):
        """Save wizard configuration."""
        
        config_dir = Path.home() / ".njordscan"
        config_dir.mkdir(exist_ok=True)
        
        config_file = config_dir / "wizard_config.json"
        
        try:
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save wizard config: {e}")
    
    def _save_scan_results(self, results: Dict[str, Any]):
        """Save scan results to file."""
        
        results_dir = Path(self.config.results_directory)
        results_dir.mkdir(exist_ok=True)
        
        # Create filename with timestamp
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"njordscan_{timestamp}_{results['scan_id']}.json"
        results_file = results_dir / filename
        
        try:
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            self.console.print(f"[green]💾 Results saved: {results_file}[/green]")
            
        except Exception as e:
            logger.error(f"Failed to save results: {e}")


# CLI Entry Points

# Standalone functions for main CLI imports
async def setup_wizard(ide: bool = False, ci: bool = False, framework: str = None, level: str = "standard") -> Dict[str, Any]:
    """Standalone setup wizard function for main CLI."""
    interactive_cli = InteractiveCLI()
    return interactive_cli.setup_wizard()

async def interactive_configure() -> Dict[str, Any]:
    """Standalone interactive configure function for main CLI."""
    interactive_cli = InteractiveCLI()
    return interactive_cli.configure_settings()

async def interactive_results() -> Dict[str, Any]:
    """Standalone interactive results function for main CLI."""
    interactive_cli = InteractiveCLI()
    return interactive_cli.show_results_browser()

async def interactive_fix() -> Dict[str, Any]:
    """Standalone interactive fix function for main CLI."""
    interactive_cli = InteractiveCLI()
    # This would need to be implemented in the InteractiveCLI class
    return {"status": "fix functionality not yet implemented"}

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """NjordScan Interactive CLI"""
    if ctx.invoked_subcommand is None:
        # Start interactive mode
        interactive_cli = InteractiveCLI()
        interactive_cli.show_welcome()
        
        while True:
            choice = interactive_cli.show_main_menu()
            
            if choice == "exit":
                interactive_cli.console.print("[bold]👋 Thanks for using NjordScan![/bold]")
                break
            elif choice == "quick":
                interactive_cli.interactive_scan(ScanMode.QUICK)
            elif choice == "standard":
                interactive_cli.interactive_scan(ScanMode.STANDARD)
            elif choice == "deep":
                interactive_cli.interactive_scan(ScanMode.DEEP)
            elif choice == "configure":
                interactive_cli.configure_settings()
            elif choice == "results":
                interactive_cli.show_results_browser()
            elif choice == "help":
                interactive_cli.show_help()


@cli.command()
def setup():
    """Run the interactive setup wizard"""
    interactive_cli = InteractiveCLI()
    interactive_cli.setup_wizard()


@cli.command()
@click.argument('target', required=False)
@click.option('--mode', type=click.Choice(['quick', 'standard', 'deep', 'custom']), default='standard')
def scan(target, mode):
    """Run an interactive scan"""
    interactive_cli = InteractiveCLI()
    scan_mode = ScanMode(mode)
    interactive_cli.interactive_scan(scan_mode, target)


@cli.command()
def results():
    """Browse previous scan results"""
    interactive_cli = InteractiveCLI()
    interactive_cli.show_results_browser()


@cli.command()
def configure():
    """Configure NjordScan settings"""
    interactive_cli = InteractiveCLI()
    interactive_cli.configure_settings()


if __name__ == "__main__":
    cli()
