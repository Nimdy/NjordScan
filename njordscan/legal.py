"""
Legal Disclaimer and Terms Acceptance Module

Handles legal disclaimers, terms acceptance, and caching for NjordScan.
"""

import os
import time
import json
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass
import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

@dataclass
class LegalAcceptance:
    """Legal acceptance record."""
    accepted: bool
    timestamp: float
    version: str
    user_id: Optional[str] = None

class LegalManager:
    """Manages legal disclaimers and terms acceptance."""
    
    def __init__(self):
        self.cache_file = Path.home() / '.njordscan' / 'legal_acceptance.json'
        self.cache_file.parent.mkdir(exist_ok=True)
        self.disclaimer_version = "1.0.0"
        self.cache_duration = 3 * 3600  # 3 hours in seconds
    
    def get_legal_disclaimer(self) -> str:
        """Get the full legal disclaimer text."""
        return """
╔══════════════════════════════════════════════════════════════════════════════╗
║                           ⚖️  LEGAL DISCLAIMER                              ║
║                                                                              ║
║  IMPORTANT: READ THIS DISCLAIMER CAREFULLY BEFORE USING NJORDSCAN          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

TERMS OF USE AND LIABILITY DISCLAIMER

By using NjordScan, you acknowledge and agree to the following terms:

1. NO WARRANTY
   • NjordScan is provided "AS IS" without any warranty, express or implied
   • We make no representations or warranties regarding the accuracy, reliability, 
     or completeness of scan results
   • We do not guarantee that NjordScan will detect all vulnerabilities

2. LIMITATION OF LIABILITY
   • YOU USE NJORDSCAN AT YOUR OWN RISK
   • We are not responsible for any damage, loss, or harm caused by:
     - Use or misuse of this software
     - False positives or false negatives in scan results
     - System instability, crashes, or data loss
     - Any security incidents that occur before, during, or after scanning
     - Actions taken based on scan results

3. ETHICAL USE ONLY
   • ONLY USE ON SYSTEMS YOU OWN OR HAVE EXPLICIT PERMISSION TO TEST
   • Unauthorized scanning of systems is illegal and prohibited
   • You are solely responsible for ensuring you have proper authorization
   • We are not responsible for any legal consequences of unauthorized use

4. PROFESSIONAL ADVICE
   • Scan results are for informational purposes only
   • They do not constitute professional security advice
   • Consult qualified security professionals for critical security decisions
   • We recommend independent verification of all findings

5. DATA AND PRIVACY
   • Scan results may contain sensitive information
   • You are responsible for protecting and securing scan data
   • We are not responsible for data breaches or privacy violations

6. THIRD-PARTY DEPENDENCIES
   • NjordScan uses third-party libraries and services
   • We are not responsible for vulnerabilities in third-party components
   • Use of external APIs is subject to their respective terms of service

7. UPDATES AND CHANGES
   • Software may be updated without notice
   • We reserve the right to modify or discontinue the software
   • Previous versions may become unsupported

ACCEPTANCE OF TERMS
By running NjordScan, you confirm that you have read, understood, and agree to be 
bound by this disclaimer. If you do not agree to these terms, do not use this software.

For the full disclaimer, visit: https://github.com/nimdy/njordscan/blob/main/README.md
        """
    
    def load_acceptance(self) -> Optional[LegalAcceptance]:
        """Load legal acceptance from cache."""
        try:
            if not self.cache_file.exists():
                return None
            
            with open(self.cache_file, 'r') as f:
                data = json.load(f)
            
            acceptance = LegalAcceptance(**data)
            
            # Check if cache is still valid
            if time.time() - acceptance.timestamp > self.cache_duration:
                return None
            
            # Check if version matches
            if acceptance.version != self.disclaimer_version:
                return None
            
            return acceptance
            
        except (json.JSONDecodeError, KeyError, TypeError):
            return None
    
    def save_acceptance(self, accepted: bool, user_id: Optional[str] = None):
        """Save legal acceptance to cache."""
        acceptance = LegalAcceptance(
            accepted=accepted,
            timestamp=time.time(),
            version=self.disclaimer_version,
            user_id=user_id
        )
        
        with open(self.cache_file, 'w') as f:
            json.dump(acceptance.__dict__, f, indent=2)
    
    def show_disclaimer(self) -> bool:
        """Show legal disclaimer and get user acceptance."""
        # Check if already accepted recently
        acceptance = self.load_acceptance()
        if acceptance and acceptance.accepted:
            return True
        
        # Show disclaimer
        disclaimer_text = self.get_legal_disclaimer()
        
        # Create a scrollable panel
        panel = Panel(
            Text(disclaimer_text, style="white"),
            title="[bold red]LEGAL DISCLAIMER[/bold red]",
            border_style="red",
            padding=(1, 2),
            width=100
        )
        
        console.print(panel)
        console.print()
        
        # Get user acceptance
        while True:
            try:
                response = click.prompt(
                    "\n[bold]Do you accept these terms and conditions?[/bold]",
                    type=click.Choice(['yes', 'no', 'y', 'n'], case_sensitive=False),
                    default='no'
                ).lower()
                
                if response in ['yes', 'y']:
                    self.save_acceptance(True)
                    console.print("\n[green]✓ Terms accepted. You can now use NjordScan.[/green]")
                    return True
                elif response in ['no', 'n']:
                    console.print("\n[red]✗ Terms not accepted. NjordScan cannot be used.[/red]")
                    console.print("[yellow]Please read the full disclaimer at:[/yellow]")
                    console.print("[blue]https://github.com/nimdy/njordscan/blob/main/README.md[/blue]")
                    return False
                else:
                    console.print("[red]Please enter 'yes' or 'no'[/red]")
                    
            except (KeyboardInterrupt, EOFError):
                console.print("\n[yellow]Operation cancelled.[/yellow]")
                return False
    
    def check_acceptance(self) -> bool:
        """Check if user has accepted terms recently."""
        acceptance = self.load_acceptance()
        return acceptance is not None and acceptance.accepted
    
    def force_show_disclaimer(self) -> bool:
        """Force show disclaimer regardless of cache."""
        return self.show_disclaimer()
    
    def clear_acceptance(self):
        """Clear cached acceptance (for testing or re-acceptance)."""
        if self.cache_file.exists():
            self.cache_file.unlink()

# Global legal manager instance
legal_manager = LegalManager()

def require_legal_acceptance(func):
    """Decorator to require legal acceptance before running commands."""
    def wrapper(*args, **kwargs):
        if not legal_manager.check_acceptance():
            if not legal_manager.show_disclaimer():
                console.print("\n[red]❌ Legal terms not accepted. Exiting.[/red]")
                raise click.Abort()
        
        return func(*args, **kwargs)
    
    # Preserve Click function metadata
    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    wrapper.__click_params__ = getattr(func, '__click_params__', [])
    wrapper.__click_options__ = getattr(func, '__click_options__', [])
    wrapper.__click_arguments__ = getattr(func, '__click_arguments__', [])
    
    return wrapper

def show_legal_disclaimer():
    """Show the legal disclaimer."""
    return legal_manager.show_disclaimer()

def check_legal_acceptance():
    """Check if legal terms have been accepted."""
    return legal_manager.check_acceptance()
