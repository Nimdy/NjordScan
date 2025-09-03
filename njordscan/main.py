#!/usr/bin/env python3
"""
🛡️ NjordScan v1.0.0 - Main Entry Point

The Ultimate Security Scanner for Next.js, React, and Vite Applications
"""

import sys
import os
from pathlib import Path

# Add the package directory to Python path
package_dir = Path(__file__).parent
if str(package_dir) not in sys.path:
    sys.path.insert(0, str(package_dir))

def main():
    """Main entry point for NjordScan."""
    try:
        # Import CLI after path setup
        from .cli import main as cli_main
        
        # Run the CLI
        cli_main()
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Please ensure NjordScan is properly installed:")
        print("  pip install njordscan")
        sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n❌ Interrupted by user")
        sys.exit(1)
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()