#!/usr/bin/env python3
"""
Test script to verify CVE and MITRE data updates work properly.
"""

import asyncio
import sys
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

from njordscan.data_updater import VulnerabilityDataManager
from njordscan.config import Config

async def test_cve_mitre_updates():
    """Test CVE and MITRE data updates."""
    print("🧪 Testing CVE and MITRE data updates...")
    
    # Create a basic config
    config = Config(
        target='.',
        mode='standard',
        framework='auto',
        report_format='terminal'
    )
    
    # Initialize data manager
    data_manager = VulnerabilityDataManager(config)
    
    print("\n📡 Available data sources:")
    for source_name, source in data_manager.sources.items():
        print(f"  • {source_name}: {source.url}")
        print(f"    Update frequency: {source.update_frequency} hours")
        print(f"    Enabled: {source.enabled}")
    
    print("\n🔍 Checking for updates...")
    updates_available = await data_manager.check_for_updates()
    
    print("\n📊 Update status:")
    for source, needs_update in updates_available.items():
        status = "🔄 Needs update" if needs_update else "✅ Up to date"
        print(f"  • {source}: {status}")
    
    print("\n🔄 Running update (this may take a few minutes)...")
    results = await data_manager.update_all_sources(force=True)
    
    print("\n📈 Update results:")
    for source, result in results.items():
        if result.get('success', False):
            if result.get('updated', False):
                records = result.get('records', 0)
                print(f"  ✅ {source}: {records} records updated")
            else:
                print(f"  ℹ️ {source}: No changes (up to date)")
        else:
            error = result.get('error', 'Unknown error')
            print(f"  ❌ {source}: {error}")
    
    print("\n📁 Checking generated files...")
    processed_dir = data_manager.processed_dir
    
    files_to_check = [
        'cve_database.json',
        'mitre_attck.json',
        'js_frameworks.json',
        'npm_packages.json'
    ]
    
    for filename in files_to_check:
        file_path = processed_dir / filename
        if file_path.exists():
            file_size = file_path.stat().st_size
            print(f"  ✅ {filename}: {file_size} bytes")
        else:
            print(f"  ❌ {filename}: Not found")
    
    print("\n🎉 Test completed!")

if __name__ == "__main__":
    asyncio.run(test_cve_mitre_updates())
