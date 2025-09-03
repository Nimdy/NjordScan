"""
🛡️ Legacy Plugin Creator for NjordScan v1.0.0

Basic plugin creation from templates - maintained for backward compatibility.
For advanced plugin creation, use plugins_v2.PluginManager.create_plugin_template().
"""

import os
import shutil
from pathlib import Path
from typing import Dict, Any

class PluginCreator:
    """Legacy plugin creator - maintained for backward compatibility.
    
    For advanced plugin creation with marketplace integration,
    use plugins_v2.PluginManager.create_plugin_template() instead.
    """
    
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.templates_dir = self.base_dir / 'plugins' / 'templates'
    
    def create_plugin(self, plugin_type: str, plugin_name: str, output_dir: str) -> Path:
        """Create a new plugin from template."""
        if plugin_type not in ['scanner', 'reporter']:
            raise ValueError(f"Invalid plugin type: {plugin_type}. Must be 'scanner' or 'reporter'")
        
        template_dir = self.templates_dir / f"{plugin_type}_template"
        if not template_dir.exists():
            raise FileNotFoundError(f"Template directory not found: {template_dir}")
        
        output_path = Path(output_dir) / plugin_name
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Copy template files
        self._copy_template_files(template_dir, output_path, plugin_name, plugin_type)
        
        return output_path
    
    def _copy_template_files(self, template_dir: Path, output_path: Path, plugin_name: str, plugin_type: str):
        """Copy and customize template files."""
        for item in template_dir.iterdir():
            if item.name == 'README.md':
                continue  # Skip README
            
            dest_path = output_path / item.name
            
            if item.is_file():
                # Read template content
                content = item.read_text()
                
                # Replace template placeholders
                content = content.replace('template_scanner', f"{plugin_name}_scanner")
                content = content.replace('template_reporter', f"{plugin_name}_reporter")
                content = content.replace('TemplateScanner', f"{plugin_name.title()}Scanner")
                content = content.replace('TemplateReporter', f"{plugin_name.title()}Reporter")
                content = content.replace('template_', f"{plugin_name}_")
                content = content.replace('Template', plugin_name.title())
                
                # Rename files
                if item.name.startswith('template_'):
                    new_name = item.name.replace('template_', f"{plugin_name}_")
                    dest_path = output_path / new_name
                
                # Write customized content
                dest_path.write_text(content)
            else:
                # Copy directories recursively
                shutil.copytree(item, dest_path)

def create_plugin_template(plugin_name: str, template_type: str):
    """Create a plugin template of the specified type."""
    creator = PluginCreator()
    
    # Map template types to plugin types
    template_mapping = {
        'scanner': 'scanner',
        'reporter': 'reporter',
        'framework': 'scanner'  # Framework plugins are typically scanners
    }
    
    if template_type not in template_mapping:
        raise ValueError(f"Invalid template type: {template_type}. Must be one of {list(template_mapping.keys())}")
    
    plugin_type = template_mapping[template_type]
    
    # Create plugin in current directory
    output_dir = "."
    output_path = creator.create_plugin(plugin_type, plugin_name, output_dir)
    
    print(f"✅ Plugin template created successfully!")
    print(f"📁 Location: {output_path}")
    print(f"🔧 Type: {template_type}")
    print(f"📝 Next steps:")
    print(f"   1. Review the generated files in {output_path}")
    print(f"   2. Customize the plugin logic")
    print(f"   3. Test your plugin with: njordscan plugins test {plugin_name}")