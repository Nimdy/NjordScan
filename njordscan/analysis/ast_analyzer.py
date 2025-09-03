"""
Advanced AST Analysis for JavaScript and TypeScript

Provides deep code analysis using Abstract Syntax Trees.
"""

import re
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class NodeType(Enum):
    """AST Node types we're interested in."""
    FUNCTION_DECLARATION = "FunctionDeclaration"
    ARROW_FUNCTION = "ArrowFunctionExpression"
    CALL_EXPRESSION = "CallExpression"
    MEMBER_EXPRESSION = "MemberExpression"
    LITERAL = "Literal"
    IDENTIFIER = "Identifier"
    ASSIGNMENT_EXPRESSION = "AssignmentExpression"
    VARIABLE_DECLARATION = "VariableDeclaration"
    JSX_ELEMENT = "JSXElement"
    JSX_EXPRESSION_CONTAINER = "JSXExpressionContainer"

@dataclass
class ASTNode:
    """Represents an AST node with security-relevant information."""
    type: str
    value: Optional[str] = None
    name: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    children: List['ASTNode'] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.children is None:
            self.children = []
        if self.metadata is None:
            self.metadata = {}

@dataclass
class SecurityFinding:
    """Represents a security finding from AST analysis."""
    finding_type: str
    severity: str
    message: str
    line: int
    column: int
    code_snippet: str
    function_context: Optional[str] = None
    data_flow: List[str] = None
    confidence: float = 1.0
    
    def __post_init__(self):
        if self.data_flow is None:
            self.data_flow = []

class BaseASTAnalyzer:
    """Base class for AST analyzers."""
    
    def __init__(self):
        self.security_patterns = {
            'xss_sinks': [
                'innerHTML', 'outerHTML', 'insertAdjacentHTML',
                'document.write', 'document.writeln',
                'dangerouslySetInnerHTML'
            ],
            'sql_injection_patterns': [
                'query', 'execute', 'exec', 'prepare'
            ],
            'command_injection_patterns': [
                'exec', 'spawn', 'execSync', 'spawnSync',
                'child_process.exec', 'child_process.spawn'
            ],
            'path_traversal_sinks': [
                'fs.readFile', 'fs.writeFile', 'fs.createReadStream',
                'fs.createWriteStream', 'require', 'import'
            ],
            'crypto_weak_patterns': [
                'Math.random', 'crypto.pseudoRandomBytes'
            ],
            'eval_patterns': [
                'eval', 'Function', 'setTimeout', 'setInterval'
            ]
        }
        
        self.taint_sources = [
            'req.body', 'req.query', 'req.params', 'req.headers',
            'window.location', 'document.location', 'location.search',
            'process.argv', 'process.env'
        ]
    
    def analyze_file(self, file_path: Path, content: str) -> List[SecurityFinding]:
        """Analyze a file and return security findings."""
        try:
            ast_data = self._parse_to_ast(content, file_path)
            if not ast_data:
                return []
            
            findings = []
            
            # Analyze different security aspects
            findings.extend(self._analyze_xss_vulnerabilities(ast_data, content))
            findings.extend(self._analyze_injection_vulnerabilities(ast_data, content))
            findings.extend(self._analyze_crypto_issues(ast_data, content))
            findings.extend(self._analyze_path_traversal(ast_data, content))
            findings.extend(self._analyze_dangerous_functions(ast_data, content))
            
            return findings
            
        except Exception as e:
            logger.error(f"AST analysis failed for {file_path}: {e}")
            return []
    
    def _parse_to_ast(self, content: str, file_path: Path) -> Optional[Dict]:
        """Parse JavaScript/TypeScript to AST. Override in subclasses."""
        raise NotImplementedError
    
    def _analyze_xss_vulnerabilities(self, ast_data: Dict, content: str) -> List[SecurityFinding]:
        """Analyze XSS vulnerabilities using AST."""
        findings = []
        
        def visit_node(node, parent_context=""):
            if not isinstance(node, dict):
                return
            
            node_type = node.get('type')
            
            # Check for dangerous innerHTML assignments
            if node_type == 'AssignmentExpression':
                left = node.get('left', {})
                if (left.get('type') == 'MemberExpression' and
                    left.get('property', {}).get('name') in ['innerHTML', 'outerHTML']):
                    
                    right = node.get('right', {})
                    if self._contains_user_input(right):
                        findings.append(SecurityFinding(
                            finding_type='xss_innerHTML',
                            severity='high',
                            message='Potential XSS via innerHTML assignment with user input',
                            line=node.get('loc', {}).get('start', {}).get('line', 0),
                            column=node.get('loc', {}).get('start', {}).get('column', 0),
                            code_snippet=self._get_code_snippet(content, node),
                            function_context=parent_context
                        ))
            
            # Check for dangerouslySetInnerHTML in JSX
            elif node_type == 'JSXAttribute':
                name = node.get('name', {}).get('name')
                if name == 'dangerouslySetInnerHTML':
                    value = node.get('value', {})
                    if self._contains_user_input(value):
                        findings.append(SecurityFinding(
                            finding_type='xss_jsx_dangerous',
                            severity='high',
                            message='Potential XSS via dangerouslySetInnerHTML with user input',
                            line=node.get('loc', {}).get('start', {}).get('line', 0),
                            column=node.get('loc', {}).get('start', {}).get('column', 0),
                            code_snippet=self._get_code_snippet(content, node),
                            function_context=parent_context
                        ))
            
            # Check for document.write calls
            elif node_type == 'CallExpression':
                callee = node.get('callee', {})
                if (callee.get('type') == 'MemberExpression' and
                    callee.get('object', {}).get('name') == 'document' and
                    callee.get('property', {}).get('name') in ['write', 'writeln']):
                    
                    args = node.get('arguments', [])
                    if args and self._contains_user_input(args[0]):
                        findings.append(SecurityFinding(
                            finding_type='xss_document_write',
                            severity='medium',
                            message='Potential XSS via document.write with user input',
                            line=node.get('loc', {}).get('start', {}).get('line', 0),
                            column=node.get('loc', {}).get('start', {}).get('column', 0),
                            code_snippet=self._get_code_snippet(content, node),
                            function_context=parent_context
                        ))
            
            # Recursively visit child nodes
            for key, value in node.items():
                if isinstance(value, dict):
                    visit_node(value, parent_context)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            visit_node(item, parent_context)
        
        visit_node(ast_data)
        return findings
    
    def _analyze_injection_vulnerabilities(self, ast_data: Dict, content: str) -> List[SecurityFinding]:
        """Analyze SQL and command injection vulnerabilities."""
        findings = []
        
        def visit_node(node, parent_context=""):
            if not isinstance(node, dict):
                return
            
            node_type = node.get('type')
            
            # Check for SQL injection patterns
            if node_type == 'CallExpression':
                callee = node.get('callee', {})
                
                # Database query methods
                if self._is_database_call(callee):
                    args = node.get('arguments', [])
                    if args and self._contains_user_input_in_string(args[0]):
                        findings.append(SecurityFinding(
                            finding_type='sql_injection',
                            severity='critical',
                            message='Potential SQL injection via dynamic query construction',
                            line=node.get('loc', {}).get('start', {}).get('line', 0),
                            column=node.get('loc', {}).get('start', {}).get('column', 0),
                            code_snippet=self._get_code_snippet(content, node),
                            function_context=parent_context
                        ))
                
                # Command injection patterns
                elif self._is_command_execution_call(callee):
                    args = node.get('arguments', [])
                    if args and self._contains_user_input(args[0]):
                        findings.append(SecurityFinding(
                            finding_type='command_injection',
                            severity='critical',
                            message='Potential command injection via dynamic command execution',
                            line=node.get('loc', {}).get('start', {}).get('line', 0),
                            column=node.get('loc', {}).get('start', {}).get('column', 0),
                            code_snippet=self._get_code_snippet(content, node),
                            function_context=parent_context
                        ))
            
            # Recursively visit child nodes
            for key, value in node.items():
                if isinstance(value, dict):
                    visit_node(value, parent_context)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            visit_node(item, parent_context)
        
        visit_node(ast_data)
        return findings
    
    def _analyze_crypto_issues(self, ast_data: Dict, content: str) -> List[SecurityFinding]:
        """Analyze cryptographic issues."""
        findings = []
        
        def visit_node(node, parent_context=""):
            if not isinstance(node, dict):
                return
            
            node_type = node.get('type')
            
            # Check for weak random number generation
            if node_type == 'CallExpression':
                callee = node.get('callee', {})
                
                if (callee.get('type') == 'MemberExpression' and
                    callee.get('object', {}).get('name') == 'Math' and
                    callee.get('property', {}).get('name') == 'random'):
                    
                    findings.append(SecurityFinding(
                        finding_type='weak_crypto',
                        severity='medium',
                        message='Use of cryptographically weak Math.random()',
                        line=node.get('loc', {}).get('start', {}).get('line', 0),
                        column=node.get('loc', {}).get('start', {}).get('column', 0),
                        code_snippet=self._get_code_snippet(content, node),
                        function_context=parent_context,
                        confidence=0.8
                    ))
            
            # Check for hardcoded crypto keys/secrets
            elif node_type == 'Literal':
                value = node.get('value')
                if isinstance(value, str) and len(value) > 20:
                    # Check if it looks like a crypto key
                    if self._looks_like_crypto_key(value):
                        findings.append(SecurityFinding(
                            finding_type='hardcoded_secret',
                            severity='high',
                            message='Potential hardcoded cryptographic key or secret',
                            line=node.get('loc', {}).get('start', {}).get('line', 0),
                            column=node.get('loc', {}).get('start', {}).get('column', 0),
                            code_snippet=self._get_code_snippet(content, node),
                            function_context=parent_context,
                            confidence=0.7
                        ))
            
            # Recursively visit child nodes
            for key, value in node.items():
                if isinstance(value, dict):
                    visit_node(value, parent_context)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            visit_node(item, parent_context)
        
        visit_node(ast_data)
        return findings
    
    def _analyze_path_traversal(self, ast_data: Dict, content: str) -> List[SecurityFinding]:
        """Analyze path traversal vulnerabilities."""
        findings = []
        
        def visit_node(node, parent_context=""):
            if not isinstance(node, dict):
                return
            
            node_type = node.get('type')
            
            if node_type == 'CallExpression':
                callee = node.get('callee', {})
                
                # Check for file system operations with user input
                if self._is_file_operation(callee):
                    args = node.get('arguments', [])
                    if args and self._contains_user_input(args[0]):
                        findings.append(SecurityFinding(
                            finding_type='path_traversal',
                            severity='high',
                            message='Potential path traversal via file operation with user input',
                            line=node.get('loc', {}).get('start', {}).get('line', 0),
                            column=node.get('loc', {}).get('start', {}).get('column', 0),
                            code_snippet=self._get_code_snippet(content, node),
                            function_context=parent_context
                        ))
            
            # Recursively visit child nodes
            for key, value in node.items():
                if isinstance(value, dict):
                    visit_node(value, parent_context)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            visit_node(item, parent_context)
        
        visit_node(ast_data)
        return findings
    
    def _analyze_dangerous_functions(self, ast_data: Dict, content: str) -> List[SecurityFinding]:
        """Analyze usage of dangerous functions."""
        findings = []
        
        def visit_node(node, parent_context=""):
            if not isinstance(node, dict):
                return
            
            node_type = node.get('type')
            
            if node_type == 'CallExpression':
                callee = node.get('callee', {})
                
                # Check for eval() calls
                if callee.get('type') == 'Identifier' and callee.get('name') == 'eval':
                    args = node.get('arguments', [])
                    if args and self._contains_user_input(args[0]):
                        findings.append(SecurityFinding(
                            finding_type='code_injection',
                            severity='critical',
                            message='Potential code injection via eval() with user input',
                            line=node.get('loc', {}).get('start', {}).get('line', 0),
                            column=node.get('loc', {}).get('start', {}).get('column', 0),
                            code_snippet=self._get_code_snippet(content, node),
                            function_context=parent_context
                        ))
                
                # Check for Function constructor
                elif callee.get('type') == 'Identifier' and callee.get('name') == 'Function':
                    args = node.get('arguments', [])
                    if args and any(self._contains_user_input(arg) for arg in args):
                        findings.append(SecurityFinding(
                            finding_type='code_injection',
                            severity='critical',
                            message='Potential code injection via Function constructor with user input',
                            line=node.get('loc', {}).get('start', {}).get('line', 0),
                            column=node.get('loc', {}).get('start', {}).get('column', 0),
                            code_snippet=self._get_code_snippet(content, node),
                            function_context=parent_context
                        ))
            
            # Recursively visit child nodes
            for key, value in node.items():
                if isinstance(value, dict):
                    visit_node(value, parent_context)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            visit_node(item, parent_context)
        
        visit_node(ast_data)
        return findings
    
    def _contains_user_input(self, node: Dict) -> bool:
        """Check if a node contains user input."""
        if not isinstance(node, dict):
            return False
        
        # Simple heuristic - look for known taint sources
        def check_node(n):
            if not isinstance(n, dict):
                return False
            
            node_type = n.get('type')
            
            # Check for member expressions like req.body, req.query
            if node_type == 'MemberExpression':
                obj = n.get('object', {})
                prop = n.get('property', {})
                
                if obj.get('name') == 'req' and prop.get('name') in ['body', 'query', 'params', 'headers']:
                    return True
                
                # Check for nested member expressions
                obj_str = self._member_expression_to_string(n)
                if any(source in obj_str for source in self.taint_sources):
                    return True
            
            # Check for template literals with user input
            elif node_type == 'TemplateLiteral':
                expressions = n.get('expressions', [])
                return any(check_node(expr) for expr in expressions)
            
            # Check for binary expressions (concatenation)
            elif node_type == 'BinaryExpression':
                return check_node(n.get('left', {})) or check_node(n.get('right', {}))
            
            # Recursively check child nodes
            for key, value in n.items():
                if isinstance(value, dict):
                    if check_node(value):
                        return True
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict) and check_node(item):
                            return True
            
            return False
        
        return check_node(node)
    
    def _contains_user_input_in_string(self, node: Dict) -> bool:
        """Check if string construction contains user input."""
        if not isinstance(node, dict):
            return False
        
        node_type = node.get('type')
        
        # Template literals
        if node_type == 'TemplateLiteral':
            expressions = node.get('expressions', [])
            return any(self._contains_user_input(expr) for expr in expressions)
        
        # Binary expressions (string concatenation)
        elif node_type == 'BinaryExpression' and node.get('operator') == '+':
            return (self._contains_user_input(node.get('left', {})) or 
                   self._contains_user_input(node.get('right', {})))
        
        return self._contains_user_input(node)
    
    def _is_database_call(self, callee: Dict) -> bool:
        """Check if callee is a database operation."""
        if not isinstance(callee, dict):
            return False
        
        # Simple method name check
        if callee.get('type') == 'MemberExpression':
            prop_name = callee.get('property', {}).get('name', '')
            return prop_name in self.security_patterns['sql_injection_patterns']
        
        return False
    
    def _is_command_execution_call(self, callee: Dict) -> bool:
        """Check if callee is a command execution function."""
        if not isinstance(callee, dict):
            return False
        
        if callee.get('type') == 'Identifier':
            name = callee.get('name', '')
            return name in ['exec', 'spawn']
        
        elif callee.get('type') == 'MemberExpression':
            obj = callee.get('object', {})
            prop = callee.get('property', {})
            
            if obj.get('name') == 'child_process':
                return prop.get('name') in ['exec', 'spawn', 'execSync', 'spawnSync']
        
        return False
    
    def _is_file_operation(self, callee: Dict) -> bool:
        """Check if callee is a file system operation."""
        if not isinstance(callee, dict):
            return False
        
        if callee.get('type') == 'MemberExpression':
            obj = callee.get('object', {})
            prop = callee.get('property', {})
            
            if obj.get('name') == 'fs':
                return prop.get('name') in ['readFile', 'writeFile', 'createReadStream', 'createWriteStream']
        
        return False
    
    def _looks_like_crypto_key(self, value: str) -> bool:
        """Check if string looks like a cryptographic key."""
        # Base64 pattern
        if re.match(r'^[A-Za-z0-9+/]+=*$', value) and len(value) >= 32:
            return True
        
        # Hex pattern
        if re.match(r'^[0-9a-fA-F]+$', value) and len(value) >= 32:
            return True
        
        # Common key prefixes
        key_prefixes = ['sk-', 'pk-', 'AKIA', 'ghp_', 'sk-ant-']
        if any(value.startswith(prefix) for prefix in key_prefixes):
            return True
        
        return False
    
    def _member_expression_to_string(self, node: Dict) -> str:
        """Convert member expression to string representation."""
        if not isinstance(node, dict) or node.get('type') != 'MemberExpression':
            return ''
        
        obj = node.get('object', {})
        prop = node.get('property', {})
        
        obj_str = ''
        if obj.get('type') == 'Identifier':
            obj_str = obj.get('name', '')
        elif obj.get('type') == 'MemberExpression':
            obj_str = self._member_expression_to_string(obj)
        
        prop_str = prop.get('name', '') if prop.get('type') == 'Identifier' else ''
        
        return f"{obj_str}.{prop_str}" if obj_str and prop_str else ''
    
    def _get_code_snippet(self, content: str, node: Dict) -> str:
        """Extract code snippet for a node."""
        try:
            loc = node.get('loc', {})
            start_line = loc.get('start', {}).get('line', 1) - 1
            end_line = loc.get('end', {}).get('line', 1) - 1
            
            lines = content.split('\n')
            if 0 <= start_line < len(lines):
                if start_line == end_line:
                    return lines[start_line].strip()
                else:
                    return '\n'.join(lines[start_line:end_line + 1]).strip()
        except:
            pass
        
        return "Code snippet unavailable"

class JavaScriptASTAnalyzer(BaseASTAnalyzer):
    """AST analyzer for JavaScript files."""
    
    def _parse_to_ast(self, content: str, file_path: Path) -> Optional[Dict]:
        """Parse JavaScript to AST using Node.js."""
        try:
            # Try using esprima via Node.js
            import tempfile
            import os
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
                f.write(content)
                temp_file = f.name
            
            try:
                # Create a simple Node.js script to parse with esprima
                parser_script = f"""
                const esprima = require('esprima');
                const fs = require('fs');
                
                try {{
                    const code = fs.readFileSync('{temp_file}', 'utf8');
                    const ast = esprima.parseScript(code, {{ loc: true, range: true }});
                    console.log(JSON.stringify(ast));
                }} catch (error) {{
                    console.error(JSON.stringify({{ error: error.message }}));
                    process.exit(1);
                }}
                """
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as script_f:
                    script_f.write(parser_script)
                    script_file = script_f.name
                
                try:
                    result = subprocess.run(
                        ['node', script_file],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    if result.returncode == 0:
                        return json.loads(result.stdout)
                    else:
                        logger.warning(f"esprima parsing failed: {result.stderr}")
                        return None
                
                finally:
                    os.unlink(script_file)
            
            finally:
                os.unlink(temp_file)
                
        except Exception as e:
            logger.debug(f"Node.js AST parsing failed, falling back to regex: {e}")
            return None

class TypeScriptASTAnalyzer(BaseASTAnalyzer):
    """AST analyzer for TypeScript files."""
    
    def _parse_to_ast(self, content: str, file_path: Path) -> Optional[Dict]:
        """Parse TypeScript to AST using TypeScript compiler API."""
        try:
            # Try using TypeScript compiler via Node.js
            import tempfile
            import os
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ts', delete=False) as f:
                f.write(content)
                temp_file = f.name
            
            try:
                # Create a Node.js script to parse with TypeScript
                parser_script = f"""
                const ts = require('typescript');
                const fs = require('fs');
                
                try {{
                    const code = fs.readFileSync('{temp_file}', 'utf8');
                    const sourceFile = ts.createSourceFile(
                        '{file_path}',
                        code,
                        ts.ScriptTarget.Latest,
                        true
                    );
                    
                    // Convert TypeScript AST to JSON (simplified)
                    function astToJson(node) {{
                        const result = {{
                            type: ts.SyntaxKind[node.kind],
                            pos: node.pos,
                            end: node.end
                        }};
                        
                        if (node.text) result.text = node.text;
                        if (node.name) result.name = astToJson(node.name);
                        
                        const children = [];
                        ts.forEachChild(node, child => {{
                            children.push(astToJson(child));
                        }});
                        
                        if (children.length > 0) result.children = children;
                        return result;
                    }}
                    
                    console.log(JSON.stringify(astToJson(sourceFile)));
                }} catch (error) {{
                    console.error(JSON.stringify({{ error: error.message }}));
                    process.exit(1);
                }}
                """
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as script_f:
                    script_f.write(parser_script)
                    script_file = script_f.name
                
                try:
                    result = subprocess.run(
                        ['node', script_file],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    if result.returncode == 0:
                        return json.loads(result.stdout)
                    else:
                        logger.warning(f"TypeScript parsing failed: {result.stderr}")
                        return None
                
                finally:
                    os.unlink(script_file)
            
            finally:
                os.unlink(temp_file)
                
        except Exception as e:
            logger.debug(f"TypeScript AST parsing failed, falling back to JavaScript parser: {e}")
            # Fallback to JavaScript parser
            js_analyzer = JavaScriptASTAnalyzer()
            return js_analyzer._parse_to_ast(content, file_path)

# Factory function to get appropriate analyzer
def get_ast_analyzer(file_path: Path) -> BaseASTAnalyzer:
    """Get appropriate AST analyzer based on file extension."""
    suffix = file_path.suffix.lower()
    
    if suffix in ['.ts', '.tsx']:
        return TypeScriptASTAnalyzer()
    elif suffix in ['.js', '.jsx', '.mjs']:
        return JavaScriptASTAnalyzer()
    else:
        return JavaScriptASTAnalyzer()  # Default fallback
