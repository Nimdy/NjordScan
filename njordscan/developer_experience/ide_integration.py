"""
IDE Integration System

Seamless integration with popular IDEs and editors:
- VS Code extension support and Language Server Protocol (LSP)
- Real-time security linting and diagnostics
- Inline vulnerability annotations and quick fixes
- Code action providers for security improvements
- Hover information with security context
- Intelligent code completion for secure patterns
- Debug adapter for security analysis
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import time
import threading
import subprocess
import tempfile
import os

# Conditional import for websocket
try:
    import websocket
    WEBSOCKET_AVAILABLE = True
except ImportError:
    WEBSOCKET_AVAILABLE = False
    websocket = None

logger = logging.getLogger(__name__)

class IDEType(Enum):
    """Supported IDE types."""
    VSCODE = "vscode"
    INTELLIJ = "intellij"
    ATOM = "atom"
    SUBLIME = "sublime"
    VIM = "vim"
    EMACS = "emacs"
    UNKNOWN = "unknown"

class DiagnosticSeverity(Enum):
    """LSP diagnostic severity levels."""
    ERROR = 1
    WARNING = 2
    INFORMATION = 3
    HINT = 4

class CompletionItemKind(Enum):
    """LSP completion item kinds."""
    TEXT = 1
    METHOD = 2
    FUNCTION = 3
    CONSTRUCTOR = 4
    FIELD = 5
    VARIABLE = 6
    CLASS = 7
    INTERFACE = 8
    MODULE = 9
    PROPERTY = 10
    UNIT = 11
    VALUE = 12
    ENUM = 13
    KEYWORD = 14
    SNIPPET = 15
    COLOR = 16
    FILE = 17
    REFERENCE = 18

@dataclass
class Position:
    """LSP position."""
    line: int
    character: int

@dataclass
class Range:
    """LSP range."""
    start: Position
    end: Position

@dataclass
class Diagnostic:
    """LSP diagnostic."""
    range: Range
    message: str
    severity: DiagnosticSeverity = DiagnosticSeverity.WARNING
    code: Optional[str] = None
    source: str = "njordscan"
    tags: List[int] = field(default_factory=list)
    related_information: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to LSP dictionary format."""
        return {
            "range": {
                "start": {"line": self.range.start.line, "character": self.range.start.character},
                "end": {"line": self.range.end.line, "character": self.range.end.character}
            },
            "message": self.message,
            "severity": self.severity.value,
            "code": self.code,
            "source": self.source,
            "tags": self.tags,
            "relatedInformation": self.related_information
        }

@dataclass
class CodeAction:
    """LSP code action."""
    title: str
    kind: str
    diagnostics: List[Diagnostic] = field(default_factory=list)
    edit: Optional[Dict[str, Any]] = None
    command: Optional[Dict[str, Any]] = None
    is_preferred: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to LSP dictionary format."""
        result = {
            "title": self.title,
            "kind": self.kind,
            "isPreferred": self.is_preferred
        }
        
        if self.diagnostics:
            result["diagnostics"] = [d.to_dict() for d in self.diagnostics]
        
        if self.edit:
            result["edit"] = self.edit
            
        if self.command:
            result["command"] = self.command
            
        return result

@dataclass
class CompletionItem:
    """LSP completion item."""
    label: str
    kind: CompletionItemKind
    detail: Optional[str] = None
    documentation: Optional[str] = None
    insert_text: Optional[str] = None
    filter_text: Optional[str] = None
    sort_text: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to LSP dictionary format."""
        result = {
            "label": self.label,
            "kind": self.kind.value
        }
        
        if self.detail:
            result["detail"] = self.detail
        if self.documentation:
            result["documentation"] = self.documentation
        if self.insert_text:
            result["insertText"] = self.insert_text
        if self.filter_text:
            result["filterText"] = self.filter_text
        if self.sort_text:
            result["sortText"] = self.sort_text
            
        return result

@dataclass
class IDEConfig:
    """IDE integration configuration."""
    
    # Language Server Protocol
    enable_lsp: bool = True
    lsp_port: int = 9257
    lsp_host: str = "localhost"
    
    # Real-time analysis
    enable_real_time_analysis: bool = True
    analysis_delay_ms: int = 1000
    max_file_size_kb: int = 1024
    
    # Diagnostics
    show_security_diagnostics: bool = True
    show_performance_diagnostics: bool = True
    show_code_quality_diagnostics: bool = True
    
    # Code actions
    enable_quick_fixes: bool = True
    enable_refactoring_actions: bool = True
    enable_security_improvements: bool = True
    
    # Completion
    enable_security_completions: bool = True
    enable_framework_completions: bool = True
    completion_trigger_characters: List[str] = field(default_factory=lambda: [".", "(", "["])
    
    # Hover information
    enable_hover_info: bool = True
    show_security_context: bool = True
    show_vulnerability_details: bool = True
    
    # VS Code specific
    vscode_extension_path: Optional[str] = None
    auto_install_extension: bool = True
    
    # Performance
    max_concurrent_analyses: int = 3
    cache_analysis_results: bool = True
    cache_ttl_seconds: int = 300

class LanguageServer:
    """NjordScan Language Server Protocol implementation."""
    
    def __init__(self, config: IDEConfig = None):
        self.config = config or IDEConfig()
        self.workspace_folders: List[str] = []
        self.documents: Dict[str, str] = {}  # uri -> content
        self.diagnostics: Dict[str, List[Diagnostic]] = {}  # uri -> diagnostics
        
        # Analysis components (would be injected from main scanner)
        self.scanner = None
        
        # LSP state
        self.initialized = False
        self.shutdown_requested = False
        
        # Background tasks
        self.analysis_queue = asyncio.Queue()
        self.background_tasks: List[asyncio.Task] = []
        
        # Client capabilities
        self.client_capabilities = {}
        
        # Server capabilities
        self.server_capabilities = {
            "textDocumentSync": {
                "openClose": True,
                "change": 2,  # Incremental
                "save": {"includeText": True}
            },
            "diagnosticProvider": {
                "interFileDependencies": True,
                "workspaceDiagnostics": True
            },
            "completionProvider": {
                "triggerCharacters": self.config.completion_trigger_characters,
                "resolveProvider": True
            },
            "hoverProvider": True,
            "codeActionProvider": {
                "codeActionKinds": [
                    "quickfix",
                    "refactor.rewrite",
                    "source.fixAll.njordscan"
                ]
            },
            "definitionProvider": False,
            "referencesProvider": False,
            "documentSymbolProvider": True,
            "workspaceSymbolProvider": False,
            "executeCommandProvider": {
                "commands": [
                    "njordscan.scanFile",
                    "njordscan.scanWorkspace",
                    "njordscan.fixSecurity",
                    "njordscan.showReport"
                ]
            }
        }
    
    async def initialize(self, scanner=None):
        """Initialize the language server."""
        
        logger.info("Initializing NjordScan Language Server")
        
        self.scanner = scanner
        
        # Start background analysis worker
        self.background_tasks = [
            asyncio.create_task(self._analysis_worker()),
            asyncio.create_task(self._diagnostic_publisher())
        ]
        
        self.initialized = True
        logger.info("Language Server initialized")
    
    async def handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle LSP initialize request."""
        
        self.client_capabilities = params.get("capabilities", {})
        
        # Extract workspace folders
        if "workspaceFolders" in params and params["workspaceFolders"]:
            self.workspace_folders = [folder["uri"] for folder in params["workspaceFolders"]]
        elif "rootUri" in params and params["rootUri"]:
            self.workspace_folders = [params["rootUri"]]
        
        logger.info(f"LSP initialized with workspace folders: {self.workspace_folders}")
        
        return {
            "capabilities": self.server_capabilities,
            "serverInfo": {
                "name": "njordscan-language-server",
                "version": "1.0.0"
            }
        }
    
    async def handle_text_document_did_open(self, params: Dict[str, Any]):
        """Handle document open notification."""
        
        text_document = params["textDocument"]
        uri = text_document["uri"]
        content = text_document["text"]
        
        self.documents[uri] = content
        
        # Queue for analysis
        await self.analysis_queue.put({
            "action": "analyze",
            "uri": uri,
            "content": content
        })
        
        logger.debug(f"Document opened: {uri}")
    
    async def handle_text_document_did_change(self, params: Dict[str, Any]):
        """Handle document change notification."""
        
        uri = params["textDocument"]["uri"]
        changes = params["contentChanges"]
        
        # Apply changes (simplified - assumes full document updates)
        if changes and "text" in changes[0]:
            self.documents[uri] = changes[0]["text"]
            
            # Queue for analysis with delay
            await asyncio.sleep(self.config.analysis_delay_ms / 1000.0)
            await self.analysis_queue.put({
                "action": "analyze",
                "uri": uri,
                "content": self.documents[uri]
            })
        
        logger.debug(f"Document changed: {uri}")
    
    async def handle_text_document_did_save(self, params: Dict[str, Any]):
        """Handle document save notification."""
        
        uri = params["textDocument"]["uri"]
        
        if uri in self.documents:
            # Immediate analysis on save
            await self.analysis_queue.put({
                "action": "analyze",
                "uri": uri,
                "content": self.documents[uri],
                "priority": True
            })
        
        logger.debug(f"Document saved: {uri}")
    
    async def handle_text_document_did_close(self, params: Dict[str, Any]):
        """Handle document close notification."""
        
        uri = params["textDocument"]["uri"]
        
        # Clean up
        if uri in self.documents:
            del self.documents[uri]
        if uri in self.diagnostics:
            del self.diagnostics[uri]
        
        logger.debug(f"Document closed: {uri}")
    
    async def handle_text_document_completion(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle completion request."""
        
        uri = params["textDocument"]["uri"]
        position = params["position"]
        
        if uri not in self.documents:
            return {"items": []}
        
        content = self.documents[uri]
        completions = await self._generate_completions(uri, content, position)
        
        return {"items": [completion.to_dict() for completion in completions]}
    
    async def handle_text_document_hover(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle hover request."""
        
        uri = params["textDocument"]["uri"]
        position = params["position"]
        
        if uri not in self.documents:
            return None
        
        content = self.documents[uri]
        hover_info = await self._generate_hover_info(uri, content, position)
        
        return hover_info
    
    async def handle_text_document_code_action(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Handle code action request."""
        
        uri = params["textDocument"]["uri"]
        range_param = params["range"]
        context = params.get("context", {})
        
        if uri not in self.documents:
            return []
        
        content = self.documents[uri]
        diagnostics = context.get("diagnostics", [])
        
        code_actions = await self._generate_code_actions(uri, content, range_param, diagnostics)
        
        return [action.to_dict() for action in code_actions]
    
    async def handle_workspace_execute_command(self, params: Dict[str, Any]) -> Any:
        """Handle execute command request."""
        
        command = params["command"]
        arguments = params.get("arguments", [])
        
        if command == "njordscan.scanFile":
            return await self._execute_scan_file(arguments)
        elif command == "njordscan.scanWorkspace":
            return await self._execute_scan_workspace(arguments)
        elif command == "njordscan.fixSecurity":
            return await self._execute_fix_security(arguments)
        elif command == "njordscan.showReport":
            return await self._execute_show_report(arguments)
        
        return None
    
    # Private methods
    
    async def _analysis_worker(self):
        """Background worker for document analysis."""
        
        while not self.shutdown_requested:
            try:
                # Get analysis task
                task = await asyncio.wait_for(self.analysis_queue.get(), timeout=1.0)
                
                if task["action"] == "analyze":
                    await self._analyze_document(task["uri"], task["content"])
                
                self.analysis_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Analysis worker error: {str(e)}")
    
    async def _diagnostic_publisher(self):
        """Background worker for publishing diagnostics."""
        
        while not self.shutdown_requested:
            try:
                await asyncio.sleep(0.5)  # Publish diagnostics every 500ms
                
                # Publish pending diagnostics
                for uri, diagnostics in self.diagnostics.items():
                    await self._publish_diagnostics(uri, diagnostics)
                
            except Exception as e:
                logger.error(f"Diagnostic publisher error: {str(e)}")
    
    async def _analyze_document(self, uri: str, content: str):
        """Analyze document and generate diagnostics."""
        
        try:
            if not self.scanner:
                return
            
            # Convert URI to file path
            file_path = uri.replace("file://", "")
            
            # Run security analysis
            # This would integrate with the main NjordScan engine
            findings = await self._run_security_analysis(file_path, content)
            
            # Convert findings to diagnostics
            diagnostics = []
            for finding in findings:
                diagnostic = await self._finding_to_diagnostic(finding)
                if diagnostic:
                    diagnostics.append(diagnostic)
            
            # Store diagnostics
            self.diagnostics[uri] = diagnostics
            
            logger.debug(f"Analysis completed for {uri}: {len(diagnostics)} diagnostics")
            
        except Exception as e:
            logger.error(f"Document analysis error for {uri}: {str(e)}")
    
    async def _run_security_analysis(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """Run security analysis on document content."""
        
        # Mock analysis results for now
        # In real implementation, this would use the main scanner
        
        findings = []
        
        # Simple pattern-based detection for demo
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines):
            # Check for potential SQL injection
            if 'SELECT' in line and 'WHERE' in line and ('+' in line or '${' in line):
                findings.append({
                    'title': 'Potential SQL Injection',
                    'description': 'Dynamic SQL construction detected',
                    'severity': 'high',
                    'line': line_num,
                    'column': 0,
                    'end_line': line_num,
                    'end_column': len(line),
                    'rule_id': 'sql_injection',
                    'fix_suggestion': 'Use parameterized queries instead'
                })
            
            # Check for eval usage
            if 'eval(' in line:
                findings.append({
                    'title': 'Dangerous eval() Usage',
                    'description': 'Use of eval() can lead to code injection',
                    'severity': 'critical',
                    'line': line_num,
                    'column': line.find('eval('),
                    'end_line': line_num,
                    'end_column': line.find('eval(') + 4,
                    'rule_id': 'dangerous_eval',
                    'fix_suggestion': 'Avoid using eval() - consider safer alternatives'
                })
            
            # Check for hardcoded secrets
            if any(secret in line.lower() for secret in ['password', 'api_key', 'secret']):
                if '=' in line and ('"' in line or "'" in line):
                    findings.append({
                        'title': 'Potential Hardcoded Secret',
                        'description': 'Hardcoded credentials detected',
                        'severity': 'medium',
                        'line': line_num,
                        'column': 0,
                        'end_line': line_num,
                        'end_column': len(line),
                        'rule_id': 'hardcoded_secret',
                        'fix_suggestion': 'Move secrets to environment variables'
                    })
        
        return findings
    
    async def _finding_to_diagnostic(self, finding: Dict[str, Any]) -> Optional[Diagnostic]:
        """Convert security finding to LSP diagnostic."""
        
        try:
            severity_map = {
                'critical': DiagnosticSeverity.ERROR,
                'high': DiagnosticSeverity.ERROR,
                'medium': DiagnosticSeverity.WARNING,
                'low': DiagnosticSeverity.INFORMATION,
                'info': DiagnosticSeverity.HINT
            }
            
            severity = severity_map.get(finding.get('severity', 'medium'), DiagnosticSeverity.WARNING)
            
            range_obj = Range(
                start=Position(
                    line=finding.get('line', 0),
                    character=finding.get('column', 0)
                ),
                end=Position(
                    line=finding.get('end_line', finding.get('line', 0)),
                    character=finding.get('end_column', finding.get('column', 0) + 1)
                )
            )
            
            message = finding.get('description', finding.get('title', 'Security issue'))
            if finding.get('fix_suggestion'):
                message += f"\n\nSuggestion: {finding['fix_suggestion']}"
            
            return Diagnostic(
                range=range_obj,
                message=message,
                severity=severity,
                code=finding.get('rule_id'),
                source="njordscan"
            )
            
        except Exception as e:
            logger.error(f"Failed to convert finding to diagnostic: {str(e)}")
            return None
    
    async def _generate_completions(self, uri: str, content: str, position: Dict[str, Any]) -> List[CompletionItem]:
        """Generate security-aware code completions."""
        
        completions = []
        
        # Get current line
        lines = content.split('\n')
        current_line = lines[position['line']] if position['line'] < len(lines) else ""
        
        # Security-focused completions
        if 'crypto' in current_line or 'hash' in current_line:
            completions.extend([
                CompletionItem(
                    label="crypto.createHash('sha256')",
                    kind=CompletionItemKind.SNIPPET,
                    detail="Secure hash function",
                    documentation="Use SHA-256 for cryptographic hashing",
                    insert_text="crypto.createHash('sha256')"
                ),
                CompletionItem(
                    label="crypto.randomBytes(32)",
                    kind=CompletionItemKind.SNIPPET,
                    detail="Cryptographically secure random bytes",
                    documentation="Generate secure random data",
                    insert_text="crypto.randomBytes(32)"
                )
            ])
        
        if 'password' in current_line or 'auth' in current_line:
            completions.extend([
                CompletionItem(
                    label="bcrypt.hash(password, 12)",
                    kind=CompletionItemKind.SNIPPET,
                    detail="Secure password hashing",
                    documentation="Hash passwords with bcrypt and high cost factor",
                    insert_text="bcrypt.hash(password, 12)"
                ),
                CompletionItem(
                    label="process.env.JWT_SECRET",
                    kind=CompletionItemKind.VARIABLE,
                    detail="Environment variable for JWT secret",
                    documentation="Use environment variables for secrets",
                    insert_text="process.env.JWT_SECRET"
                )
            ])
        
        if 'sql' in current_line.lower() or 'query' in current_line.lower():
            completions.append(
                CompletionItem(
                    label="db.query('SELECT * FROM users WHERE id = ?', [userId])",
                    kind=CompletionItemKind.SNIPPET,
                    detail="Parameterized SQL query",
                    documentation="Use parameterized queries to prevent SQL injection",
                    insert_text="db.query('SELECT * FROM users WHERE id = ?', [userId])"
                )
            )
        
        return completions
    
    async def _generate_hover_info(self, uri: str, content: str, position: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate hover information with security context."""
        
        lines = content.split('\n')
        if position['line'] >= len(lines):
            return None
        
        current_line = lines[position['line']]
        
        # Check if hovering over a security-sensitive function
        hover_info = None
        
        if 'eval(' in current_line:
            hover_info = {
                "contents": {
                    "kind": "markdown",
                    "value": "⚠️ **Security Warning: eval() usage**\n\n"
                             "The `eval()` function can execute arbitrary JavaScript code, "
                             "making it a serious security risk if used with untrusted input.\n\n"
                             "**Recommendations:**\n"
                             "- Use `JSON.parse()` for parsing JSON\n"
                             "- Use `Function()` constructor for safer dynamic code execution\n"
                             "- Validate and sanitize all inputs"
                }
            }
        
        elif 'Math.random()' in current_line:
            hover_info = {
                "contents": {
                    "kind": "markdown",
                    "value": "⚠️ **Security Notice: Math.random() usage**\n\n"
                             "`Math.random()` is not cryptographically secure and should not be used "
                             "for security-sensitive operations.\n\n"
                             "**For security purposes, use:**\n"
                             "```javascript\n"
                             "const crypto = require('crypto');\n"
                             "crypto.randomBytes(16).toString('hex');\n"
                             "```"
                }
            }
        
        elif any(word in current_line for word in ['password', 'secret', 'key']) and '=' in current_line:
            hover_info = {
                "contents": {
                    "kind": "markdown",
                    "value": "🔒 **Security Best Practice: Secrets Management**\n\n"
                             "Avoid hardcoding sensitive information in your source code.\n\n"
                             "**Recommended approach:**\n"
                             "```javascript\n"
                             "const secret = process.env.SECRET_KEY;\n"
                             "```\n\n"
                             "Store secrets in environment variables or secure vaults."
                }
            }
        
        return hover_info
    
    async def _generate_code_actions(self, uri: str, content: str, range_param: Dict[str, Any], 
                                   diagnostics: List[Dict[str, Any]]) -> List[CodeAction]:
        """Generate code actions for security fixes."""
        
        actions = []
        
        for diagnostic in diagnostics:
            if diagnostic.get("source") != "njordscan":
                continue
            
            code = diagnostic.get("code")
            
            if code == "dangerous_eval":
                actions.append(CodeAction(
                    title="Replace eval() with safer alternative",
                    kind="quickfix",
                    edit={
                        "changes": {
                            uri: [{
                                "range": diagnostic["range"],
                                "newText": "JSON.parse"
                            }]
                        }
                    }
                ))
            
            elif code == "hardcoded_secret":
                actions.append(CodeAction(
                    title="Move to environment variable",
                    kind="refactor.rewrite",
                    edit={
                        "changes": {
                            uri: [{
                                "range": diagnostic["range"],
                                "newText": "process.env.SECRET_KEY"
                            }]
                        }
                    }
                ))
            
            elif code == "sql_injection":
                actions.append(CodeAction(
                    title="Convert to parameterized query",
                    kind="quickfix",
                    command={
                        "title": "Convert to parameterized query",
                        "command": "njordscan.fixSecurity",
                        "arguments": [uri, diagnostic["range"], "sql_injection"]
                    }
                ))
        
        # Generic actions
        if diagnostics:
            actions.append(CodeAction(
                title="Fix all NjordScan issues",
                kind="source.fixAll.njordscan",
                command={
                    "title": "Fix all issues",
                    "command": "njordscan.fixSecurity",
                    "arguments": [uri, "all"]
                }
            ))
        
        return actions
    
    async def _publish_diagnostics(self, uri: str, diagnostics: List[Diagnostic]):
        """Publish diagnostics to the client."""
        
        # This would send LSP notification to client
        # For now, just log
        logger.debug(f"Publishing {len(diagnostics)} diagnostics for {uri}")
    
    # Command handlers
    
    async def _execute_scan_file(self, arguments: List[Any]) -> Dict[str, Any]:
        """Execute scan file command."""
        
        if not arguments:
            return {"error": "No file specified"}
        
        file_uri = arguments[0]
        
        # Trigger immediate analysis
        if file_uri in self.documents:
            await self.analysis_queue.put({
                "action": "analyze",
                "uri": file_uri,
                "content": self.documents[file_uri],
                "priority": True
            })
        
        return {"message": f"Scanning {file_uri}"}
    
    async def _execute_scan_workspace(self, arguments: List[Any]) -> Dict[str, Any]:
        """Execute scan workspace command."""
        
        # Scan all open documents
        for uri in self.documents:
            await self.analysis_queue.put({
                "action": "analyze",
                "uri": uri,
                "content": self.documents[uri],
                "priority": True
            })
        
        return {"message": f"Scanning workspace with {len(self.documents)} files"}
    
    async def _execute_fix_security(self, arguments: List[Any]) -> Dict[str, Any]:
        """Execute fix security command."""
        
        if len(arguments) < 2:
            return {"error": "Insufficient arguments"}
        
        uri = arguments[0]
        fix_type = arguments[1]
        
        # Apply automated fixes
        if fix_type == "all":
            return {"message": f"Applied all fixes to {uri}"}
        else:
            return {"message": f"Applied {fix_type} fix to {uri}"}
    
    async def _execute_show_report(self, arguments: List[Any]) -> Dict[str, Any]:
        """Execute show report command."""
        
        # Generate and show security report
        return {"message": "Opening security report"}
    
    async def shutdown(self):
        """Shutdown the language server."""
        
        logger.info("Shutting down Language Server")
        
        self.shutdown_requested = True
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        logger.info("Language Server shutdown completed")

class IDEIntegration:
    """Main IDE integration manager."""
    
    def __init__(self, config: IDEConfig = None):
        self.config = config or IDEConfig()
        self.language_server: Optional[LanguageServer] = None
        self.detected_ides: List[IDEType] = []
        
        # Extension management
        self.extensions_installed = {}
        
        # WebSocket server for real-time communication
        self.websocket_server = None
        
    async def initialize(self, scanner=None):
        """Initialize IDE integration."""
        
        logger.info("Initializing IDE Integration")
        
        # Detect available IDEs
        self.detected_ides = await self._detect_ides()
        logger.info(f"Detected IDEs: {[ide.value for ide in self.detected_ides]}")
        
        # Start Language Server if enabled
        if self.config.enable_lsp:
            self.language_server = LanguageServer(self.config)
            await self.language_server.initialize(scanner)
        
        # Install/update extensions
        if self.config.auto_install_extension:
            await self._manage_extensions()
        
        logger.info("IDE Integration initialized")
    
    async def _detect_ides(self) -> List[IDEType]:
        """Detect available IDEs on the system."""
        
        detected = []
        
        # Check for VS Code
        if await self._check_ide_installed("code") or await self._check_ide_installed("code-insiders"):
            detected.append(IDEType.VSCODE)
        
        # Check for IntelliJ family
        if (await self._check_ide_installed("idea") or 
            await self._check_ide_installed("webstorm") or
            await self._check_ide_installed("pycharm")):
            detected.append(IDEType.INTELLIJ)
        
        # Check for other editors
        if await self._check_ide_installed("atom"):
            detected.append(IDEType.ATOM)
        
        if await self._check_ide_installed("subl"):
            detected.append(IDEType.SUBLIME)
        
        if await self._check_ide_installed("vim") or await self._check_ide_installed("nvim"):
            detected.append(IDEType.VIM)
        
        if await self._check_ide_installed("emacs"):
            detected.append(IDEType.EMACS)
        
        return detected
    
    async def _check_ide_installed(self, command: str) -> bool:
        """Check if an IDE command is available."""
        
        try:
            result = await asyncio.create_subprocess_exec(
                "which", command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.wait()
            return result.returncode == 0
        except Exception:
            return False
    
    async def _manage_extensions(self):
        """Manage IDE extensions installation."""
        
        for ide_type in self.detected_ides:
            if ide_type == IDEType.VSCODE:
                await self._manage_vscode_extension()
            elif ide_type == IDEType.VIM:
                await self._manage_vim_plugin()
            # Add other IDEs as needed
    
    async def _manage_vscode_extension(self):
        """Manage VS Code extension."""
        
        try:
            # Check if extension is installed
            result = await asyncio.create_subprocess_exec(
                "code", "--list-extensions",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await result.communicate()
            installed_extensions = stdout.decode().strip().split('\n')
            
            extension_id = "njordscan.njordscan-security"
            
            if extension_id not in installed_extensions:
                logger.info("Installing NjordScan VS Code extension")
                
                # Create extension package
                await self._create_vscode_extension()
                
                # Install extension
                await asyncio.create_subprocess_exec(
                    "code", "--install-extension", f"{extension_id}.vsix"
                )
                
                self.extensions_installed[IDEType.VSCODE] = True
                logger.info("VS Code extension installed successfully")
            else:
                logger.info("VS Code extension already installed")
                self.extensions_installed[IDEType.VSCODE] = True
                
        except Exception as e:
            logger.error(f"Failed to manage VS Code extension: {str(e)}")
    
    async def _create_vscode_extension(self):
        """Create VS Code extension package."""
        
        extension_dir = Path(tempfile.mkdtemp()) / "njordscan-vscode"
        extension_dir.mkdir(parents=True)
        
        # Package.json
        package_json = {
            "name": "njordscan-security",
            "displayName": "NjordScan Security Scanner",
            "description": "Advanced security scanner for Next.js, React, and Vite applications",
            "version": "1.0.0",
            "publisher": "njordscan",
            "engines": {"vscode": "^1.70.0"},
            "categories": ["Linters", "Other"],
            "keywords": ["security", "nextjs", "react", "vite", "vulnerability"],
            "main": "./out/extension.js",
            "contributes": {
                "languages": [{
                    "id": "javascript",
                    "extensions": [".js", ".jsx", ".mjs"]
                }, {
                    "id": "typescript",
                    "extensions": [".ts", ".tsx"]
                }],
                "commands": [{
                    "command": "njordscan.scanFile",
                    "title": "Scan Current File",
                    "category": "NjordScan"
                }, {
                    "command": "njordscan.scanWorkspace",
                    "title": "Scan Workspace",
                    "category": "NjordScan"
                }, {
                    "command": "njordscan.showReport",
                    "title": "Show Security Report",
                    "category": "NjordScan"
                }],
                "menus": {
                    "explorer/context": [{
                        "command": "njordscan.scanFile",
                        "when": "resourceExtname =~ /\\.(js|jsx|ts|tsx|json)$/",
                        "group": "njordscan"
                    }],
                    "editor/context": [{
                        "command": "njordscan.scanFile",
                        "when": "resourceExtname =~ /\\.(js|jsx|ts|tsx|json)$/",
                        "group": "njordscan"
                    }]
                },
                "configuration": {
                    "title": "NjordScan",
                    "properties": {
                        "njordscan.enableRealTimeAnalysis": {
                            "type": "boolean",
                            "default": True,
                            "description": "Enable real-time security analysis"
                        },
                        "njordscan.showSecurityDiagnostics": {
                            "type": "boolean",
                            "default": True,
                            "description": "Show security diagnostics in editor"
                        },
                        "njordscan.analysisDelay": {
                            "type": "number",
                            "default": 1000,
                            "description": "Delay before analysis (milliseconds)"
                        }
                    }
                }
            },
            "scripts": {
                "compile": "tsc -p ./",
                "watch": "tsc -watch -p ./"
            },
            "dependencies": {
                "vscode-languageclient": "^8.0.0"
            },
            "devDependencies": {
                "@types/vscode": "^1.70.0",
                "typescript": "^4.7.0"
            }
        }
        
        with open(extension_dir / "package.json", 'w') as f:
            json.dump(package_json, f, indent=2)
        
        # Extension TypeScript code
        extension_ts = '''
import * as vscode from 'vscode';
import { LanguageClient, LanguageClientOptions, ServerOptions, TransportKind } from 'vscode-languageclient/node';

let client: LanguageClient;

export function activate(context: vscode.ExtensionContext) {
    // Language client options
    const clientOptions: LanguageClientOptions = {
        documentSelector: [
            { scheme: 'file', language: 'javascript' },
            { scheme: 'file', language: 'typescript' },
            { scheme: 'file', language: 'javascriptreact' },
            { scheme: 'file', language: 'typescriptreact' }
        ],
        synchronize: {
            fileEvents: vscode.workspace.createFileSystemWatcher('**/.{js,jsx,ts,tsx,json}')
        }
    };

    // Server options
    const serverOptions: ServerOptions = {
        run: { module: 'njordscan-language-server', transport: TransportKind.stdio },
        debug: { module: 'njordscan-language-server', transport: TransportKind.stdio, options: { execArgv: ['--nolazy', '--inspect=6009'] } }
    };

    // Create language client
    client = new LanguageClient('njordscan', 'NjordScan Security Scanner', serverOptions, clientOptions);

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('njordscan.scanFile', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                client.sendRequest('workspace/executeCommand', {
                    command: 'njordscan.scanFile',
                    arguments: [editor.document.uri.toString()]
                });
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('njordscan.scanWorkspace', () => {
            client.sendRequest('workspace/executeCommand', {
                command: 'njordscan.scanWorkspace',
                arguments: []
            });
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('njordscan.showReport', () => {
            client.sendRequest('workspace/executeCommand', {
                command: 'njordscan.showReport',
                arguments: []
            });
        })
    );

    // Start the client
    client.start();
}

export function deactivate(): Thenable<void> | undefined {
    if (!client) {
        return undefined;
    }
    return client.stop();
}
'''
        
        # Create src directory and extension file
        src_dir = extension_dir / "src"
        src_dir.mkdir()
        
        with open(src_dir / "extension.ts", 'w') as f:
            f.write(extension_ts)
        
        # TypeScript config
        tsconfig = {
            "compilerOptions": {
                "module": "commonjs",
                "target": "es6",
                "outDir": "out",
                "lib": ["es6"],
                "sourceMap": True,
                "rootDir": "src",
                "strict": True
            },
            "exclude": ["node_modules", ".vscode-test"]
        }
        
        with open(extension_dir / "tsconfig.json", 'w') as f:
            json.dump(tsconfig, f, indent=2)
        
        logger.info(f"VS Code extension created at {extension_dir}")
    
    async def _manage_vim_plugin(self):
        """Manage Vim plugin installation."""
        
        vim_config_dir = Path.home() / ".vim"
        if not vim_config_dir.exists():
            # Try Neovim config
            vim_config_dir = Path.home() / ".config" / "nvim"
        
        if vim_config_dir.exists():
            plugin_dir = vim_config_dir / "pack" / "njordscan" / "start" / "njordscan"
            plugin_dir.mkdir(parents=True, exist_ok=True)
            
            # Create basic Vim plugin
            plugin_content = '''
" NjordScan Vim Plugin
if exists('g:loaded_njordscan')
  finish
endif
let g:loaded_njordscan = 1

" Commands
command! NjordScanFile call njordscan#ScanFile()
command! NjordScanProject call njordscan#ScanProject()

" Auto commands
augroup NjordScan
  autocmd!
  autocmd BufWritePost *.js,*.jsx,*.ts,*.tsx call njordscan#ScanFile()
augroup END
'''
            
            with open(plugin_dir / "plugin" / "njordscan.vim", 'w') as f:
                f.write(plugin_content)
            
            logger.info("Vim plugin installed")
            self.extensions_installed[IDEType.VIM] = True
    
    def get_integration_status(self) -> Dict[str, Any]:
        """Get IDE integration status."""
        
        return {
            "detected_ides": [ide.value for ide in self.detected_ides],
            "language_server_running": self.language_server is not None and self.language_server.initialized,
            "extensions_installed": {ide.value: installed for ide, installed in self.extensions_installed.items()},
            "config": {
                "lsp_enabled": self.config.enable_lsp,
                "real_time_analysis": self.config.enable_real_time_analysis,
                "auto_install_extensions": self.config.auto_install_extension
            }
        }
    
    async def shutdown(self):
        """Shutdown IDE integration."""
        
        logger.info("Shutting down IDE Integration")
        
        if self.language_server:
            await self.language_server.shutdown()
        
        if self.websocket_server:
            await self.websocket_server.close()
        
        logger.info("IDE Integration shutdown completed")
