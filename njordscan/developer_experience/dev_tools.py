"""
Development Tools and Utilities

Comprehensive development tools for enhanced productivity:
- Project scaffolding and templates
- Security-focused code generators
- Development server integration
- Hot reload with security monitoring
- Debug tools and security profiling
- Performance analysis and optimization
- Automated fix suggestions and implementations
"""

import asyncio
import os
import shutil
import json
import yaml
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import time
import logging
import subprocess
import tempfile
import hashlib
import watchdog.observers
from watchdog.events import FileSystemEventHandler

# Conditional imports for optional dependencies
try:
    import aiofiles
    AIOFILES_AVAILABLE = True
except ImportError:
    AIOFILES_AVAILABLE = False
    aiofiles = None

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    aiohttp = None

try:
    from jinja2 import Environment, FileSystemLoader, Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False
    Environment = None
    FileSystemLoader = None
    Template = None

logger = logging.getLogger(__name__)

class ProjectType(Enum):
    """Supported project types."""
    NEXTJS = "nextjs"
    REACT = "react"
    VITE_REACT = "vite-react"
    VITE_VUE = "vite-vue"
    EXPRESS = "express"
    FASTIFY = "fastify"
    CUSTOM = "custom"

class TemplateType(Enum):
    """Template types."""
    STARTER = "starter"
    COMPONENT = "component"
    MIDDLEWARE = "middleware"
    API_ROUTE = "api_route"
    CONFIG = "config"
    SECURITY = "security"

class SecurityLevel(Enum):
    """Security configuration levels."""
    BASIC = "basic"
    STANDARD = "standard"
    ADVANCED = "advanced"
    ENTERPRISE = "enterprise"

@dataclass
class ProjectTemplate:
    """Project template definition."""
    template_id: str
    name: str
    description: str
    project_type: ProjectType
    template_type: TemplateType
    security_level: SecurityLevel
    
    # Template files and structure
    files: Dict[str, str] = field(default_factory=dict)  # path -> content
    directories: List[str] = field(default_factory=list)
    
    # Dependencies
    dependencies: Dict[str, str] = field(default_factory=dict)
    dev_dependencies: Dict[str, str] = field(default_factory=dict)
    
    # Configuration
    scripts: Dict[str, str] = field(default_factory=dict)
    environment_variables: Dict[str, str] = field(default_factory=dict)
    
    # Security features
    security_features: List[str] = field(default_factory=list)
    security_configs: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    version: str = "1.0.0"
    author: str = "NjordScan"
    license: str = "MIT"
    tags: List[str] = field(default_factory=list)

@dataclass
class CodeGenerator:
    """Code generator configuration."""
    generator_id: str
    name: str
    description: str
    target_language: str
    
    # Generation templates
    templates: Dict[str, str] = field(default_factory=dict)
    
    # Security patterns
    security_patterns: List[str] = field(default_factory=list)
    anti_patterns: List[str] = field(default_factory=list)
    
    # Validation rules
    validation_rules: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class DevServerConfig:
    """Development server configuration."""
    port: int = 3000
    host: str = "localhost"
    https: bool = False
    
    # Security monitoring
    enable_security_monitoring: bool = True
    monitor_file_changes: bool = True
    auto_scan_on_change: bool = True
    
    # Hot reload
    enable_hot_reload: bool = True
    reload_delay_ms: int = 500
    
    # Debugging
    enable_debug_mode: bool = False
    debug_port: int = 9229
    
    # Performance
    enable_performance_monitoring: bool = True
    performance_threshold_ms: int = 1000

class DevTools:
    """Comprehensive development tools suite."""
    
    def __init__(self):
        self.templates: Dict[str, ProjectTemplate] = {}
        self.code_generators: Dict[str, CodeGenerator] = {}
        
        # Template engine
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
            autoescape=True
        )
        
        # File watcher
        self.file_observer: Optional[watchdog.observers.Observer] = None
        self.watched_paths: Set[str] = set()
        
        # Development servers
        self.dev_servers: Dict[str, subprocess.Popen] = {}
        
        # Statistics
        self.stats = {
            'projects_created': 0,
            'code_generated': 0,
            'fixes_applied': 0,
            'templates_used': 0,
            'dev_servers_started': 0
        }
        
        # Initialize built-in templates and generators
        asyncio.create_task(self._initialize_builtin_resources())
    
    async def _initialize_builtin_resources(self):
        """Initialize built-in templates and code generators."""
        
        # Load built-in project templates
        await self._load_builtin_templates()
        
        # Load built-in code generators
        await self._load_builtin_generators()
        
        logger.info(f"Loaded {len(self.templates)} templates and {len(self.code_generators)} generators")
    
    async def create_project(self, project_name: str, template_id: str, 
                           target_dir: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create new project from template."""
        
        options = options or {}
        
        if template_id not in self.templates:
            return {'error': f'Template not found: {template_id}'}
        
        template = self.templates[template_id]
        project_path = Path(target_dir) / project_name
        
        try:
            logger.info(f"Creating project '{project_name}' using template '{template_id}'")
            
            # Create project directory
            project_path.mkdir(parents=True, exist_ok=True)
            
            # Create directory structure
            for directory in template.directories:
                (project_path / directory).mkdir(parents=True, exist_ok=True)
            
            # Process and create files
            for file_path, content_template in template.files.items():
                await self._create_file_from_template(
                    project_path / file_path,
                    content_template,
                    {
                        'project_name': project_name,
                        'security_level': template.security_level.value,
                        **options
                    }
                )
            
            # Create package.json if it's a Node.js project
            if template.project_type in [ProjectType.NEXTJS, ProjectType.REACT, ProjectType.VITE_REACT]:
                await self._create_package_json(project_path, project_name, template, options)
            
            # Install dependencies
            if options.get('install_dependencies', True):
                await self._install_dependencies(project_path)
            
            # Apply security configurations
            await self._apply_security_configs(project_path, template)
            
            # Generate security documentation
            await self._generate_security_docs(project_path, template)
            
            self.stats['projects_created'] += 1
            self.stats['templates_used'] += 1
            
            result = {
                'success': True,
                'project_path': str(project_path),
                'template_used': template_id,
                'security_level': template.security_level.value,
                'security_features': template.security_features,
                'next_steps': self._get_next_steps(template)
            }
            
            logger.info(f"Project created successfully: {project_path}")
            return result
            
        except Exception as e:
            logger.error(f"Failed to create project: {str(e)}")
            return {'error': str(e)}
    
    async def generate_code(self, generator_id: str, target_path: str, 
                          params: Dict[str, Any]) -> Dict[str, Any]:
        """Generate code using specified generator."""
        
        if generator_id not in self.code_generators:
            return {'error': f'Code generator not found: {generator_id}'}
        
        generator = self.code_generators[generator_id]
        
        try:
            logger.info(f"Generating code using '{generator_id}' generator")
            
            generated_files = []
            
            for template_name, template_content in generator.templates.items():
                # Process template
                template = Template(template_content)
                generated_content = template.render(**params)
                
                # Apply security patterns
                generated_content = await self._apply_security_patterns(
                    generated_content, generator.security_patterns
                )
                
                # Validate against anti-patterns
                validation_result = await self._validate_against_antipatterns(
                    generated_content, generator.anti_patterns
                )
                
                if not validation_result['valid']:
                    return {
                        'error': f'Generated code contains anti-patterns: {validation_result["issues"]}'
                    }
                
                # Write generated file
                output_file = Path(target_path) / f"{params.get('name', 'generated')}_{template_name}"
                
                async with aiofiles.open(output_file, 'w') as f:
                    await f.write(generated_content)
                
                generated_files.append(str(output_file))
            
            self.stats['code_generated'] += 1
            
            return {
                'success': True,
                'generated_files': generated_files,
                'generator_used': generator_id,
                'security_patterns_applied': len(generator.security_patterns)
            }
            
        except Exception as e:
            logger.error(f"Code generation failed: {str(e)}")
            return {'error': str(e)}
    
    async def start_dev_server(self, project_path: str, config: DevServerConfig = None) -> Dict[str, Any]:
        """Start development server with security monitoring."""
        
        config = config or DevServerConfig()
        project_path = Path(project_path)
        
        if not project_path.exists():
            return {'error': f'Project path not found: {project_path}'}
        
        try:
            logger.info(f"Starting development server for {project_path}")
            
            # Detect project type
            project_type = await self._detect_project_type(project_path)
            
            # Start appropriate dev server
            server_process = await self._start_project_server(project_path, project_type, config)
            
            if not server_process:
                return {'error': 'Failed to start development server'}
            
            server_id = hashlib.md5(str(project_path).encode()).hexdigest()[:8]
            self.dev_servers[server_id] = server_process
            
            # Start file monitoring if enabled
            if config.monitor_file_changes:
                await self._start_file_monitoring(project_path, config)
            
            self.stats['dev_servers_started'] += 1
            
            return {
                'success': True,
                'server_id': server_id,
                'url': f"{'https' if config.https else 'http'}://{config.host}:{config.port}",
                'pid': server_process.pid,
                'project_type': project_type.value if project_type else 'unknown',
                'monitoring_enabled': config.enable_security_monitoring
            }
            
        except Exception as e:
            logger.error(f"Failed to start dev server: {str(e)}")
            return {'error': str(e)}
    
    async def apply_automated_fixes(self, file_path: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Apply automated security fixes to a file."""
        
        file_path = Path(file_path)
        
        if not file_path.exists():
            return {'error': f'File not found: {file_path}'}
        
        try:
            logger.info(f"Applying automated fixes to {file_path}")
            
            # Read original file
            async with aiofiles.open(file_path, 'r') as f:
                original_content = await f.read()
            
            modified_content = original_content
            fixes_applied = []
            
            # Apply fixes for each finding
            for finding in findings:
                fix_result = await self._apply_single_fix(modified_content, finding)
                
                if fix_result['success']:
                    modified_content = fix_result['content']
                    fixes_applied.append(fix_result['fix_description'])
            
            # Write modified content back to file
            if fixes_applied:
                # Create backup
                backup_path = file_path.with_suffix(file_path.suffix + '.backup')
                shutil.copy2(file_path, backup_path)
                
                async with aiofiles.open(file_path, 'w') as f:
                    await f.write(modified_content)
                
                self.stats['fixes_applied'] += len(fixes_applied)
            
            return {
                'success': True,
                'fixes_applied': fixes_applied,
                'backup_created': str(backup_path) if fixes_applied else None,
                'modified': len(fixes_applied) > 0
            }
            
        except Exception as e:
            logger.error(f"Failed to apply automated fixes: {str(e)}")
            return {'error': str(e)}
    
    async def generate_security_docs(self, project_path: str) -> Dict[str, Any]:
        """Generate comprehensive security documentation."""
        
        project_path = Path(project_path)
        
        try:
            logger.info(f"Generating security documentation for {project_path}")
            
            # Analyze project structure
            project_analysis = await self._analyze_project_structure(project_path)
            
            # Generate different types of documentation
            docs_generated = []
            
            # Security documentation removed - using community-driven approach
            
            # Security checklist
            checklist_content = await self._generate_security_checklist(project_analysis)
            checklist_path = project_path / "docs" / "security-checklist.md"
            checklist_path.parent.mkdir(exist_ok=True)
            
            async with aiofiles.open(checklist_path, 'w') as f:
                await f.write(checklist_content)
            docs_generated.append(str(checklist_path))
            
            # Threat model
            threat_model = await self._generate_threat_model(project_analysis)
            threat_path = project_path / "docs" / "threat-model.md"
            
            async with aiofiles.open(threat_path, 'w') as f:
                await f.write(threat_model)
            docs_generated.append(str(threat_path))
            
            # Security configuration guide
            config_guide = await self._generate_config_guide(project_analysis)
            config_path = project_path / "docs" / "security-configuration.md"
            
            async with aiofiles.open(config_path, 'w') as f:
                await f.write(config_guide)
            docs_generated.append(str(config_path))
            
            return {
                'success': True,
                'docs_generated': docs_generated,
                'project_type': project_analysis.get('project_type', 'unknown'),
                'security_features': project_analysis.get('security_features', [])
            }
            
        except Exception as e:
            logger.error(f"Failed to generate security docs: {str(e)}")
            return {'error': str(e)}
    
    # Private methods
    
    async def _load_builtin_templates(self):
        """Load built-in project templates."""
        
        # Next.js Secure Starter Template
        nextjs_template = ProjectTemplate(
            template_id="nextjs-secure-starter",
            name="Next.js Secure Starter",
            description="Production-ready Next.js template with security best practices",
            project_type=ProjectType.NEXTJS,
            template_type=TemplateType.STARTER,
            security_level=SecurityLevel.ADVANCED,
            directories=[
                "pages/api",
                "components",
                "lib",
                "middleware",
                "public",
                "styles",
                "docs",
                "tests"
            ],
            files={
                "next.config.js": """
const { withSentryConfig } = require('@sentry/nextjs');

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  swcMinify: true,
  
  // Security headers
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'X-Frame-Options',
            value: 'DENY'
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff'
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin'
          },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=()'
          }
        ]
      }
    ];
  },
  
  // Content Security Policy
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: '/api/:path*',
        has: [
          {
            type: 'header',
            key: 'content-type',
            value: 'application/json'
          }
        ]
      }
    ];
  }
};

module.exports = withSentryConfig(nextConfig, {
  silent: true,
  org: "{{ project_name }}",
  project: "{{ project_name }}"
});
""",
                "middleware.ts": """
import { NextRequest, NextResponse } from 'next/server';
import rateLimit from '@/lib/rate-limit';

export async function middleware(request: NextRequest) {
  // Rate limiting
  const limiter = rateLimit({
    interval: 60 * 1000, // 60 seconds
    uniqueTokenPerInterval: 500, // Max 500 users per second
  });

  try {
    await limiter.check(10, 'CACHE_TOKEN'); // 10 requests per minute
  } catch {
    return new NextResponse('Too Many Requests', { status: 429 });
  }

  // Security headers
  const response = NextResponse.next();
  
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  return response;
}

export const config = {
  matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
};
""",
                "lib/auth.ts": """
import { NextAuthOptions } from 'next-auth';
import { PrismaAdapter } from '@next-auth/prisma-adapter';
import { prisma } from './prisma';
import bcrypt from 'bcryptjs';

export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(prisma),
  providers: [
    // Add your providers here
  ],
  session: {
    strategy: 'jwt',
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  jwt: {
    secret: process.env.NEXTAUTH_SECRET,
  },
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id;
      }
      return token;
    },
    async session({ session, token }) {
      if (token) {
        session.user.id = token.id;
      }
      return session;
    },
  },
  pages: {
    signIn: '/auth/signin',
    signOut: '/auth/signout',
    error: '/auth/error',
  },
};
""",
                ".env.example": """
# Database
DATABASE_URL="postgresql://username:password@localhost:5432/{{ project_name }}"

# NextAuth.js
NEXTAUTH_URL="http://localhost:3000"
NEXTAUTH_SECRET="your-secret-here"

# Security
ENCRYPTION_KEY="your-encryption-key-here"
JWT_SECRET="your-jwt-secret-here"

# External APIs
SENTRY_DSN="your-sentry-dsn-here"
""",
                ".njordscan.json": """
{
  "framework": "nextjs",
  "security_level": "{{ security_level }}",
  "modules": {
    "headers": true,
    "static": true,
    "dependencies": true,
    "configs": true,
    "runtime": true,
    "ai": true
  },
  "rules": {
    "enable_custom_rules": true,
    "severity_threshold": "medium"
  },
  "reporting": {
    "format": "html",
    "include_recommendations": true
  }
}
"""
            },
            dependencies={
                "next": "^14.0.0",
                "react": "^18.0.0",
                "react-dom": "^18.0.0",
                "next-auth": "^4.24.0",
                "@prisma/client": "^5.0.0",
                "bcryptjs": "^2.4.3",
                "@sentry/nextjs": "^7.0.0"
            },
            dev_dependencies={
                "typescript": "^5.0.0",
                "@types/node": "^20.0.0",
                "@types/react": "^18.0.0",
                "@types/bcryptjs": "^2.4.0",
                "prisma": "^5.0.0",
                "eslint": "^8.0.0",
                "eslint-config-next": "^14.0.0"
            },
            scripts={
                "dev": "next dev",
                "build": "next build",
                "start": "next start",
                "lint": "next lint",
                "security": "njordscan",
                "security:ci": "njordscan --ci --format sarif"
            },
            security_features=[
                "Security Headers",
                "Rate Limiting",
                "Authentication",
                "Input Validation",
                "CSRF Protection",
                "SQL Injection Prevention",
                "XSS Protection"
            ]
        )
        
        self.templates[nextjs_template.template_id] = nextjs_template
        
        # React Secure Component Template
        react_component_template = ProjectTemplate(
            template_id="react-secure-component",
            name="React Secure Component",
            description="Secure React component template with best practices",
            project_type=ProjectType.REACT,
            template_type=TemplateType.COMPONENT,
            security_level=SecurityLevel.STANDARD,
            files={
                "Component.tsx": """
import React, { useState, useCallback, useMemo } from 'react';
import DOMPurify from 'dompurify';

interface {{ component_name }}Props {
  data?: unknown;
  onAction?: (data: unknown) => void;
  className?: string;
}

/**
 * {{ component_name }} - A secure React component
 * 
 * Security features:
 * - Input sanitization
 * - XSS prevention
 * - Safe HTML rendering
 * - Prop validation
 */
export const {{ component_name }}: React.FC<{{ component_name }}Props> = ({
  data,
  onAction,
  className = ''
}) => {
  const [isLoading, setIsLoading] = useState(false);
  
  // Sanitize HTML content
  const sanitizeHTML = useCallback((html: string) => {
    return DOMPurify.sanitize(html, {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
      ALLOWED_ATTR: []
    });
  }, []);
  
  // Memoized safe content
  const safeContent = useMemo(() => {
    if (typeof data === 'string') {
      return sanitizeHTML(data);
    }
    return '';
  }, [data, sanitizeHTML]);
  
  // Safe event handler
  const handleAction = useCallback((event: React.MouseEvent) => {
    event.preventDefault();
    
    if (typeof onAction === 'function') {
      setIsLoading(true);
      
      try {
        onAction(data);
      } catch (error) {
        console.error('Action failed:', error);
      } finally {
        setIsLoading(false);
      }
    }
  }, [data, onAction]);
  
  return (
    <div className={`{{ component_name.lower() }} ${className}`}>
      {safeContent && (
        <div 
          dangerouslySetInnerHTML={{ __html: safeContent }}
          className="content"
        />
      )}
      
      <button
        onClick={handleAction}
        disabled={isLoading}
        className="action-button"
        type="button"
      >
        {isLoading ? 'Loading...' : 'Action'}
      </button>
    </div>
  );
};

export default {{ component_name }};
""",
                "Component.test.tsx": """
import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { {{ component_name }} } from './{{ component_name }}';

describe('{{ component_name }}', () => {
  it('renders without crashing', () => {
    render(<{{ component_name }} />);
  });
  
  it('sanitizes malicious HTML', () => {
    const maliciousData = '<script>alert("XSS")</script><p>Safe content</p>';
    render(<{{ component_name }} data={maliciousData} />);
    
    // Should not contain script tag
    expect(screen.queryByText('alert("XSS")')).not.toBeInTheDocument();
    // Should contain safe content
    expect(screen.getByText('Safe content')).toBeInTheDocument();
  });
  
  it('handles action callback safely', () => {
    const mockAction = jest.fn();
    render(<{{ component_name }} onAction={mockAction} />);
    
    const button = screen.getByRole('button');
    fireEvent.click(button);
    
    expect(mockAction).toHaveBeenCalled();
  });
});
"""
            },
            dependencies={
                "react": "^18.0.0",
                "dompurify": "^3.0.0"
            },
            dev_dependencies={
                "@types/react": "^18.0.0",
                "@types/dompurify": "^3.0.0",
                "@testing-library/react": "^14.0.0",
                "@testing-library/jest-dom": "^6.0.0"
            },
            security_features=[
                "XSS Prevention",
                "HTML Sanitization",
                "Safe Event Handling",
                "Input Validation"
            ]
        )
        
        self.templates[react_component_template.template_id] = react_component_template
    
    async def _load_builtin_generators(self):
        """Load built-in code generators."""
        
        # Secure API Route Generator
        api_generator = CodeGenerator(
            generator_id="secure-api-route",
            name="Secure API Route Generator",
            description="Generate secure API routes with validation and error handling",
            target_language="typescript",
            templates={
                "route.ts": """
import { NextApiRequest, NextApiResponse } from 'next';
import { z } from 'zod';
import rateLimit from '@/lib/rate-limit';
import { authenticate } from '@/lib/auth';

// Rate limiting
const limiter = rateLimit({
  interval: 60 * 1000, // 60 seconds
  uniqueTokenPerInterval: 500,
});

// Request validation schema
const {{ name }}Schema = z.object({
  {% for field in fields %}
  {{ field.name }}: z.{{ field.type }}(){% if field.required %}.min(1){% endif %},
  {% endfor %}
});

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  try {
    // Rate limiting
    await limiter.check(10, 'CACHE_TOKEN');
    
    // Method validation
    if (req.method !== '{{ method }}') {
      return res.status(405).json({ error: 'Method not allowed' });
    }
    
    // Authentication
    {% if requires_auth %}
    const user = await authenticate(req);
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    {% endif %}
    
    // Input validation
    const validation = {{ name }}Schema.safeParse(req.body);
    if (!validation.success) {
      return res.status(400).json({ 
        error: 'Invalid input',
        details: validation.error.errors
      });
    }
    
    const data = validation.data;
    
    // Business logic
    const result = await process{{ name }}(data{% if requires_auth %}, user{% endif %});
    
    // Success response
    res.status(200).json({ 
      success: true,
      data: result
    });
    
  } catch (error) {
    console.error('{{ name }} API error:', error);
    
    // Security: Don't expose internal errors
    res.status(500).json({ 
      error: 'Internal server error'
    });
  }
}

async function process{{ name }}(
  data: z.infer<typeof {{ name }}Schema>{% if requires_auth %},
  user: any{% endif %}
) {
  // TODO: Implement your business logic here
  
  return {
    message: 'Processing completed',
    timestamp: new Date().toISOString()
  };
}
"""
            },
            security_patterns=[
                "Rate limiting on all endpoints",
                "Input validation with Zod schemas",
                "Authentication checks",
                "Method validation",
                "Error handling without information leakage",
                "CORS headers",
                "Request logging"
            ],
            anti_patterns=[
                "eval(",
                "dangerouslySetInnerHTML",
                "innerHTML =",
                "document.write",
                "setTimeout(string",
                "setInterval(string"
            ]
        )
        
        self.code_generators[api_generator.generator_id] = api_generator
    
    async def _create_file_from_template(self, file_path: Path, template_content: str, 
                                       context: Dict[str, Any]):
        """Create file from template with context substitution."""
        
        # Ensure directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Process template
        template = Template(template_content)
        processed_content = template.render(**context)
        
        # Write file
        async with aiofiles.open(file_path, 'w') as f:
            await f.write(processed_content)
    
    async def _create_package_json(self, project_path: Path, project_name: str, 
                                 template: ProjectTemplate, options: Dict[str, Any]):
        """Create package.json file."""
        
        package_json = {
            "name": project_name,
            "version": "0.1.0",
            "private": True,
            "description": f"Secure {template.project_type.value} application",
            "scripts": {
                **template.scripts,
                "security:scan": "njordscan",
                "security:fix": "njordscan --fix",
                "security:report": "njordscan --format html --output security-report.html"
            },
            "dependencies": template.dependencies,
            "devDependencies": {
                **template.dev_dependencies,
                "njordscan": "^1.0.0"
            },
            "engines": {
                "node": ">=18.0.0",
                "npm": ">=8.0.0"
            },
            "keywords": [
                template.project_type.value,
                "security",
                "njordscan",
                *template.tags
            ]
        }
        
        async with aiofiles.open(project_path / "package.json", 'w') as f:
            await f.write(json.dumps(package_json, indent=2))
    
    async def _install_dependencies(self, project_path: Path):
        """Install project dependencies."""
        
        try:
            logger.info("Installing dependencies...")
            
            # Check if npm is available
            result = await asyncio.create_subprocess_exec(
                "npm", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.wait()
            
            if result.returncode != 0:
                logger.warning("npm not found, skipping dependency installation")
                return
            
            # Install dependencies
            process = await asyncio.create_subprocess_exec(
                "npm", "install",
                cwd=project_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                logger.info("Dependencies installed successfully")
            else:
                logger.error(f"Failed to install dependencies: {stderr.decode()}")
                
        except Exception as e:
            logger.error(f"Dependency installation error: {str(e)}")
    
    async def _apply_security_configs(self, project_path: Path, template: ProjectTemplate):
        """Apply security configurations."""
        
        # Create .njordscan.json if not exists
        njordscan_config = project_path / ".njordscan.json"
        if not njordscan_config.exists():
            config = {
                "framework": template.project_type.value,
                "security_level": template.security_level.value,
                "modules": {
                    "headers": True,
                    "static": True,
                    "dependencies": True,
                    "configs": True,
                    "runtime": template.security_level in [SecurityLevel.ADVANCED, SecurityLevel.ENTERPRISE],
                    "ai": template.security_level == SecurityLevel.ENTERPRISE
                },
                "rules": {
                    "enable_custom_rules": True,
                    "severity_threshold": "medium" if template.security_level == SecurityLevel.BASIC else "low"
                }
            }
            
            async with aiofiles.open(njordscan_config, 'w') as f:
                await f.write(json.dumps(config, indent=2))
    
    async def _generate_security_docs(self, project_path: Path, template: ProjectTemplate):
        """Generate security documentation."""
        
        docs_dir = project_path / "docs"
        docs_dir.mkdir(exist_ok=True)
        
        # Security README
        security_readme = f"""# Security Guide

This project was created using NjordScan's secure {template.project_type.value} template.

## Security Features Included

{chr(10).join('- ' + feature for feature in template.security_features)}

## Security Level: {template.security_level.value.title()}

## Quick Security Scan

Run a security scan on your project:

```bash
npm run security:scan
```

## Automated Security Fixes

Apply automated security fixes:

```bash
npm run security:fix
```

## Security Report

Generate a detailed security report:

```bash
npm run security:report
```

## Best Practices

1. Keep dependencies updated
2. Use environment variables for secrets
3. Validate all user inputs
4. Implement proper authentication
5. Use HTTPS in production
6. Regular security scans

## Resources

- [NjordScan Documentation](https://njordscan.dev/docs)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Security Headers](https://securityheaders.com/)
"""
        
        # Security documentation removed - using community-driven approach
    
    def _get_next_steps(self, template: ProjectTemplate) -> List[str]:
        """Get recommended next steps for the project."""
        
        steps = [
            "Install dependencies: npm install",
            "Run security scan: npm run security:scan",
            "Review security best practices in documentation",
            "Configure environment variables from .env.example"
        ]
        
        if template.project_type == ProjectType.NEXTJS:
            steps.extend([
                "Set up database (if using Prisma)",
                "Configure authentication providers",
                "Deploy to Vercel or similar platform"
            ])
        
        return steps
    
    # Additional helper methods would be implemented here...
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get development tools statistics."""
        
        return {
            'templates_available': len(self.templates),
            'generators_available': len(self.code_generators),
            'dev_servers_running': len(self.dev_servers),
            'watched_paths': len(self.watched_paths),
            **self.stats
        }
