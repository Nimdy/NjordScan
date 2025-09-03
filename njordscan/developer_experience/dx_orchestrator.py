"""
Developer Experience Orchestrator

Master orchestrator for all developer experience features:
- Coordinates CLI, IDE integration, and development tools
- Provides unified developer experience interface
- Manages developer workflow optimization
- Handles developer feedback and learning
- Orchestrates seamless development experience
- Manages developer productivity metrics
"""

import asyncio
import time
import logging
from typing import Dict, List, Any, Optional, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import json
import os

from .interactive_cli import InteractiveCLI, CLIConfig
from .ide_integration import IDEIntegration, IDEConfig, LanguageServer
from .dev_tools import DevTools, ProjectTemplate, DevServerConfig

logger = logging.getLogger(__name__)

class DeveloperProfile(Enum):
    """Developer experience profiles."""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    EXPERT = "expert"
    SECURITY_FOCUSED = "security_focused"

class WorkflowStage(Enum):
    """Development workflow stages."""
    SETUP = "setup"
    DEVELOPMENT = "development"
    TESTING = "testing"
    DEPLOYMENT = "deployment"
    MAINTENANCE = "maintenance"

class ExperienceLevel(Enum):
    """Experience quality levels."""
    POOR = "poor"
    BASIC = "basic"
    GOOD = "good"
    EXCELLENT = "excellent"
    OUTSTANDING = "outstanding"

@dataclass
class DeveloperMetrics:
    """Developer productivity and experience metrics."""
    
    # Productivity metrics
    projects_created: int = 0
    scans_performed: int = 0
    issues_fixed: int = 0
    time_saved_minutes: float = 0.0
    
    # Experience metrics
    cli_interactions: int = 0
    ide_integrations_used: int = 0
    automated_fixes_applied: int = 0
    documentation_generated: int = 0
    
    # Quality metrics
    false_positive_rate: float = 0.0
    fix_success_rate: float = 1.0
    developer_satisfaction: float = 5.0  # 1-5 scale
    
    # Learning metrics
    tips_shown: int = 0
    tutorials_completed: int = 0
    help_accessed: int = 0
    
    # Performance metrics
    average_scan_time: float = 0.0
    cache_hit_rate: float = 0.0
    error_rate: float = 0.0

@dataclass
class DeveloperFeedback:
    """Developer feedback and suggestions."""
    feedback_id: str
    developer_profile: DeveloperProfile
    workflow_stage: WorkflowStage
    
    # Feedback content
    rating: int  # 1-5 scale
    comment: str = ""
    suggestions: List[str] = field(default_factory=list)
    
    # Context
    feature_used: str = ""
    time_spent_minutes: float = 0.0
    issues_encountered: List[str] = field(default_factory=list)
    
    # Metadata
    timestamp: float = field(default_factory=time.time)
    version: str = "1.0.0"
    environment: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DXOrchestratorConfig:
    """Configuration for developer experience orchestrator."""
    
    # Core components
    enable_cli: bool = True
    enable_ide_integration: bool = True
    enable_dev_tools: bool = True
    
    # Experience optimization
    enable_adaptive_experience: bool = True
    enable_productivity_tracking: bool = True
    enable_learning_assistance: bool = True
    
    # Developer profiles
    auto_detect_profile: bool = True
    default_profile: DeveloperProfile = DeveloperProfile.INTERMEDIATE
    
    # Feedback and learning
    enable_feedback_collection: bool = True
    enable_usage_analytics: bool = True
    feedback_prompt_frequency: int = 10  # Every 10 interactions
    
    # Performance optimization
    enable_performance_monitoring: bool = True
    cache_developer_preferences: bool = True
    preload_common_features: bool = True
    
    # Component configurations
    cli_config: CLIConfig = field(default_factory=CLIConfig)
    ide_config: IDEConfig = field(default_factory=IDEConfig)
    dev_server_config: DevServerConfig = field(default_factory=DevServerConfig)
    
    # Personalization
    enable_personalization: bool = True
    remember_preferences: bool = True
    adaptive_ui: bool = True
    
    # Integration settings
    enable_workflow_optimization: bool = True
    enable_cross_tool_coordination: bool = True
    enable_context_sharing: bool = True

class DeveloperExperienceOrchestrator:
    """Master orchestrator for developer experience."""
    
    def __init__(self, config: DXOrchestratorConfig = None):
        self.config = config or DXOrchestratorConfig()
        
        # Initialize components
        self.cli: Optional[InteractiveCLI] = None
        self.ide_integration: Optional[IDEIntegration] = None
        self.dev_tools: Optional[DevTools] = None
        
        # Developer state
        self.developer_profile = self.config.default_profile
        self.current_workflow_stage = WorkflowStage.SETUP
        self.developer_metrics = DeveloperMetrics()
        
        # Experience management
        self.feedback_history: List[DeveloperFeedback] = []
        self.preferences: Dict[str, Any] = {}
        self.learning_progress: Dict[str, Any] = {}
        
        # Active sessions
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        
        # Background tasks
        self.background_tasks: List[asyncio.Task] = []
        self.running = False
        self.shutdown_event = asyncio.Event()
        
        # Workflow optimization
        self.workflow_optimizer = WorkflowOptimizer(self.config)
        self.experience_analyzer = ExperienceAnalyzer(self.config)
        self.learning_assistant = LearningAssistant(self.config)
        
        self.start_time = time.time()
    
    async def initialize(self, scanner=None):
        """Initialize developer experience orchestrator."""
        
        logger.info("Initializing Developer Experience Orchestrator")
        
        self.running = True
        
        # Load developer preferences
        await self._load_developer_preferences()
        
        # Auto-detect developer profile if enabled
        if self.config.auto_detect_profile:
            self.developer_profile = await self._detect_developer_profile()
        
        # Initialize components based on configuration
        if self.config.enable_cli:
            self.cli = InteractiveCLI()
            # Apply personalized CLI configuration
            await self._personalize_cli()
        
        if self.config.enable_ide_integration:
            self.ide_integration = IDEIntegration(self.config.ide_config)
            await self.ide_integration.initialize(scanner)
        
        if self.config.enable_dev_tools:
            self.dev_tools = DevTools()
        
        # Initialize experience components
        await self.workflow_optimizer.initialize()
        await self.experience_analyzer.initialize()
        await self.learning_assistant.initialize()
        
        # Start background services
        self.background_tasks = [
            asyncio.create_task(self._experience_monitoring_worker()),
            asyncio.create_task(self._workflow_optimization_worker()),
            asyncio.create_task(self._learning_assistance_worker())
        ]
        
        if self.config.enable_feedback_collection:
            self.background_tasks.append(
                asyncio.create_task(self._feedback_collection_worker())
            )
        
        logger.info(f"Developer Experience Orchestrator initialized for {self.developer_profile.value} profile")
    
    async def start_interactive_session(self) -> Dict[str, Any]:
        """Start interactive developer session."""
        
        session_id = f"session_{int(time.time())}"
        
        logger.info(f"Starting interactive session: {session_id}")
        
        try:
            # Create session context
            session_context = {
                'session_id': session_id,
                'start_time': time.time(),
                'developer_profile': self.developer_profile.value,
                'workflow_stage': self.current_workflow_stage.value,
                'tools_used': [],
                'actions_performed': []
            }
            
            self.active_sessions[session_id] = session_context
            
            # Show personalized welcome
            if self.cli:
                await self._show_personalized_welcome()
            
            # Provide contextual assistance
            assistance = await self._get_contextual_assistance()
            
            # Start workflow optimization
            if self.config.enable_workflow_optimization:
                await self.workflow_optimizer.start_session(session_context)
            
            return {
                'session_id': session_id,
                'developer_profile': self.developer_profile.value,
                'assistance': assistance,
                'available_tools': self._get_available_tools(),
                'recommendations': await self._get_session_recommendations()
            }
            
        except Exception as e:
            logger.error(f"Failed to start interactive session: {str(e)}")
            return {'error': str(e)}
    
    async def create_secure_project(self, project_name: str, project_type: str,
                                  target_dir: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create secure project with full developer experience."""
        
        if not self.dev_tools:
            return {'error': 'Development tools not available'}
        
        try:
            logger.info(f"Creating secure project: {project_name}")
            
            # Update workflow stage
            self.current_workflow_stage = WorkflowStage.SETUP
            
            # Get appropriate template based on developer profile
            template_id = await self._select_optimal_template(project_type, self.developer_profile)
            
            # Create project with enhanced options
            enhanced_options = {
                'developer_profile': self.developer_profile.value,
                'enable_learning_mode': self.developer_profile == DeveloperProfile.BEGINNER,
                'security_level': self._get_security_level_for_profile(),
                **(options or {})
            }
            
            # Create project
            result = await self.dev_tools.create_project(
                project_name, template_id, target_dir, enhanced_options
            )
            
            if result.get('success'):
                # Post-creation enhancements
                project_path = result['project_path']
                
                # Generate comprehensive documentation
                if self.developer_profile in [DeveloperProfile.BEGINNER, DeveloperProfile.SECURITY_FOCUSED]:
                    doc_result = await self.dev_tools.generate_security_docs(project_path)
                    result['documentation_generated'] = doc_result.get('success', False)
                
                # Set up IDE integration
                if self.ide_integration and enhanced_options.get('setup_ide', True):
                    ide_result = await self._setup_project_ide_integration(project_path)
                    result['ide_integration'] = ide_result
                
                # Provide next steps guidance
                result['guided_next_steps'] = await self._generate_guided_next_steps(
                    project_path, self.developer_profile
                )
                
                # Update metrics
                self.developer_metrics.projects_created += 1
                
                # Track workflow progress
                if self.config.enable_workflow_optimization:
                    await self.workflow_optimizer.track_action('project_created', {
                        'project_type': project_type,
                        'template_used': template_id,
                        'success': True
                    })
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to create secure project: {str(e)}")
            return {'error': str(e)}
    
    async def optimize_developer_workflow(self, workflow_data: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize developer workflow based on usage patterns."""
        
        try:
            logger.info("Optimizing developer workflow")
            
            # Analyze current workflow
            analysis = await self.experience_analyzer.analyze_workflow(workflow_data)
            
            # Generate optimization recommendations
            optimizations = await self.workflow_optimizer.generate_optimizations(
                analysis, self.developer_profile
            )
            
            # Apply automatic optimizations
            applied_optimizations = []
            for optimization in optimizations.get('automatic', []):
                try:
                    await self._apply_workflow_optimization(optimization)
                    applied_optimizations.append(optimization['name'])
                except Exception as e:
                    logger.error(f"Failed to apply optimization {optimization['name']}: {str(e)}")
            
            # Update developer metrics
            if applied_optimizations:
                self.developer_metrics.time_saved_minutes += sum(
                    opt.get('time_saved_minutes', 0) 
                    for opt in optimizations.get('automatic', [])
                    if opt['name'] in applied_optimizations
                )
            
            return {
                'success': True,
                'analysis': analysis,
                'optimizations_available': len(optimizations.get('manual', [])),
                'optimizations_applied': applied_optimizations,
                'manual_recommendations': optimizations.get('manual', []),
                'estimated_time_saved': sum(
                    opt.get('time_saved_minutes', 0) 
                    for opt in optimizations.get('automatic', [])
                    if opt['name'] in applied_optimizations
                )
            }
            
        except Exception as e:
            logger.error(f"Workflow optimization failed: {str(e)}")
            return {'error': str(e)}
    
    async def provide_learning_assistance(self, topic: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Provide personalized learning assistance."""
        
        if not self.config.enable_learning_assistance:
            return {'error': 'Learning assistance not enabled'}
        
        try:
            context = context or {}
            context['developer_profile'] = self.developer_profile.value
            context['workflow_stage'] = self.current_workflow_stage.value
            
            assistance = await self.learning_assistant.provide_assistance(topic, context)
            
            # Track learning progress
            self.learning_progress[topic] = self.learning_progress.get(topic, 0) + 1
            self.developer_metrics.help_accessed += 1
            
            return assistance
            
        except Exception as e:
            logger.error(f"Learning assistance failed: {str(e)}")
            return {'error': str(e)}
    
    async def collect_feedback(self, feedback: DeveloperFeedback) -> Dict[str, Any]:
        """Collect and process developer feedback."""
        
        try:
            # Store feedback
            self.feedback_history.append(feedback)
            
            # Analyze feedback for immediate improvements
            if feedback.rating <= 2:  # Poor experience
                await self._handle_poor_experience(feedback)
            
            # Update developer satisfaction metric
            total_ratings = len(self.feedback_history)
            if total_ratings > 0:
                self.developer_metrics.developer_satisfaction = (
                    sum(f.rating for f in self.feedback_history) / total_ratings
                )
            
            # Trigger experience improvements
            if len(self.feedback_history) % 5 == 0:  # Every 5 pieces of feedback
                await self._trigger_experience_improvements()
            
            return {
                'success': True,
                'feedback_id': feedback.feedback_id,
                'improvements_triggered': feedback.rating <= 3
            }
            
        except Exception as e:
            logger.error(f"Feedback collection failed: {str(e)}")
            return {'error': str(e)}
    
    async def get_developer_dashboard(self) -> Dict[str, Any]:
        """Get comprehensive developer dashboard."""
        
        try:
            # Calculate experience quality
            experience_quality = await self._calculate_experience_quality()
            
            # Get productivity insights
            productivity_insights = await self._get_productivity_insights()
            
            # Get learning recommendations
            learning_recommendations = await self.learning_assistant.get_recommendations(
                self.developer_profile, self.learning_progress
            )
            
            # Get workflow optimization opportunities
            workflow_opportunities = await self.workflow_optimizer.get_opportunities()
            
            dashboard = {
                'developer_profile': self.developer_profile.value,
                'experience_quality': experience_quality.value,
                'metrics': {
                    'projects_created': self.developer_metrics.projects_created,
                    'scans_performed': self.developer_metrics.scans_performed,
                    'issues_fixed': self.developer_metrics.issues_fixed,
                    'time_saved_hours': self.developer_metrics.time_saved_minutes / 60,
                    'satisfaction_score': self.developer_metrics.developer_satisfaction,
                    'fix_success_rate': self.developer_metrics.fix_success_rate
                },
                'productivity_insights': productivity_insights,
                'learning': {
                    'recommendations': learning_recommendations,
                    'progress': self.learning_progress,
                    'tips_available': await self.learning_assistant.count_available_tips()
                },
                'workflow': {
                    'current_stage': self.current_workflow_stage.value,
                    'optimization_opportunities': len(workflow_opportunities),
                    'recent_optimizations': workflow_opportunities[:3]
                },
                'tools': {
                    'cli_available': self.cli is not None,
                    'ide_integration_active': (
                        self.ide_integration is not None and 
                        self.ide_integration.language_server is not None
                    ),
                    'dev_tools_available': self.dev_tools is not None
                },
                'session_info': {
                    'active_sessions': len(self.active_sessions),
                    'uptime_hours': (time.time() - self.start_time) / 3600
                }
            }
            
            return dashboard
            
        except Exception as e:
            logger.error(f"Failed to generate developer dashboard: {str(e)}")
            return {'error': str(e)}
    
    # Private methods
    
    async def _load_developer_preferences(self):
        """Load developer preferences from storage."""
        
        try:
            preferences_file = Path.home() / ".njordscan" / "developer_preferences.json"
            
            if preferences_file.exists():
                with open(preferences_file) as f:
                    data = json.load(f)
                
                self.preferences = data.get('preferences', {})
                self.developer_profile = DeveloperProfile(data.get('profile', self.developer_profile.value))
                self.learning_progress = data.get('learning_progress', {})
                
                logger.info("Developer preferences loaded")
            
        except Exception as e:
            logger.warning(f"Failed to load developer preferences: {str(e)}")
    
    async def _save_developer_preferences(self):
        """Save developer preferences to storage."""
        
        try:
            preferences_dir = Path.home() / ".njordscan"
            preferences_dir.mkdir(exist_ok=True)
            
            preferences_file = preferences_dir / "developer_preferences.json"
            
            data = {
                'profile': self.developer_profile.value,
                'preferences': self.preferences,
                'learning_progress': self.learning_progress,
                'metrics': {
                    'projects_created': self.developer_metrics.projects_created,
                    'scans_performed': self.developer_metrics.scans_performed,
                    'time_saved_minutes': self.developer_metrics.time_saved_minutes
                },
                'updated_at': time.time()
            }
            
            with open(preferences_file, 'w') as f:
                json.dump(data, f, indent=2)
            
        except Exception as e:
            logger.error(f"Failed to save developer preferences: {str(e)}")
    
    async def _detect_developer_profile(self) -> DeveloperProfile:
        """Auto-detect developer profile based on environment and usage."""
        
        try:
            profile_indicators = {
                DeveloperProfile.BEGINNER: 0,
                DeveloperProfile.INTERMEDIATE: 0,
                DeveloperProfile.EXPERT: 0,
                DeveloperProfile.SECURITY_FOCUSED: 0
            }
            
            # Check for advanced tools
            advanced_tools = ['docker', 'kubernetes', 'terraform', 'ansible']
            for tool in advanced_tools:
                if shutil.which(tool):
                    profile_indicators[DeveloperProfile.EXPERT] += 1
            
            # Check for security tools
            security_tools = ['nmap', 'burp', 'metasploit', 'wireshark']
            for tool in security_tools:
                if shutil.which(tool):
                    profile_indicators[DeveloperProfile.SECURITY_FOCUSED] += 2
            
            # Check development environment
            if os.path.exists(Path.home() / ".vimrc") or os.path.exists(Path.home() / ".config/nvim"):
                profile_indicators[DeveloperProfile.EXPERT] += 1
            
            # Check for multiple IDEs
            ides_found = 0
            ide_commands = ['code', 'idea', 'webstorm', 'pycharm']
            for ide in ide_commands:
                if shutil.which(ide):
                    ides_found += 1
            
            if ides_found >= 2:
                profile_indicators[DeveloperProfile.EXPERT] += 1
            elif ides_found == 1:
                profile_indicators[DeveloperProfile.INTERMEDIATE] += 1
            
            # Default scoring
            profile_indicators[DeveloperProfile.INTERMEDIATE] += 1  # Base score
            
            # Return profile with highest score
            detected_profile = max(profile_indicators, key=profile_indicators.get)
            
            logger.info(f"Auto-detected developer profile: {detected_profile.value}")
            return detected_profile
            
        except Exception as e:
            logger.error(f"Profile detection failed: {str(e)}")
            return DeveloperProfile.INTERMEDIATE
    
    async def _personalize_cli(self):
        """Personalize CLI experience based on developer profile."""
        
        if not self.cli:
            return
        
        # Adjust CLI configuration based on profile
        if self.developer_profile == DeveloperProfile.BEGINNER:
            self.cli.config.show_tips = True
            self.cli.config.show_animations = True
            self.cli.config.enable_suggestions = True
        elif self.developer_profile == DeveloperProfile.EXPERT:
            self.cli.config.show_tips = False
            self.cli.config.show_animations = False
            self.cli.config.preferred_format = "json"
        elif self.developer_profile == DeveloperProfile.SECURITY_FOCUSED:
            self.cli.config.show_tips = True
            self.cli.config.preferred_format = "sarif"
        
        # Apply personalized theme
        preferred_theme = self.preferences.get('cli_theme')
        if preferred_theme:
            self.cli.config.theme = preferred_theme
    
    async def _show_personalized_welcome(self):
        """Show personalized welcome message."""
        
        if not self.cli:
            return
        
        welcome_messages = {
            DeveloperProfile.BEGINNER: "Welcome! Let's learn security together 🎓",
            DeveloperProfile.INTERMEDIATE: "Ready to enhance your app's security? 🛡️",
            DeveloperProfile.EXPERT: "Advanced security analysis at your service ⚡",
            DeveloperProfile.SECURITY_FOCUSED: "Time for deep security analysis 🔍"
        }
        
        message = welcome_messages.get(self.developer_profile, "Welcome to NjordScan!")
        self.cli.console.print(f"[bold green]{message}[/bold green]")
    
    async def _get_contextual_assistance(self) -> List[str]:
        """Get contextual assistance based on current state."""
        
        assistance = []
        
        if self.developer_profile == DeveloperProfile.BEGINNER:
            assistance.extend([
                "💡 Start with 'njordscan setup' to configure your environment",
                "📚 Use 'njordscan help' to learn about available features",
                "🎯 Try a quick scan with 'njordscan --mode quick'"
            ])
        
        if self.current_workflow_stage == WorkflowStage.SETUP:
            assistance.extend([
                "🚀 Create a new secure project with templates",
                "⚙️ Configure your IDE integration",
                "📋 Set up your preferred scanning options"
            ])
        
        return assistance
    
    def _get_available_tools(self) -> List[Dict[str, Any]]:
        """Get list of available tools."""
        
        tools = []
        
        if self.cli:
            tools.append({
                'name': 'Interactive CLI',
                'description': 'Rich command-line interface with guided workflows',
                'available': True
            })
        
        if self.ide_integration:
            tools.append({
                'name': 'IDE Integration',
                'description': 'Real-time security analysis in your editor',
                'available': True,
                'language_server': self.ide_integration.language_server is not None
            })
        
        if self.dev_tools:
            tools.append({
                'name': 'Development Tools',
                'description': 'Project templates and code generators',
                'available': True
            })
        
        return tools
    
    async def _get_session_recommendations(self) -> List[str]:
        """Get recommendations for current session."""
        
        recommendations = []
        
        # Based on developer profile
        if self.developer_profile == DeveloperProfile.BEGINNER:
            recommendations.extend([
                "Start with the interactive setup wizard",
                "Use the built-in help system extensively",
                "Enable all security features for learning"
            ])
        
        # Based on workflow stage
        if self.current_workflow_stage == WorkflowStage.DEVELOPMENT:
            recommendations.extend([
                "Enable real-time IDE analysis",
                "Use automated fix suggestions",
                "Run frequent security scans"
            ])
        
        return recommendations
    
    async def _select_optimal_template(self, project_type: str, profile: DeveloperProfile) -> str:
        """Select optimal project template based on type and profile."""
        
        # Map project types to template IDs
        template_mapping = {
            'nextjs': 'nextjs-secure-starter',
            'react': 'react-secure-starter',
            'vite': 'vite-secure-starter'
        }
        
        base_template = template_mapping.get(project_type, 'nextjs-secure-starter')
        
        # Adjust based on developer profile
        if profile == DeveloperProfile.BEGINNER:
            return f"{base_template}-beginner"
        elif profile == DeveloperProfile.SECURITY_FOCUSED:
            return f"{base_template}-security"
        
        return base_template
    
    def _get_security_level_for_profile(self) -> str:
        """Get appropriate security level for developer profile."""
        
        security_levels = {
            DeveloperProfile.BEGINNER: "standard",
            DeveloperProfile.INTERMEDIATE: "advanced",
            DeveloperProfile.EXPERT: "advanced",
            DeveloperProfile.SECURITY_FOCUSED: "enterprise"
        }
        
        return security_levels.get(self.developer_profile, "standard")
    
    async def _calculate_experience_quality(self) -> ExperienceLevel:
        """Calculate overall experience quality."""
        
        # Factor in multiple metrics
        satisfaction = self.developer_metrics.developer_satisfaction
        success_rate = self.developer_metrics.fix_success_rate
        error_rate = self.developer_metrics.error_rate
        
        # Calculate composite score
        score = (satisfaction / 5.0) * 0.4 + success_rate * 0.4 + (1 - error_rate) * 0.2
        
        if score >= 0.9:
            return ExperienceLevel.OUTSTANDING
        elif score >= 0.8:
            return ExperienceLevel.EXCELLENT
        elif score >= 0.7:
            return ExperienceLevel.GOOD
        elif score >= 0.5:
            return ExperienceLevel.BASIC
        else:
            return ExperienceLevel.POOR
    
    # Background workers
    
    async def _experience_monitoring_worker(self):
        """Background worker for monitoring developer experience."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(60)  # Monitor every minute
                
                # Update metrics
                await self._update_experience_metrics()
                
                # Check for experience issues
                experience_quality = await self._calculate_experience_quality()
                
                if experience_quality in [ExperienceLevel.POOR, ExperienceLevel.BASIC]:
                    await self._trigger_experience_improvements()
                
            except Exception as e:
                logger.error(f"Experience monitoring worker error: {str(e)}")
    
    async def _workflow_optimization_worker(self):
        """Background worker for workflow optimization."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(1800)  # Run every 30 minutes
                
                # Analyze workflow patterns
                if len(self.active_sessions) > 0:
                    workflow_data = {
                        'sessions': list(self.active_sessions.values()),
                        'metrics': self.developer_metrics,
                        'profile': self.developer_profile.value
                    }
                    
                    await self.optimize_developer_workflow(workflow_data)
                
            except Exception as e:
                logger.error(f"Workflow optimization worker error: {str(e)}")
    
    async def _learning_assistance_worker(self):
        """Background worker for learning assistance."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(3600)  # Run every hour
                
                # Provide proactive learning assistance
                if self.developer_profile == DeveloperProfile.BEGINNER:
                    await self._provide_proactive_tips()
                
            except Exception as e:
                logger.error(f"Learning assistance worker error: {str(e)}")
    
    async def _feedback_collection_worker(self):
        """Background worker for feedback collection."""
        
        interaction_count = 0
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(300)  # Check every 5 minutes
                
                current_interactions = (
                    self.developer_metrics.cli_interactions +
                    self.developer_metrics.scans_performed
                )
                
                # Prompt for feedback based on interaction frequency
                if (current_interactions > interaction_count and
                    current_interactions % self.config.feedback_prompt_frequency == 0):
                    
                    await self._prompt_for_feedback()
                    interaction_count = current_interactions
                
            except Exception as e:
                logger.error(f"Feedback collection worker error: {str(e)}")
    
    async def shutdown(self):
        """Shutdown developer experience orchestrator."""
        
        logger.info("Shutting down Developer Experience Orchestrator")
        
        self.running = False
        self.shutdown_event.set()
        
        # Save developer preferences
        await self._save_developer_preferences()
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        # Shutdown components
        if self.ide_integration:
            await self.ide_integration.shutdown()
        
        await self.workflow_optimizer.shutdown()
        await self.experience_analyzer.shutdown()
        await self.learning_assistant.shutdown()
        
        logger.info("Developer Experience Orchestrator shutdown completed")
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive DX statistics."""
        
        return {
            'developer_profile': self.developer_profile.value,
            'workflow_stage': self.current_workflow_stage.value,
            'experience_quality': (await self._calculate_experience_quality()).value,
            'metrics': {
                'projects_created': self.developer_metrics.projects_created,
                'scans_performed': self.developer_metrics.scans_performed,
                'issues_fixed': self.developer_metrics.issues_fixed,
                'time_saved_hours': self.developer_metrics.time_saved_minutes / 60,
                'satisfaction_score': self.developer_metrics.developer_satisfaction,
                'cli_interactions': self.developer_metrics.cli_interactions,
                'help_accessed': self.developer_metrics.help_accessed
            },
            'tools': {
                'cli_available': self.cli is not None,
                'ide_integration_available': self.ide_integration is not None,
                'dev_tools_available': self.dev_tools is not None
            },
            'sessions': {
                'active': len(self.active_sessions),
                'total_feedback': len(self.feedback_history)
            },
            'uptime': time.time() - self.start_time
        }


# Helper classes (stubs - would be implemented based on specific requirements)

class WorkflowOptimizer:
    """Workflow optimization engine."""
    
    def __init__(self, config: DXOrchestratorConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def start_session(self, session_context: Dict[str, Any]):
        pass
    
    async def track_action(self, action: str, data: Dict[str, Any]):
        pass
    
    async def generate_optimizations(self, analysis: Dict[str, Any], 
                                   profile: DeveloperProfile) -> Dict[str, Any]:
        return {'automatic': [], 'manual': []}
    
    async def get_opportunities(self) -> List[Dict[str, Any]]:
        return []
    
    async def shutdown(self):
        pass


class ExperienceAnalyzer:
    """Developer experience analyzer."""
    
    def __init__(self, config: DXOrchestratorConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def analyze_workflow(self, workflow_data: Dict[str, Any]) -> Dict[str, Any]:
        return {}
    
    async def shutdown(self):
        pass


class LearningAssistant:
    """Learning assistance engine."""
    
    def __init__(self, config: DXOrchestratorConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def provide_assistance(self, topic: str, context: Dict[str, Any]) -> Dict[str, Any]:
        return {'assistance': f'Help for {topic}'}
    
    async def get_recommendations(self, profile: DeveloperProfile, 
                                progress: Dict[str, Any]) -> List[str]:
        return []
    
    async def count_available_tips(self) -> int:
        return 0
    
    async def shutdown(self):
        pass
