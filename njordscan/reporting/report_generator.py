"""
Advanced Report Generator

Comprehensive report generation system supporting multiple formats and audiences:
- Executive summaries with business impact analysis
- Technical reports with detailed findings
- Compliance reports for regulatory frameworks
- Multi-format output (HTML, PDF, JSON, SARIF, CSV, XML)
- Interactive and static visualizations
"""

import json
import time
import base64
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging
import jinja2
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class ReportFormat(Enum):
    """Supported report formats."""
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    SARIF = "sarif"
    CSV = "csv"
    XML = "xml"
    MARKDOWN = "markdown"
    DOCX = "docx"
    XLSX = "xlsx"

class ReportAudience(Enum):
    """Target audiences for reports."""
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    DEVELOPER = "developer"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    AUDITOR = "auditor"

class ReportPriority(Enum):
    """Report generation priority."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"

@dataclass
class ReportSection:
    """Individual report section."""
    id: str
    title: str
    content: Any
    section_type: str  # summary, findings, charts, recommendations, etc.
    
    # Display options
    include_in_toc: bool = True
    page_break_before: bool = False
    page_break_after: bool = False
    
    # Conditional inclusion
    include_for_audiences: List[ReportAudience] = field(default_factory=list)
    exclude_for_audiences: List[ReportAudience] = field(default_factory=list)
    
    # Metadata
    order: int = 100
    template: Optional[str] = None

@dataclass
class ReportConfiguration:
    """Configuration for report generation."""
    
    # Basic settings
    title: str
    subtitle: str = ""
    audience: ReportAudience = ReportAudience.TECHNICAL
    formats: List[ReportFormat] = field(default_factory=lambda: [ReportFormat.HTML])
    
    # Content settings
    include_executive_summary: bool = True
    include_technical_details: bool = True
    include_recommendations: bool = True
    include_charts: bool = True
    include_raw_data: bool = False
    
    # Filtering and scope
    severity_filter: List[str] = field(default_factory=list)  # Empty = all severities
    category_filter: List[str] = field(default_factory=list)  # Empty = all categories
    max_findings: Optional[int] = None
    
    # Styling and branding
    theme: str = "professional"
    logo_path: Optional[str] = None
    company_name: str = "NjordScan Security Analysis"
    color_scheme: Dict[str, str] = field(default_factory=dict)
    
    # Output settings
    output_directory: Path = Path("reports")
    filename_template: str = "njordscan_report_{timestamp}"
    
    # Advanced options
    include_remediation_timeline: bool = True
    include_risk_matrix: bool = True
    include_trend_analysis: bool = True
    include_compliance_mapping: bool = True
    
    # Privacy and redaction
    redact_sensitive_data: bool = False
    redact_file_paths: bool = False
    redact_urls: bool = False

@dataclass
class ReportData:
    """Comprehensive data for report generation."""
    
    # Metadata
    scan_id: str
    project_name: str
    scan_timestamp: float
    scan_duration: float
    njordscan_version: str
    
    # Summary statistics
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    
    # Detailed findings
    findings: List[Dict[str, Any]] = field(default_factory=list)
    
    # Analysis results
    static_analysis_results: Optional[Dict[str, Any]] = None
    dependency_analysis_results: Optional[Dict[str, Any]] = None
    configuration_analysis_results: Optional[Dict[str, Any]] = None
    runtime_analysis_results: Optional[Dict[str, Any]] = None
    
    # Risk assessment
    overall_risk_score: float = 0.0
    risk_level: str = "unknown"
    business_impact_score: float = 0.0
    
    # Compliance
    compliance_results: Dict[str, Any] = field(default_factory=dict)
    
    # Trends and history
    historical_data: List[Dict[str, Any]] = field(default_factory=list)
    trend_analysis: Dict[str, Any] = field(default_factory=dict)
    
    # Recommendations
    immediate_actions: List[str] = field(default_factory=list)
    short_term_recommendations: List[str] = field(default_factory=list)
    long_term_recommendations: List[str] = field(default_factory=list)
    
    # Additional context
    project_metadata: Dict[str, Any] = field(default_factory=dict)
    environment_info: Dict[str, Any] = field(default_factory=dict)
    custom_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class GeneratedReport:
    """Generated report information."""
    report_id: str
    configuration: ReportConfiguration
    data: ReportData
    
    # Generated files
    generated_files: Dict[ReportFormat, Path] = field(default_factory=dict)
    
    # Generation metadata
    generation_time: float = 0.0
    generation_duration: float = 0.0
    total_pages: int = 0
    file_sizes: Dict[ReportFormat, int] = field(default_factory=dict)
    
    # Quality metrics
    completeness_score: float = 0.0
    generation_success: bool = True
    generation_errors: List[str] = field(default_factory=list)

class ReportGenerator:
    """Advanced multi-format report generator."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Generator configuration
        self.generator_config = {
            'template_directory': self.config.get('template_directory', 'templates/reports'),
            'static_assets_directory': self.config.get('static_assets_directory', 'static'),
            'max_concurrent_generations': self.config.get('max_concurrent_generations', 3),
            'enable_pdf_generation': self.config.get('enable_pdf_generation', True),
            'enable_charts': self.config.get('enable_charts', True),
            'chart_engine': self.config.get('chart_engine', 'plotly'),
            'pdf_engine': self.config.get('pdf_engine', 'weasyprint'),
            'cache_templates': self.config.get('cache_templates', True)
        }
        
        # Initialize template engine
        self.template_loader = jinja2.FileSystemLoader(self.generator_config['template_directory'])
        self.jinja_env = jinja2.Environment(
            loader=self.template_loader,
            autoescape=jinja2.select_autoescape(['html', 'xml']),
            cache_size=100 if self.generator_config['cache_templates'] else 0
        )
        
        # Register custom filters and functions
        self._register_template_helpers()
        
        # Report templates by audience
        self.templates = {
            ReportAudience.EXECUTIVE: 'executive_report.html',
            ReportAudience.TECHNICAL: 'technical_report.html',
            ReportAudience.DEVELOPER: 'developer_report.html',
            ReportAudience.SECURITY: 'security_report.html',
            ReportAudience.COMPLIANCE: 'compliance_report.html',
            ReportAudience.AUDITOR: 'audit_report.html'
        }
        
        # Statistics
        self.stats = {
            'reports_generated': 0,
            'total_generation_time': 0.0,
            'formats_generated': {},
            'audiences_served': {},
            'generation_failures': 0
        }
    
    async def generate_report(self, data: ReportData, config: ReportConfiguration) -> GeneratedReport:
        """Generate comprehensive report in specified formats."""
        
        generation_start_time = time.time()
        report_id = f"report_{data.scan_id}_{int(generation_start_time)}"
        
        logger.info(f"Generating report: {report_id} for audience: {config.audience.value}")
        logger.info(f"Formats: {[f.value for f in config.formats]}")
        
        try:
            # Create output directory
            config.output_directory.mkdir(parents=True, exist_ok=True)
            
            # Initialize report
            report = GeneratedReport(
                report_id=report_id,
                configuration=config,
                data=data,
                generation_time=generation_start_time
            )
            
            # Process and enrich data
            enriched_data = await self._enrich_report_data(data, config)
            
            # Generate report sections
            sections = await self._generate_report_sections(enriched_data, config)
            
            # Generate reports in each requested format
            for report_format in config.formats:
                try:
                    output_file = await self._generate_format(
                        report_format, sections, enriched_data, config, report_id
                    )
                    
                    if output_file:
                        report.generated_files[report_format] = output_file
                        report.file_sizes[report_format] = output_file.stat().st_size
                        
                        logger.info(f"Generated {report_format.value} report: {output_file}")
                        
                        # Update statistics
                        if report_format.value not in self.stats['formats_generated']:
                            self.stats['formats_generated'][report_format.value] = 0
                        self.stats['formats_generated'][report_format.value] += 1
                        
                except Exception as e:
                    error_msg = f"Failed to generate {report_format.value} format: {str(e)}"
                    logger.error(error_msg)
                    report.generation_errors.append(error_msg)
            
            # Finalize report
            report.generation_duration = time.time() - generation_start_time
            report.generation_success = len(report.generated_files) > 0
            report.completeness_score = self._calculate_completeness_score(report, config)
            
            # Update statistics
            self._update_statistics(report)
            
            if report.generation_success:
                logger.info(f"Report generation completed: {report_id} "
                           f"({len(report.generated_files)} formats, "
                           f"{report.generation_duration:.2f}s)")
            else:
                logger.error(f"Report generation failed: {report_id}")
                self.stats['generation_failures'] += 1
            
            return report
            
        except Exception as e:
            logger.error(f"Report generation failed: {report_id} - {str(e)}")
            
            # Return failed report
            return GeneratedReport(
                report_id=report_id,
                configuration=config,
                data=data,
                generation_time=generation_start_time,
                generation_duration=time.time() - generation_start_time,
                generation_success=False,
                generation_errors=[str(e)]
            )
    
    async def _enrich_report_data(self, data: ReportData, config: ReportConfiguration) -> Dict[str, Any]:
        """Enrich report data with additional context and calculations."""
        
        enriched = {
            # Original data
            'scan_data': data,
            'config': config,
            
            # Timestamps and formatting
            'scan_date': datetime.fromtimestamp(data.scan_timestamp, tz=timezone.utc),
            'generation_date': datetime.now(tz=timezone.utc),
            'scan_duration_formatted': self._format_duration(data.scan_duration),
            
            # Summary calculations
            'total_issues': data.total_findings,
            'critical_high_count': data.critical_findings + data.high_findings,
            'severity_distribution': {
                'critical': data.critical_findings,
                'high': data.high_findings,
                'medium': data.medium_findings,
                'low': data.low_findings,
                'info': data.info_findings
            },
            
            # Risk assessment
            'risk_level_color': self._get_risk_color(data.risk_level),
            'risk_score_percentage': min(100, data.overall_risk_score),
            'business_impact_level': self._categorize_business_impact(data.business_impact_score),
            
            # Filtered findings
            'filtered_findings': self._filter_findings(data.findings, config),
            
            # Categorized findings
            'findings_by_category': self._group_findings_by_category(data.findings),
            'findings_by_severity': self._group_findings_by_severity(data.findings),
            'findings_by_file': self._group_findings_by_file(data.findings),
            
            # Top issues
            'top_critical_findings': self._get_top_findings(data.findings, 'critical', 10),
            'top_high_findings': self._get_top_findings(data.findings, 'high', 10),
            
            # Recommendations by priority
            'prioritized_recommendations': {
                'immediate': data.immediate_actions,
                'short_term': data.short_term_recommendations,
                'long_term': data.long_term_recommendations
            },
            
            # Compliance status
            'compliance_summary': self._summarize_compliance(data.compliance_results),
            
            # Trend insights
            'trend_insights': self._generate_trend_insights(data.trend_analysis),
            
            # Executive summary data
            'executive_summary': await self._generate_executive_summary(data, config)
        }
        
        return enriched
    
    async def _generate_report_sections(self, data: Dict[str, Any], 
                                       config: ReportConfiguration) -> List[ReportSection]:
        """Generate report sections based on configuration and audience."""
        
        sections = []
        
        # Executive Summary
        if config.include_executive_summary:
            sections.append(ReportSection(
                id="executive_summary",
                title="Executive Summary",
                content=data['executive_summary'],
                section_type="summary",
                order=10,
                include_for_audiences=[ReportAudience.EXECUTIVE, ReportAudience.SECURITY]
            ))
        
        # Risk Assessment
        sections.append(ReportSection(
            id="risk_assessment",
            title="Risk Assessment",
            content={
                'overall_risk_score': data['risk_score_percentage'],
                'risk_level': data['scan_data'].risk_level,
                'business_impact': data['business_impact_level'],
                'risk_factors': self._identify_risk_factors(data)
            },
            section_type="risk_analysis",
            order=20
        ))
        
        # Security Findings Overview
        sections.append(ReportSection(
            id="findings_overview",
            title="Security Findings Overview",
            content={
                'total_findings': data['total_issues'],
                'severity_distribution': data['severity_distribution'],
                'category_breakdown': data['findings_by_category'],
                'critical_high_summary': data['critical_high_count']
            },
            section_type="findings_overview",
            order=30
        ))
        
        # Detailed Findings
        if config.include_technical_details:
            sections.append(ReportSection(
                id="detailed_findings",
                title="Detailed Security Findings",
                content={
                    'findings': data['filtered_findings'],
                    'top_critical': data['top_critical_findings'],
                    'top_high': data['top_high_findings']
                },
                section_type="detailed_findings",
                order=40,
                exclude_for_audiences=[ReportAudience.EXECUTIVE]
            ))
        
        # Compliance Results
        if config.include_compliance_mapping and data['scan_data'].compliance_results:
            sections.append(ReportSection(
                id="compliance_results",
                title="Compliance Assessment",
                content={
                    'compliance_summary': data['compliance_summary'],
                    'detailed_results': data['scan_data'].compliance_results
                },
                section_type="compliance",
                order=50,
                include_for_audiences=[ReportAudience.COMPLIANCE, ReportAudience.AUDITOR, ReportAudience.EXECUTIVE]
            ))
        
        # Trend Analysis
        if config.include_trend_analysis and data['scan_data'].historical_data:
            sections.append(ReportSection(
                id="trend_analysis",
                title="Security Trend Analysis",
                content={
                    'trend_insights': data['trend_insights'],
                    'historical_data': data['scan_data'].historical_data
                },
                section_type="trends",
                order=60
            ))
        
        # Recommendations
        if config.include_recommendations:
            sections.append(ReportSection(
                id="recommendations",
                title="Security Recommendations",
                content={
                    'prioritized_recommendations': data['prioritized_recommendations'],
                    'remediation_timeline': self._generate_remediation_timeline(data) if config.include_remediation_timeline else None
                },
                section_type="recommendations",
                order=70
            ))
        
        # Technical Details (for technical audiences)
        if config.audience in [ReportAudience.TECHNICAL, ReportAudience.DEVELOPER, ReportAudience.SECURITY]:
            sections.append(ReportSection(
                id="technical_details",
                title="Technical Analysis Details",
                content={
                    'static_analysis': data['scan_data'].static_analysis_results,
                    'dependency_analysis': data['scan_data'].dependency_analysis_results,
                    'configuration_analysis': data['scan_data'].configuration_analysis_results,
                    'runtime_analysis': data['scan_data'].runtime_analysis_results
                },
                section_type="technical_details",
                order=80,
                exclude_for_audiences=[ReportAudience.EXECUTIVE]
            ))
        
        # Appendices
        if config.include_raw_data:
            sections.append(ReportSection(
                id="appendices",
                title="Appendices",
                content={
                    'raw_findings': data['scan_data'].findings,
                    'scan_metadata': {
                        'scan_id': data['scan_data'].scan_id,
                        'njordscan_version': data['scan_data'].njordscan_version,
                        'environment_info': data['scan_data'].environment_info
                    }
                },
                section_type="appendices",
                order=90,
                exclude_for_audiences=[ReportAudience.EXECUTIVE]
            ))
        
        # Filter sections based on audience
        filtered_sections = self._filter_sections_for_audience(sections, config.audience)
        
        # Sort by order
        filtered_sections.sort(key=lambda s: s.order)
        
        return filtered_sections
    
    async def _generate_format(self, format_type: ReportFormat, sections: List[ReportSection],
                              data: Dict[str, Any], config: ReportConfiguration, 
                              report_id: str) -> Optional[Path]:
        """Generate report in specific format."""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = config.filename_template.format(
            timestamp=timestamp,
            scan_id=data['scan_data'].scan_id,
            audience=config.audience.value,
            format=format_type.value
        )
        
        output_file = config.output_directory / f"{filename}.{format_type.value}"
        
        try:
            if format_type == ReportFormat.HTML:
                return await self._generate_html_report(sections, data, config, output_file)
            elif format_type == ReportFormat.PDF:
                return await self._generate_pdf_report(sections, data, config, output_file)
            elif format_type == ReportFormat.JSON:
                return await self._generate_json_report(sections, data, config, output_file)
            elif format_type == ReportFormat.SARIF:
                return await self._generate_sarif_report(sections, data, config, output_file)
            elif format_type == ReportFormat.CSV:
                return await self._generate_csv_report(sections, data, config, output_file)
            elif format_type == ReportFormat.MARKDOWN:
                return await self._generate_markdown_report(sections, data, config, output_file)
            else:
                logger.warning(f"Unsupported report format: {format_type.value}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to generate {format_type.value} report: {str(e)}")
            return None
    
    async def _generate_html_report(self, sections: List[ReportSection], data: Dict[str, Any],
                                   config: ReportConfiguration, output_file: Path) -> Path:
        """Generate HTML report."""
        
        # Get template for audience
        template_name = self.templates.get(config.audience, 'technical_report.html')
        
        try:
            template = self.jinja_env.get_template(template_name)
        except jinja2.TemplateNotFound:
            logger.warning(f"Template {template_name} not found, using default")
            template = self.jinja_env.from_string(self._get_default_html_template())
        
        # Prepare template context
        context = {
            'config': config,
            'data': data,
            'sections': sections,
            'generation_time': datetime.now(),
            'charts': await self._generate_charts(data, config) if config.include_charts else {},
            'theme_css': self._get_theme_css(config.theme),
            'custom_css': self._get_custom_css(config.color_scheme)
        }
        
        # Render template
        html_content = template.render(context)
        
        # Write to file
        output_file.write_text(html_content, encoding='utf-8')
        
        return output_file
    
    async def _generate_pdf_report(self, sections: List[ReportSection], data: Dict[str, Any],
                                  config: ReportConfiguration, output_file: Path) -> Path:
        """Generate PDF report."""
        
        if not self.generator_config['enable_pdf_generation']:
            logger.warning("PDF generation is disabled")
            return None
        
        # First generate HTML
        html_file = output_file.with_suffix('.html')
        await self._generate_html_report(sections, data, config, html_file)
        
        try:
            # Convert HTML to PDF using configured engine
            if self.generator_config['pdf_engine'] == 'weasyprint':
                await self._html_to_pdf_weasyprint(html_file, output_file)
            else:
                logger.error(f"Unsupported PDF engine: {self.generator_config['pdf_engine']}")
                return None
            
            # Clean up temporary HTML file
            html_file.unlink(missing_ok=True)
            
            return output_file
            
        except Exception as e:
            logger.error(f"PDF generation failed: {str(e)}")
            html_file.unlink(missing_ok=True)
            return None
    
    async def _generate_json_report(self, sections: List[ReportSection], data: Dict[str, Any],
                                   config: ReportConfiguration, output_file: Path) -> Path:
        """Generate JSON report."""
        
        # Create JSON structure
        json_data = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'njordscan_version': data['scan_data'].njordscan_version,
                'report_format': 'json',
                'audience': config.audience.value
            },
            'scan_summary': {
                'scan_id': data['scan_data'].scan_id,
                'project_name': data['scan_data'].project_name,
                'scan_timestamp': data['scan_data'].scan_timestamp,
                'scan_duration': data['scan_data'].scan_duration,
                'total_findings': data['scan_data'].total_findings,
                'severity_distribution': data['severity_distribution'],
                'risk_assessment': {
                    'overall_risk_score': data['scan_data'].overall_risk_score,
                    'risk_level': data['scan_data'].risk_level,
                    'business_impact_score': data['scan_data'].business_impact_score
                }
            },
            'findings': data['scan_data'].findings,
            'recommendations': data['prioritized_recommendations'],
            'compliance_results': data['scan_data'].compliance_results,
            'sections': [
                {
                    'id': section.id,
                    'title': section.title,
                    'type': section.section_type,
                    'content': section.content
                }
                for section in sections
            ]
        }
        
        # Write JSON file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False, default=str)
        
        return output_file
    
    async def _generate_sarif_report(self, sections: List[ReportSection], data: Dict[str, Any],
                                    config: ReportConfiguration, output_file: Path) -> Path:
        """Generate SARIF (Static Analysis Results Interchange Format) report."""
        
        # Create SARIF structure
        sarif_data = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "NjordScan",
                            "version": data['scan_data'].njordscan_version,
                            "informationUri": "https://github.com/njordscan/njordscan",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }
        
        # Convert findings to SARIF results
        for finding in data['scan_data'].findings:
            sarif_result = {
                "ruleId": finding.get('rule_id', 'unknown'),
                "message": {
                    "text": finding.get('description', 'Security finding detected')
                },
                "level": self._map_severity_to_sarif_level(finding.get('severity', 'medium')),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.get('file_path', 'unknown')
                            },
                            "region": {
                                "startLine": finding.get('line_number', 1),
                                "startColumn": finding.get('column_number', 1)
                            }
                        }
                    }
                ]
            }
            
            if 'code_snippet' in finding:
                sarif_result['locations'][0]['physicalLocation']['contextRegion'] = {
                    "snippet": {
                        "text": finding['code_snippet']
                    }
                }
            
            sarif_data["runs"][0]["results"].append(sarif_result)
        
        # Write SARIF file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(sarif_data, f, indent=2, ensure_ascii=False)
        
        return output_file
    
    async def _generate_csv_report(self, sections: List[ReportSection], data: Dict[str, Any],
                                  config: ReportConfiguration, output_file: Path) -> Path:
        """Generate CSV report."""
        
        import csv
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'finding_id', 'severity', 'category', 'title', 'description',
                'file_path', 'line_number', 'rule_id', 'confidence',
                'remediation', 'references'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for finding in data['scan_data'].findings:
                writer.writerow({
                    'finding_id': finding.get('id', ''),
                    'severity': finding.get('severity', ''),
                    'category': finding.get('category', ''),
                    'title': finding.get('title', ''),
                    'description': finding.get('description', ''),
                    'file_path': finding.get('file_path', ''),
                    'line_number': finding.get('line_number', ''),
                    'rule_id': finding.get('rule_id', ''),
                    'confidence': finding.get('confidence', ''),
                    'remediation': finding.get('remediation', ''),
                    'references': '; '.join(finding.get('references', []))
                })
        
        return output_file
    
    async def _generate_markdown_report(self, sections: List[ReportSection], data: Dict[str, Any],
                                       config: ReportConfiguration, output_file: Path) -> Path:
        """Generate Markdown report."""
        
        markdown_content = []
        
        # Title
        markdown_content.append(f"# {config.title}")
        if config.subtitle:
            markdown_content.append(f"## {config.subtitle}")
        
        markdown_content.append("")
        markdown_content.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        markdown_content.append(f"**Project:** {data['scan_data'].project_name}")
        markdown_content.append(f"**Scan ID:** {data['scan_data'].scan_id}")
        markdown_content.append("")
        
        # Sections
        for section in sections:
            markdown_content.append(f"## {section.title}")
            markdown_content.append("")
            
            if section.section_type == "summary":
                markdown_content.extend(self._format_summary_as_markdown(section.content))
            elif section.section_type == "findings_overview":
                markdown_content.extend(self._format_findings_overview_as_markdown(section.content))
            elif section.section_type == "detailed_findings":
                markdown_content.extend(self._format_detailed_findings_as_markdown(section.content))
            else:
                markdown_content.append(f"```json")
                markdown_content.append(json.dumps(section.content, indent=2, default=str))
                markdown_content.append(f"```")
            
            markdown_content.append("")
        
        # Write Markdown file
        output_file.write_text('\n'.join(markdown_content), encoding='utf-8')
        
        return output_file
    
    # Helper methods continue in next part due to length...
    
    def _register_template_helpers(self):
        """Register custom Jinja2 filters and functions."""
        
        @self.jinja_env.filter('severity_color')
        def severity_color(severity):
            colors = {
                'critical': '#dc3545',
                'high': '#fd7e14',
                'medium': '#ffc107',
                'low': '#28a745',
                'info': '#17a2b8'
            }
            return colors.get(severity.lower(), '#6c757d')
        
        @self.jinja_env.filter('format_duration')
        def format_duration(seconds):
            return self._format_duration(seconds)
        
        @self.jinja_env.filter('truncate_path')
        def truncate_path(path, max_length=50):
            if len(path) <= max_length:
                return path
            return '...' + path[-(max_length-3):]
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color for risk level."""
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745',
            'unknown': '#6c757d'
        }
        return colors.get(risk_level.lower(), '#6c757d')
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get generator statistics."""
        return dict(self.stats)
    
    def _get_default_html_template(self) -> str:
        """Get default HTML template if custom template is not found."""
        return '''
<!DOCTYPE html>
<html>
<head>
    <title>{{ config.title }}</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { border-bottom: 2px solid #333; padding-bottom: 20px; }
        .section { margin: 30px 0; }
        .finding { border: 1px solid #ddd; margin: 10px 0; padding: 15px; }
        .critical { border-left: 4px solid #dc3545; }
        .high { border-left: 4px solid #fd7e14; }
        .medium { border-left: 4px solid #ffc107; }
        .low { border-left: 4px solid #28a745; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ config.title }}</h1>
        <p>Generated: {{ generation_time.strftime('%Y-%m-%d %H:%M:%S') }}</p>
    </div>
    
    {% for section in sections %}
    <div class="section">
        <h2>{{ section.title }}</h2>
        <!-- Section content would be rendered here -->
    </div>
    {% endfor %}
</body>
</html>
        '''
