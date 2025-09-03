"""
Advanced Visualization Engine

Comprehensive visualization system for security data including:
- Interactive charts and graphs
- Security dashboards
- Risk matrices and heat maps
- Trend analysis visualizations
- Compliance status dashboards
- Real-time monitoring displays
"""

import json
import time
import base64
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class ChartType(Enum):
    """Types of charts and visualizations."""
    BAR_CHART = "bar_chart"
    LINE_CHART = "line_chart"
    PIE_CHART = "pie_chart"
    DONUT_CHART = "donut_chart"
    SCATTER_PLOT = "scatter_plot"
    HEATMAP = "heatmap"
    TREEMAP = "treemap"
    SUNBURST = "sunburst"
    GAUGE = "gauge"
    RADAR_CHART = "radar_chart"
    HISTOGRAM = "histogram"
    BOX_PLOT = "box_plot"
    VIOLIN_PLOT = "violin_plot"
    SANKEY_DIAGRAM = "sankey_diagram"
    NETWORK_GRAPH = "network_graph"
    TIMELINE = "timeline"
    GANTT_CHART = "gantt_chart"
    RISK_MATRIX = "risk_matrix"

class VisualizationTheme(Enum):
    """Visualization themes."""
    LIGHT = "light"
    DARK = "dark"
    SECURITY = "security"
    CORPORATE = "corporate"
    COLORBLIND_FRIENDLY = "colorblind_friendly"
    HIGH_CONTRAST = "high_contrast"

@dataclass
class ChartConfiguration:
    """Configuration for individual charts."""
    chart_id: str
    title: str
    chart_type: ChartType
    
    # Data configuration
    data_source: str
    x_axis: str = ""
    y_axis: str = ""
    color_field: str = ""
    size_field: str = ""
    
    # Display options
    width: int = 800
    height: int = 400
    theme: VisualizationTheme = VisualizationTheme.LIGHT
    interactive: bool = True
    
    # Styling
    colors: List[str] = field(default_factory=list)
    title_font_size: int = 16
    axis_font_size: int = 12
    show_legend: bool = True
    legend_position: str = "right"
    
    # Animation and interaction
    animate: bool = True
    animation_duration: int = 750
    enable_zoom: bool = True
    enable_pan: bool = True
    enable_crossfilter: bool = False
    
    # Export options
    enable_export: bool = True
    export_formats: List[str] = field(default_factory=lambda: ["png", "svg", "pdf"])

@dataclass
class DashboardConfiguration:
    """Configuration for dashboards."""
    dashboard_id: str
    title: str
    description: str = ""
    
    # Layout
    layout: str = "grid"  # grid, flex, masonry
    columns: int = 12
    responsive: bool = True
    
    # Charts and widgets
    charts: List[ChartConfiguration] = field(default_factory=list)
    
    # Filtering and interaction
    enable_global_filters: bool = True
    enable_cross_filtering: bool = True
    auto_refresh: bool = False
    refresh_interval: int = 30  # seconds
    
    # Styling
    theme: VisualizationTheme = VisualizationTheme.LIGHT
    custom_css: str = ""
    
    # Export and sharing
    enable_export: bool = True
    enable_sharing: bool = True
    public_access: bool = False

@dataclass
class VisualizationData:
    """Data for visualizations."""
    data_id: str
    name: str
    data: List[Dict[str, Any]]
    
    # Metadata
    columns: List[str] = field(default_factory=list)
    data_types: Dict[str, str] = field(default_factory=dict)
    row_count: int = 0
    
    # Processing info
    last_updated: float = 0.0
    processing_duration: float = 0.0
    
    def __post_init__(self):
        if self.data:
            self.row_count = len(self.data)
            if not self.columns and self.data:
                self.columns = list(self.data[0].keys())

@dataclass
class GeneratedVisualization:
    """Generated visualization information."""
    visualization_id: str
    chart_type: ChartType
    config: ChartConfiguration
    
    # Generated content
    html_content: str = ""
    javascript_code: str = ""
    css_styles: str = ""
    
    # Metadata
    generation_time: float = 0.0
    generation_duration: float = 0.0
    data_points: int = 0
    
    # Export options
    export_urls: Dict[str, str] = field(default_factory=dict)
    
    # Performance metrics
    render_time: float = 0.0
    memory_usage: float = 0.0

class VisualizationEngine:
    """Advanced visualization engine for security data."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Engine configuration
        self.engine_config = {
            'default_theme': self.config.get('default_theme', 'light'),
            'enable_animations': self.config.get('enable_animations', True),
            'chart_library': self.config.get('chart_library', 'plotly'),  # plotly, d3, chartjs
            'max_data_points': self.config.get('max_data_points', 10000),
            'enable_caching': self.config.get('enable_caching', True),
            'cache_duration': self.config.get('cache_duration', 3600),
            'export_quality': self.config.get('export_quality', 'high')
        }
        
        # Color schemes
        self.color_schemes = {
            VisualizationTheme.LIGHT: {
                'primary': '#007bff',
                'secondary': '#6c757d',
                'success': '#28a745',
                'warning': '#ffc107',
                'danger': '#dc3545',
                'info': '#17a2b8',
                'background': '#ffffff',
                'text': '#212529'
            },
            VisualizationTheme.DARK: {
                'primary': '#0d6efd',
                'secondary': '#6c757d',
                'success': '#198754',
                'warning': '#fd7e14',
                'danger': '#dc3545',
                'info': '#0dcaf0',
                'background': '#212529',
                'text': '#ffffff'
            },
            VisualizationTheme.SECURITY: {
                'critical': '#dc3545',
                'high': '#fd7e14',
                'medium': '#ffc107',
                'low': '#28a745',
                'info': '#17a2b8',
                'background': '#f8f9fa',
                'text': '#212529'
            }
        }
        
        # Chart templates
        self.chart_templates = self._initialize_chart_templates()
        
        # Data cache
        self.data_cache: Dict[str, VisualizationData] = {}
        self.chart_cache: Dict[str, GeneratedVisualization] = {}
        
        # Statistics
        self.stats = {
            'charts_generated': 0,
            'dashboards_created': 0,
            'data_points_processed': 0,
            'total_generation_time': 0.0,
            'cache_hits': 0,
            'cache_misses': 0
        }
    
    async def create_security_overview_dashboard(self, scan_data: Dict[str, Any]) -> DashboardConfiguration:
        """Create comprehensive security overview dashboard."""
        
        logger.info("Creating security overview dashboard")
        
        # Prepare visualization data
        findings_data = self._prepare_findings_data(scan_data)
        severity_data = self._prepare_severity_data(scan_data)
        category_data = self._prepare_category_data(scan_data)
        trend_data = self._prepare_trend_data(scan_data)
        
        # Create charts
        charts = []
        
        # Severity Distribution Pie Chart
        charts.append(ChartConfiguration(
            chart_id="severity_distribution",
            title="Findings by Severity",
            chart_type=ChartType.DONUT_CHART,
            data_source="severity_data",
            width=400,
            height=300,
            colors=self._get_severity_colors(),
            theme=VisualizationTheme.SECURITY
        ))
        
        # Category Breakdown Bar Chart
        charts.append(ChartConfiguration(
            chart_id="category_breakdown",
            title="Findings by Category",
            chart_type=ChartType.BAR_CHART,
            data_source="category_data",
            x_axis="category",
            y_axis="count",
            width=600,
            height=400
        ))
        
        # Risk Score Gauge
        charts.append(ChartConfiguration(
            chart_id="risk_score",
            title="Overall Risk Score",
            chart_type=ChartType.GAUGE,
            data_source="risk_data",
            width=300,
            height=300
        ))
        
        # Trend Analysis Line Chart
        if trend_data:
            charts.append(ChartConfiguration(
                chart_id="security_trends",
                title="Security Trends Over Time",
                chart_type=ChartType.LINE_CHART,
                data_source="trend_data",
                x_axis="date",
                y_axis="findings_count",
                color_field="severity",
                width=800,
                height=400
            ))
        
        # File Risk Heatmap
        charts.append(ChartConfiguration(
            chart_id="file_risk_heatmap",
            title="File Risk Analysis",
            chart_type=ChartType.HEATMAP,
            data_source="file_data",
            width=800,
            height=500
        ))
        
        # Top Vulnerable Files
        charts.append(ChartConfiguration(
            chart_id="top_vulnerable_files",
            title="Top 10 Most Vulnerable Files",
            chart_type=ChartType.BAR_CHART,
            data_source="file_summary_data",
            x_axis="file",
            y_axis="vulnerability_count",
            width=600,
            height=400
        ))
        
        # Create dashboard
        dashboard = DashboardConfiguration(
            dashboard_id=f"security_overview_{int(time.time())}",
            title="Security Overview Dashboard",
            description="Comprehensive overview of security findings and risk assessment",
            charts=charts,
            layout="grid",
            columns=12,
            theme=VisualizationTheme.SECURITY,
            enable_global_filters=True,
            enable_cross_filtering=True
        )
        
        return dashboard
    
    async def create_compliance_dashboard(self, compliance_data: Dict[str, Any]) -> DashboardConfiguration:
        """Create compliance status dashboard."""
        
        logger.info("Creating compliance dashboard")
        
        charts = []
        
        # Compliance Status Overview
        charts.append(ChartConfiguration(
            chart_id="compliance_status",
            title="Compliance Framework Status",
            chart_type=ChartType.BAR_CHART,
            data_source="compliance_status_data",
            x_axis="framework",
            y_axis="compliance_score",
            width=600,
            height=400,
            colors=["#28a745", "#ffc107", "#dc3545"]  # Green, Yellow, Red
        ))
        
        # Control Implementation Status
        charts.append(ChartConfiguration(
            chart_id="control_status",
            title="Security Control Implementation",
            chart_type=ChartType.SUNBURST,
            data_source="control_data",
            width=500,
            height=500
        ))
        
        # Compliance Trend
        charts.append(ChartConfiguration(
            chart_id="compliance_trend",
            title="Compliance Score Trend",
            chart_type=ChartType.LINE_CHART,
            data_source="compliance_trend_data",
            x_axis="date",
            y_axis="score",
            color_field="framework",
            width=800,
            height=400
        ))
        
        # Risk vs Compliance Matrix
        charts.append(ChartConfiguration(
            chart_id="risk_compliance_matrix",
            title="Risk vs Compliance Matrix",
            chart_type=ChartType.SCATTER_PLOT,
            data_source="risk_compliance_data",
            x_axis="compliance_score",
            y_axis="risk_score",
            size_field="impact",
            width=600,
            height=500
        ))
        
        dashboard = DashboardConfiguration(
            dashboard_id=f"compliance_dashboard_{int(time.time())}",
            title="Compliance Dashboard",
            description="Regulatory compliance status and control implementation tracking",
            charts=charts,
            theme=VisualizationTheme.CORPORATE
        )
        
        return dashboard
    
    async def generate_chart(self, config: ChartConfiguration, data: VisualizationData) -> GeneratedVisualization:
        """Generate individual chart visualization."""
        
        generation_start_time = time.time()
        chart_id = f"{config.chart_id}_{int(generation_start_time)}"
        
        logger.debug(f"Generating chart: {chart_id} ({config.chart_type.value})")
        
        try:
            # Check cache
            cache_key = self._generate_chart_cache_key(config, data)
            if self.engine_config['enable_caching'] and cache_key in self.chart_cache:
                cached_chart = self.chart_cache[cache_key]
                self.stats['cache_hits'] += 1
                logger.debug(f"Returning cached chart: {chart_id}")
                return cached_chart
            
            self.stats['cache_misses'] += 1
            
            # Generate chart based on library
            if self.engine_config['chart_library'] == 'plotly':
                visualization = await self._generate_plotly_chart(config, data, chart_id)
            elif self.engine_config['chart_library'] == 'd3':
                visualization = await self._generate_d3_chart(config, data, chart_id)
            elif self.engine_config['chart_library'] == 'chartjs':
                visualization = await self._generate_chartjs_chart(config, data, chart_id)
            else:
                raise ValueError(f"Unsupported chart library: {self.engine_config['chart_library']}")
            
            # Finalize visualization
            visualization.generation_duration = time.time() - generation_start_time
            visualization.data_points = len(data.data)
            
            # Cache result
            if self.engine_config['enable_caching']:
                self.chart_cache[cache_key] = visualization
            
            # Update statistics
            self.stats['charts_generated'] += 1
            self.stats['data_points_processed'] += len(data.data)
            self.stats['total_generation_time'] += visualization.generation_duration
            
            logger.debug(f"Chart generated: {chart_id} ({visualization.generation_duration:.2f}s)")
            
            return visualization
            
        except Exception as e:
            logger.error(f"Failed to generate chart {chart_id}: {str(e)}")
            raise
    
    async def generate_dashboard(self, config: DashboardConfiguration, 
                               data_sources: Dict[str, VisualizationData]) -> str:
        """Generate complete dashboard HTML."""
        
        logger.info(f"Generating dashboard: {config.dashboard_id}")
        
        try:
            # Generate all charts
            chart_visualizations = {}
            for chart_config in config.charts:
                if chart_config.data_source in data_sources:
                    data = data_sources[chart_config.data_source]
                    visualization = await self.generate_chart(chart_config, data)
                    chart_visualizations[chart_config.chart_id] = visualization
            
            # Create dashboard HTML
            dashboard_html = await self._generate_dashboard_html(config, chart_visualizations)
            
            self.stats['dashboards_created'] += 1
            
            return dashboard_html
            
        except Exception as e:
            logger.error(f"Failed to generate dashboard {config.dashboard_id}: {str(e)}")
            raise
    
    async def _generate_plotly_chart(self, config: ChartConfiguration, 
                                    data: VisualizationData, chart_id: str) -> GeneratedVisualization:
        """Generate chart using Plotly library."""
        
        # Get color scheme
        colors = self.color_schemes.get(config.theme, self.color_schemes[VisualizationTheme.LIGHT])
        
        # Prepare chart data and layout
        chart_data = []
        layout = {
            'title': {
                'text': config.title,
                'font': {'size': config.title_font_size}
            },
            'width': config.width,
            'height': config.height,
            'showlegend': config.show_legend,
            'paper_bgcolor': colors['background'],
            'plot_bgcolor': colors['background'],
            'font': {'color': colors['text']}
        }
        
        # Generate chart based on type
        if config.chart_type == ChartType.BAR_CHART:
            chart_data = self._create_plotly_bar_chart(data, config, colors)
        elif config.chart_type == ChartType.PIE_CHART:
            chart_data = self._create_plotly_pie_chart(data, config, colors)
        elif config.chart_type == ChartType.DONUT_CHART:
            chart_data = self._create_plotly_donut_chart(data, config, colors)
        elif config.chart_type == ChartType.LINE_CHART:
            chart_data = self._create_plotly_line_chart(data, config, colors)
        elif config.chart_type == ChartType.SCATTER_PLOT:
            chart_data = self._create_plotly_scatter_plot(data, config, colors)
        elif config.chart_type == ChartType.HEATMAP:
            chart_data = self._create_plotly_heatmap(data, config, colors)
        elif config.chart_type == ChartType.GAUGE:
            chart_data = self._create_plotly_gauge(data, config, colors)
        else:
            raise ValueError(f"Unsupported chart type for Plotly: {config.chart_type.value}")
        
        # Generate JavaScript code
        javascript_code = f'''
        var data_{chart_id} = {json.dumps(chart_data)};
        var layout_{chart_id} = {json.dumps(layout)};
        var config_{chart_id} = {{
            responsive: true,
            displayModeBar: {str(config.enable_export).lower()},
            modeBarButtonsToRemove: ['pan2d', 'lasso2d'],
            toImageButtonOptions: {{
                format: 'png',
                filename: '{chart_id}',
                height: {config.height},
                width: {config.width},
                scale: 2
            }}
        }};
        
        Plotly.newPlot('{chart_id}', data_{chart_id}, layout_{chart_id}, config_{chart_id});
        '''
        
        # Generate HTML container
        html_content = f'''
        <div id="{chart_id}" class="chart-container" style="width: {config.width}px; height: {config.height}px;"></div>
        '''
        
        return GeneratedVisualization(
            visualization_id=chart_id,
            chart_type=config.chart_type,
            config=config,
            html_content=html_content,
            javascript_code=javascript_code,
            css_styles="",
            generation_time=time.time()
        )
    
    def _create_plotly_bar_chart(self, data: VisualizationData, 
                                config: ChartConfiguration, colors: Dict[str, str]) -> List[Dict[str, Any]]:
        """Create Plotly bar chart data."""
        
        x_values = [item[config.x_axis] for item in data.data]
        y_values = [item[config.y_axis] for item in data.data]
        
        chart_colors = config.colors if config.colors else [colors['primary']]
        
        return [{
            'x': x_values,
            'y': y_values,
            'type': 'bar',
            'marker': {
                'color': chart_colors[0] if len(chart_colors) == 1 else chart_colors[:len(x_values)]
            },
            'name': config.title
        }]
    
    def _create_plotly_pie_chart(self, data: VisualizationData, 
                                config: ChartConfiguration, colors: Dict[str, str]) -> List[Dict[str, Any]]:
        """Create Plotly pie chart data."""
        
        labels = [item.get('label', item.get('name', '')) for item in data.data]
        values = [item.get('value', item.get('count', 0)) for item in data.data]
        
        chart_colors = config.colors if config.colors else self._get_severity_colors()
        
        return [{
            'labels': labels,
            'values': values,
            'type': 'pie',
            'marker': {
                'colors': chart_colors
            },
            'textinfo': 'label+percent',
            'textposition': 'outside'
        }]
    
    def _create_plotly_donut_chart(self, data: VisualizationData, 
                                  config: ChartConfiguration, colors: Dict[str, str]) -> List[Dict[str, Any]]:
        """Create Plotly donut chart data."""
        
        pie_data = self._create_plotly_pie_chart(data, config, colors)
        pie_data[0]['hole'] = 0.4  # Create donut hole
        
        return pie_data
    
    def _create_plotly_line_chart(self, data: VisualizationData, 
                                 config: ChartConfiguration, colors: Dict[str, str]) -> List[Dict[str, Any]]:
        """Create Plotly line chart data."""
        
        x_values = [item[config.x_axis] for item in data.data]
        y_values = [item[config.y_axis] for item in data.data]
        
        return [{
            'x': x_values,
            'y': y_values,
            'type': 'scatter',
            'mode': 'lines+markers',
            'line': {'color': colors['primary']},
            'marker': {'color': colors['primary']},
            'name': config.title
        }]
    
    def _create_plotly_gauge(self, data: VisualizationData, 
                            config: ChartConfiguration, colors: Dict[str, str]) -> List[Dict[str, Any]]:
        """Create Plotly gauge chart data."""
        
        # Assume data contains a single value for the gauge
        value = data.data[0].get('value', 0) if data.data else 0
        
        return [{
            'domain': {'x': [0, 1], 'y': [0, 1]},
            'value': value,
            'title': {'text': config.title},
            'type': "indicator",
            'mode': "gauge+number+delta",
            'gauge': {
                'axis': {'range': [None, 100]},
                'bar': {'color': colors['primary']},
                'steps': [
                    {'range': [0, 50], 'color': colors.get('success', '#28a745')},
                    {'range': [50, 80], 'color': colors.get('warning', '#ffc107')},
                    {'range': [80, 100], 'color': colors.get('danger', '#dc3545')}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        }]
    
    def _get_severity_colors(self) -> List[str]:
        """Get color scheme for severity levels."""
        return [
            '#dc3545',  # Critical - Red
            '#fd7e14',  # High - Orange
            '#ffc107',  # Medium - Yellow
            '#28a745',  # Low - Green
            '#17a2b8'   # Info - Blue
        ]
    
    def _prepare_findings_data(self, scan_data: Dict[str, Any]) -> VisualizationData:
        """Prepare findings data for visualization."""
        
        findings = scan_data.get('findings', [])
        
        return VisualizationData(
            data_id="findings_data",
            name="Security Findings",
            data=findings,
            row_count=len(findings)
        )
    
    def _prepare_severity_data(self, scan_data: Dict[str, Any]) -> VisualizationData:
        """Prepare severity distribution data."""
        
        severity_counts = scan_data.get('severity_distribution', {})
        
        data = [
            {'label': severity.title(), 'value': count}
            for severity, count in severity_counts.items()
            if count > 0
        ]
        
        return VisualizationData(
            data_id="severity_data",
            name="Severity Distribution",
            data=data
        )
    
    def _prepare_category_data(self, scan_data: Dict[str, Any]) -> VisualizationData:
        """Prepare category breakdown data."""
        
        findings = scan_data.get('findings', [])
        category_counts = {}
        
        for finding in findings:
            category = finding.get('category', 'Unknown')
            category_counts[category] = category_counts.get(category, 0) + 1
        
        data = [
            {'category': category, 'count': count}
            for category, count in category_counts.items()
        ]
        
        return VisualizationData(
            data_id="category_data",
            name="Category Breakdown",
            data=data
        )
    
    def _prepare_trend_data(self, scan_data: Dict[str, Any]) -> Optional[VisualizationData]:
        """Prepare trend analysis data."""
        
        historical_data = scan_data.get('historical_data', [])
        
        if not historical_data:
            return None
        
        return VisualizationData(
            data_id="trend_data",
            name="Security Trends",
            data=historical_data
        )
    
    async def _generate_dashboard_html(self, config: DashboardConfiguration, 
                                      visualizations: Dict[str, GeneratedVisualization]) -> str:
        """Generate complete dashboard HTML."""
        
        # Collect all JavaScript and CSS
        all_javascript = []
        all_css = []
        
        for viz in visualizations.values():
            if viz.javascript_code:
                all_javascript.append(viz.javascript_code)
            if viz.css_styles:
                all_css.append(viz.css_styles)
        
        # Create chart containers HTML
        chart_containers = []
        for chart_config in config.charts:
            if chart_config.chart_id in visualizations:
                viz = visualizations[chart_config.chart_id]
                chart_containers.append(f'''
                <div class="chart-wrapper col-lg-6 col-md-12 mb-4">
                    <div class="card">
                        <div class="card-header">
                            <h5 class="card-title">{chart_config.title}</h5>
                        </div>
                        <div class="card-body">
                            {viz.html_content}
                        </div>
                    </div>
                </div>
                ''')
        
        # Generate complete dashboard HTML
        dashboard_html = f'''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{config.title}</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
            <style>
                body {{
                    background-color: {self.color_schemes[config.theme]['background']};
                    color: {self.color_schemes[config.theme]['text']};
                }}
                .chart-container {{
                    width: 100%;
                    height: 100%;
                }}
                {chr(10).join(all_css)}
                {config.custom_css}
            </style>
        </head>
        <body>
            <div class="container-fluid">
                <div class="row">
                    <div class="col-12">
                        <h1 class="mt-4 mb-4">{config.title}</h1>
                        {f'<p class="text-muted">{config.description}</p>' if config.description else ''}
                    </div>
                </div>
                <div class="row">
                    {chr(10).join(chart_containers)}
                </div>
            </div>
            
            <script>
                {chr(10).join(all_javascript)}
                
                // Auto-refresh functionality
                {f'''
                setInterval(function() {{
                    location.reload();
                }}, {config.refresh_interval * 1000});
                ''' if config.auto_refresh else ''}
            </script>
        </body>
        </html>
        '''
        
        return dashboard_html
    
    def _generate_chart_cache_key(self, config: ChartConfiguration, data: VisualizationData) -> str:
        """Generate cache key for chart."""
        
        import hashlib
        
        key_data = {
            'chart_type': config.chart_type.value,
            'data_id': data.data_id,
            'data_hash': hashlib.md5(json.dumps(data.data, sort_keys=True, default=str).encode()).hexdigest(),
            'config_hash': hashlib.md5(json.dumps(config.__dict__, sort_keys=True, default=str).encode()).hexdigest()
        }
        
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _initialize_chart_templates(self) -> Dict[ChartType, Dict[str, Any]]:
        """Initialize chart templates."""
        
        return {
            ChartType.BAR_CHART: {
                'default_width': 600,
                'default_height': 400,
                'supports_animation': True,
                'supports_interaction': True
            },
            ChartType.PIE_CHART: {
                'default_width': 400,
                'default_height': 400,
                'supports_animation': True,
                'supports_interaction': True
            },
            ChartType.LINE_CHART: {
                'default_width': 800,
                'default_height': 400,
                'supports_animation': True,
                'supports_interaction': True
            },
            ChartType.HEATMAP: {
                'default_width': 800,
                'default_height': 600,
                'supports_animation': False,
                'supports_interaction': True
            }
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get visualization engine statistics."""
        
        return dict(self.stats)
