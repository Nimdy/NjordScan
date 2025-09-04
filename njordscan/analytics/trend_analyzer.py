#!/usr/bin/env python3
"""
📊 Vulnerability Trend Analysis System
Track security improvements and identify patterns over time.
"""

import json
import sqlite3
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import pandas as pd
from collections import defaultdict, Counter

from ..vulnerability import Vulnerability

@dataclass
class TrendData:
    """Trend analysis data point."""
    date: str
    total_vulnerabilities: int
    high_severity: int
    medium_severity: int
    low_severity: int
    new_vulnerabilities: int
    fixed_vulnerabilities: int
    scan_count: int

@dataclass
class TrendAnalysis:
    """Complete trend analysis result."""
    period: str
    start_date: str
    end_date: str
    trend_data: List[TrendData]
    summary: Dict[str, Any]
    recommendations: List[str]

class TrendAnalyzer:
    """Analyzes vulnerability trends over time."""
    
    def __init__(self, data_dir: Path = None):
        self.data_dir = data_dir or Path.home() / '.njordscan' / 'analytics'
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.db_path = self.data_dir / 'trends.db'
        self._init_database()

    def _init_database(self):
        """Initialize the trends database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS vulnerability_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL,
                        vuln_id TEXT NOT NULL,
                        vuln_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        file_path TEXT,
                        line_number INTEGER,
                        status TEXT DEFAULT 'active',
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        fix_date TEXT,
                        scan_date TEXT NOT NULL
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT UNIQUE NOT NULL,
                        target TEXT NOT NULL,
                        scan_mode TEXT NOT NULL,
                        scan_date TEXT NOT NULL,
                        total_vulnerabilities INTEGER DEFAULT 0,
                        new_vulnerabilities INTEGER DEFAULT 0,
                        fixed_vulnerabilities INTEGER DEFAULT 0
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS trend_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        date TEXT UNIQUE NOT NULL,
                        total_vulns INTEGER DEFAULT 0,
                        high_severity INTEGER DEFAULT 0,
                        medium_severity INTEGER DEFAULT 0,
                        low_severity INTEGER DEFAULT 0,
                        new_vulns INTEGER DEFAULT 0,
                        fixed_vulns INTEGER DEFAULT 0,
                        scan_count INTEGER DEFAULT 0
                    )
                ''')
                
                conn.commit()
        except Exception as e:
            print(f"Warning: Could not initialize trends database: {e}")

    def record_scan_results(self, scan_id: str, target: str, scan_mode: str, 
                          vulnerabilities: List[Vulnerability], scan_date: str = None):
        """Record scan results for trend analysis."""
        if scan_date is None:
            scan_date = datetime.now().isoformat()
            
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Record scan
                conn.execute('''
                    INSERT OR REPLACE INTO scan_history 
                    (scan_id, target, scan_mode, scan_date, total_vulnerabilities)
                    VALUES (?, ?, ?, ?, ?)
                ''', (scan_id, target, scan_mode, scan_date, len(vulnerabilities)))
                
                # Record vulnerabilities
                for vuln in vulnerabilities:
                    vuln_id = self._create_vulnerability_id(vuln)
                    
                    # Check if vulnerability already exists
                    cursor = conn.execute('''
                        SELECT id, status, first_seen FROM vulnerability_history 
                        WHERE vuln_id = ? AND file_path = ? AND line_number = ?
                    ''', (vuln_id, vuln.file_path, vuln.line_number))
                    
                    existing = cursor.fetchone()
                    
                    if existing:
                        # Update existing vulnerability
                        conn.execute('''
                            UPDATE vulnerability_history 
                            SET last_seen = ?, scan_date = ?
                            WHERE id = ?
                        ''', (scan_date, scan_date, existing[0]))
                    else:
                        # Record new vulnerability
                        conn.execute('''
                            INSERT INTO vulnerability_history 
                            (scan_id, vuln_id, vuln_type, severity, file_path, line_number,
                             first_seen, last_seen, scan_date)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            scan_id, vuln_id, vuln.vuln_type, vuln.severity,
                            vuln.file_path, vuln.line_number, scan_date, scan_date, scan_date
                        ))
                
                conn.commit()
                
                # Update daily metrics
                self._update_daily_metrics(scan_date, vulnerabilities)
                
        except Exception as e:
            print(f"Error recording scan results: {e}")

    def _create_vulnerability_id(self, vuln: Vulnerability) -> str:
        """Create a unique ID for a vulnerability."""
        identifier = f"{vuln.vuln_type}:{vuln.file_path}:{vuln.line_number}"
        return identifier

    def _update_daily_metrics(self, scan_date: str, vulnerabilities: List[Vulnerability]):
        """Update daily trend metrics."""
        try:
            date = scan_date.split('T')[0]  # Extract date part
            
            with sqlite3.connect(self.db_path) as conn:
                # Get existing metrics for the date
                cursor = conn.execute('SELECT * FROM trend_metrics WHERE date = ?', (date,))
                existing = cursor.fetchone()
                
                # Count vulnerabilities by severity
                severity_counts = Counter(vuln.severity for vuln in vulnerabilities)
                
                if existing:
                    # Update existing metrics
                    conn.execute('''
                        UPDATE trend_metrics 
                        SET total_vulns = total_vulns + ?,
                            high_severity = high_severity + ?,
                            medium_severity = medium_severity + ?,
                            low_severity = low_severity + ?,
                            scan_count = scan_count + 1
                        WHERE date = ?
                    ''', (
                        len(vulnerabilities),
                        severity_counts.get('high', 0),
                        severity_counts.get('medium', 0),
                        severity_counts.get('low', 0),
                        date
                    ))
                else:
                    # Create new metrics
                    conn.execute('''
                        INSERT INTO trend_metrics 
                        (date, total_vulns, high_severity, medium_severity, low_severity, scan_count)
                        VALUES (?, ?, ?, ?, ?, 1)
                    ''', (
                        date,
                        len(vulnerabilities),
                        severity_counts.get('high', 0),
                        severity_counts.get('medium', 0),
                        severity_counts.get('low', 0)
                    ))
                
                conn.commit()
                
        except Exception as e:
            print(f"Error updating daily metrics: {e}")

    def analyze_trends(self, days: int = 30) -> TrendAnalysis:
        """Analyze vulnerability trends over the specified period."""
        try:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days)
            
            with sqlite3.connect(self.db_path) as conn:
                # Get trend data
                cursor = conn.execute('''
                    SELECT date, total_vulns, high_severity, medium_severity, low_severity, 
                           new_vulns, fixed_vulns, scan_count
                    FROM trend_metrics 
                    WHERE date >= ? AND date <= ?
                    ORDER BY date
                ''', (start_date.date().isoformat(), end_date.date().isoformat()))
                
                trend_data = []
                for row in cursor.fetchall():
                    trend_data.append(TrendData(
                        date=row[0],
                        total_vulnerabilities=row[1],
                        high_severity=row[2],
                        medium_severity=row[3],
                        low_severity=row[4],
                        new_vulnerabilities=row[5] or 0,
                        fixed_vulnerabilities=row[6] or 0,
                        scan_count=row[7]
                    ))
                
                # Calculate summary statistics
                summary = self._calculate_summary(trend_data)
                
                # Generate recommendations
                recommendations = self._generate_recommendations(trend_data, summary)
                
                return TrendAnalysis(
                    period=f"{days} days",
                    start_date=start_date.date().isoformat(),
                    end_date=end_date.date().isoformat(),
                    trend_data=trend_data,
                    summary=summary,
                    recommendations=recommendations
                )
                
        except Exception as e:
            print(f"Error analyzing trends: {e}")
            return TrendAnalysis(
                period=f"{days} days",
                start_date="",
                end_date="",
                trend_data=[],
                summary={},
                recommendations=["Error analyzing trends"]
            )

    def _calculate_summary(self, trend_data: List[TrendData]) -> Dict[str, Any]:
        """Calculate summary statistics from trend data."""
        if not trend_data:
            return {}
            
        # Calculate totals
        total_vulns = sum(d.total_vulnerabilities for d in trend_data)
        total_high = sum(d.high_severity for d in trend_data)
        total_medium = sum(d.medium_severity for d in trend_data)
        total_low = sum(d.low_severity for d in trend_data)
        total_scans = sum(d.scan_count for d in trend_data)
        
        # Calculate trends
        if len(trend_data) > 1:
            first_day = trend_data[0].total_vulnerabilities
            last_day = trend_data[-1].total_vulnerabilities
            
            if first_day > 0:
                change_percentage = ((last_day - first_day) / first_day) * 100
            else:
                change_percentage = 0
                
            trend_direction = "improving" if change_percentage < 0 else "worsening"
        else:
            change_percentage = 0
            trend_direction = "stable"
            
        # Calculate averages
        avg_vulns_per_scan = total_vulns / total_scans if total_scans > 0 else 0
        avg_vulns_per_day = total_vulns / len(trend_data) if trend_data else 0
        
        return {
            'total_vulnerabilities': total_vulns,
            'severity_distribution': {
                'high': total_high,
                'medium': total_medium,
                'low': total_low
            },
            'total_scans': total_scans,
            'change_percentage': change_percentage,
            'trend_direction': trend_direction,
            'avg_vulns_per_scan': avg_vulns_per_scan,
            'avg_vulns_per_day': avg_vulns_per_day,
            'analysis_period_days': len(trend_data)
        }

    def _generate_recommendations(self, trend_data: List[TrendData], summary: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on trend analysis."""
        recommendations = []
        
        if not trend_data:
            return ["No trend data available for recommendations"]
            
        # Analyze vulnerability count trends
        if summary.get('trend_direction') == 'worsening':
            recommendations.append("🚨 Vulnerability count is increasing. Review your security practices and consider implementing additional security measures.")
        elif summary.get('trend_direction') == 'improving':
            recommendations.append("✅ Great progress! Vulnerability count is decreasing. Keep up the good security practices.")
            
        # Analyze severity distribution
        high_severity = summary.get('severity_distribution', {}).get('high', 0)
        if high_severity > 0:
            recommendations.append(f"⚠️ {high_severity} high-severity vulnerabilities detected. Prioritize fixing these critical issues.")
            
        # Analyze scan frequency
        avg_scans_per_day = summary.get('total_scans', 0) / summary.get('analysis_period_days', 1)
        if avg_scans_per_day < 1:
            recommendations.append("📅 Consider increasing scan frequency to catch vulnerabilities earlier.")
        elif avg_scans_per_day > 5:
            recommendations.append("⚡ High scan frequency detected. Ensure scans are not overwhelming your system.")
            
        # Analyze vulnerability density
        avg_vulns_per_scan = summary.get('avg_vulns_per_scan', 0)
        if avg_vulns_per_scan > 10:
            recommendations.append("🔍 High vulnerability density per scan. Consider breaking down large targets into smaller components.")
        elif avg_vulns_per_scan < 1:
            recommendations.append("🎯 Low vulnerability density. Your security practices appear effective.")
            
        # Time-based recommendations
        if len(trend_data) >= 7:
            weekly_trend = self._analyze_weekly_trend(trend_data)
            if weekly_trend['pattern'] == 'spike':
                recommendations.append("📈 Recent spike in vulnerabilities detected. Investigate recent changes or deployments.")
            elif weekly_trend['pattern'] == 'decline':
                recommendations.append("📉 Consistent decline in vulnerabilities. Your security improvements are working.")
                
        return recommendations

    def _analyze_weekly_trend(self, trend_data: List[TrendData]) -> Dict[str, Any]:
        """Analyze weekly patterns in the data."""
        if len(trend_data) < 7:
            return {'pattern': 'insufficient_data'}
            
        # Get last 7 days
        recent_data = trend_data[-7:]
        vuln_counts = [d.total_vulnerabilities for d in recent_data]
        
        # Calculate trend
        if len(vuln_counts) >= 2:
            trend = (vuln_counts[-1] - vuln_counts[0]) / len(vuln_counts)
            
            if trend > 2:
                pattern = 'spike'
            elif trend < -2:
                pattern = 'decline'
            else:
                pattern = 'stable'
        else:
            pattern = 'stable'
            
        return {
            'pattern': pattern,
            'trend': trend if 'trend' in locals() else 0,
            'recent_counts': vuln_counts
        }

    def get_vulnerability_lifecycle(self, days: int = 30) -> Dict[str, Any]:
        """Analyze vulnerability lifecycle and persistence."""
        try:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days)
            
            with sqlite3.connect(self.db_path) as conn:
                # Get vulnerability persistence data
                cursor = conn.execute('''
                    SELECT vuln_type, severity, 
                           COUNT(*) as occurrence_count,
                           AVG(JULIANDAY(last_seen) - JULIANDAY(first_seen)) as avg_days_active
                    FROM vulnerability_history 
                    WHERE first_seen >= ? AND first_seen <= ?
                    GROUP BY vuln_type, severity
                    ORDER BY occurrence_count DESC
                ''', (start_date.date().isoformat(), end_date.date().isoformat()))
                
                lifecycle_data = []
                for row in cursor.fetchall():
                    lifecycle_data.append({
                        'vuln_type': row[0],
                        'severity': row[1],
                        'occurrence_count': row[2],
                        'avg_days_active': row[3] or 0
                    })
                    
                return {
                    'period_days': days,
                    'lifecycle_data': lifecycle_data,
                    'total_unique_vulns': len(lifecycle_data),
                    'most_persistent': max(lifecycle_data, key=lambda x: x['avg_days_active']) if lifecycle_data else None,
                    'most_common': max(lifecycle_data, key=lambda x: x['occurrence_count']) if lifecycle_data else None
                }
                
        except Exception as e:
            print(f"Error analyzing vulnerability lifecycle: {e}")
            return {}

    def generate_trend_report(self, days: int = 30, output_path: Path = None) -> str:
        """Generate a comprehensive trend report."""
        try:
            # Get trend analysis
            analysis = self.analyze_trends(days)
            
            # Get lifecycle data
            lifecycle = self.get_vulnerability_lifecycle(days)
            
            # Generate report
            report = self._format_trend_report(analysis, lifecycle)
            
            # Save report if output path specified
            if output_path:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(report)
                    
            return report
            
        except Exception as e:
            print(f"Error generating trend report: {e}")
            return f"Error generating report: {e}"

    def _format_trend_report(self, analysis: TrendAnalysis, lifecycle: Dict[str, Any]) -> str:
        """Format the trend analysis into a readable report."""
        report = []
        report.append("=" * 60)
        report.append("🔍 NJORDSCAN VULNERABILITY TREND REPORT")
        report.append("=" * 60)
        report.append(f"📅 Analysis Period: {analysis.period}")
        report.append(f"📊 Date Range: {analysis.start_date} to {analysis.end_date}")
        report.append("")
        
        # Summary section
        report.append("📈 SUMMARY STATISTICS")
        report.append("-" * 30)
        summary = analysis.summary
        
        if summary:
            report.append(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
            report.append(f"Total Scans: {summary.get('total_scans', 0)}")
            report.append(f"Trend Direction: {summary.get('trend_direction', 'Unknown')}")
            report.append(f"Change: {summary.get('change_percentage', 0):.1f}%")
            report.append(f"Avg Vulnerabilities per Scan: {summary.get('avg_vulns_per_scan', 0):.1f}")
            report.append("")
            
            # Severity distribution
            severity_dist = summary.get('severity_distribution', {})
            report.append("🚨 SEVERITY DISTRIBUTION")
            report.append("-" * 30)
            report.append(f"High: {severity_dist.get('high', 0)}")
            report.append(f"Medium: {severity_dist.get('medium', 0)}")
            report.append(f"Low: {severity_dist.get('low', 0)}")
            report.append("")
        
        # Recommendations section
        report.append("💡 RECOMMENDATIONS")
        report.append("-" * 30)
        for rec in analysis.recommendations:
            report.append(f"• {rec}")
        report.append("")
        
        # Lifecycle section
        if lifecycle:
            report.append("🔄 VULNERABILITY LIFECYCLE")
            report.append("-" * 30)
            report.append(f"Total Unique Vulnerability Types: {lifecycle.get('total_unique_vulns', 0)}")
            
            most_persistent = lifecycle.get('most_persistent')
            if most_persistent:
                report.append(f"Most Persistent: {most_persistent['vuln_type']} ({most_persistent['avg_days_active']:.1f} days)")
                
            most_common = lifecycle.get('most_common')
            if most_common:
                report.append(f"Most Common: {most_common['vuln_type']} ({most_common['occurrence_count']} occurrences)")
            report.append("")
        
        # Trend data section
        report.append("📊 DAILY TREND DATA")
        report.append("-" * 30)
        report.append("Date\t\tTotal\tHigh\tMedium\tLow\tScans")
        report.append("-" * 50)
        
        for data in analysis.trend_data[-10:]:  # Show last 10 days
            report.append(f"{data.date}\t{data.total_vulnerabilities}\t{data.high_severity}\t{data.medium_severity}\t{data.low_severity}\t{data.scan_count}")
            
        report.append("")
        report.append("=" * 60)
        report.append("Report generated on: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        report.append("=" * 60)
        
        return "\n".join(report)

    def export_trend_data(self, output_path: Path, format: str = 'json', days: int = 30):
        """Export trend data for external analysis."""
        try:
            analysis = self.analyze_trends(days)
            lifecycle = self.get_vulnerability_lifecycle(days)
            
            export_data = {
                'analysis': {
                    'period': analysis.period,
                    'start_date': analysis.start_date,
                    'end_date': analysis.end_date,
                    'summary': analysis.summary,
                    'recommendations': analysis.recommendations
                },
                'trend_data': [
                    {
                        'date': data.date,
                        'total_vulnerabilities': data.total_vulnerabilities,
                        'high_severity': data.high_severity,
                        'medium_severity': data.medium_severity,
                        'low_severity': data.low_severity,
                        'new_vulnerabilities': data.new_vulnerabilities,
                        'fixed_vulnerabilities': data.fixed_vulnerabilities,
                        'scan_count': data.scan_count
                    }
                    for data in analysis.trend_data
                ],
                'lifecycle': lifecycle,
                'export_date': datetime.now().isoformat()
            }
            
            if format.lower() == 'json':
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2)
            elif format.lower() == 'csv':
                # Convert to CSV format
                df = pd.DataFrame(export_data['trend_data'])
                df.to_csv(output_path, index=False)
            else:
                print(f"Unsupported format: {format}")
                return False
                
            return True
            
        except Exception as e:
            print(f"Error exporting trend data: {e}")
            return False
