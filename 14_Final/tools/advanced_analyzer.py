"""
Advanced Analysis Tools for SOAR System
Provides comprehensive analysis capabilities for security incidents, performance evaluation, and system optimization.
"""

import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.metrics import classification_report, confusion_matrix
import networkx as nx
from typing import Dict, List, Tuple, Any
import asyncio
import aiohttp
from datetime import datetime, timedelta
import json
import logging
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class AnalysisType(Enum):
    PERFORMANCE = "performance"
    THREAT_LANDSCAPE = "threat_landscape"
    COST_BENEFIT = "cost_benefit"
    RISK_ASSESSMENT = "risk_assessment"
    TREND_ANALYSIS = "trend_analysis"
    COMPARATIVE = "comparative"

@dataclass
class AnalysisResult:
    analysis_type: AnalysisType
    timestamp: datetime
    metrics: Dict[str, Any]
    visualizations: List[str]
    insights: List[str]
    recommendations: List[str]
    confidence_score: float

class AdvancedAnalyzer:
    """Advanced analysis engine for SOAR system performance and security metrics."""
    
    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self.data_cache = {}
        self.analysis_history = []
        
    def _load_config(self, config_path: str) -> Dict:
        """Load analysis configuration."""
        default_config = {
            "data_sources": {
                "prometheus": "http://localhost:9090",
                "elasticsearch": "http://localhost:9200",
                "database": "postgresql://localhost:5432/soar"
            },
            "analysis_params": {
                "time_window": 24,  # hours
                "confidence_threshold": 0.85,
                "outlier_detection_eps": 0.5,
                "clustering_min_samples": 5
            },
            "visualization": {
                "theme": "plotly_dark",
                "color_palette": "viridis",
                "export_format": "html"
            }
        }
        
        if config_path:
            with open(config_path, 'r') as f:
                custom_config = json.load(f)
                default_config.update(custom_config)
                
        return default_config
    
    async def comprehensive_analysis(self, analysis_types: List[AnalysisType] = None) -> Dict[str, AnalysisResult]:
        """Perform comprehensive analysis across multiple dimensions."""
        if analysis_types is None:
            analysis_types = list(AnalysisType)
        
        results = {}
        
        # Collect data in parallel
        data_tasks = {
            "performance": self._collect_performance_data(),
            "incidents": self._collect_incident_data(),
            "threats": self._collect_threat_data(),
            "costs": self._collect_cost_data(),
            "risks": self._collect_risk_data()
        }
        
        collected_data = await asyncio.gather(*data_tasks.values(), return_exceptions=True)
        data_dict = dict(zip(data_tasks.keys(), collected_data))
        
        # Perform analyses
        for analysis_type in analysis_types:
            try:
                if analysis_type == AnalysisType.PERFORMANCE:
                    results[analysis_type.value] = await self._analyze_performance(data_dict["performance"])
                elif analysis_type == AnalysisType.THREAT_LANDSCAPE:
                    results[analysis_type.value] = await self._analyze_threat_landscape(data_dict["threats"])
                elif analysis_type == AnalysisType.COST_BENEFIT:
                    results[analysis_type.value] = await self._analyze_cost_benefit(data_dict["costs"])
                elif analysis_type == AnalysisType.RISK_ASSESSMENT:
                    results[analysis_type.value] = await self._analyze_risk_assessment(data_dict["risks"])
                elif analysis_type == AnalysisType.TREND_ANALYSIS:
                    results[analysis_type.value] = await self._analyze_trends(data_dict)
                elif analysis_type == AnalysisType.COMPARATIVE:
                    results[analysis_type.value] = await self._analyze_comparative(data_dict)
                    
            except Exception as e:
                logger.error(f"Analysis failed for {analysis_type}: {e}")
                continue
        
        return results
    
    async def _analyze_performance(self, data: pd.DataFrame) -> AnalysisResult:
        """Analyze system performance metrics."""
        metrics = {}
        visualizations = []
        insights = []
        recommendations = []
        
        # Performance KPIs
        metrics["detection_time"] = {
            "mean": data["detection_time"].mean(),
            "p95": data["detection_time"].quantile(0.95),
            "p99": data["detection_time"].quantile(0.99),
            "target_compliance": (data["detection_time"] < 60).mean() * 100
        }
        
        metrics["response_time"] = {
            "mean": data["response_time"].mean(),
            "p95": data["response_time"].quantile(0.95),
            "p99": data["response_time"].quantile(0.99),
            "target_compliance": (data["response_time"] < 300).mean() * 100
        }
        
        metrics["false_positive_rate"] = {
            "rate": data["false_positive"].mean() * 100,
            "trend": self._calculate_trend(data["false_positive"], window=7),
            "target_compliance": (data["false_positive"] < 0.001).mean() * 100
        }
        
        # Performance trends visualization
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=("Detection Time Trend", "Response Time Trend", 
                          "False Positive Rate", "Throughput Analysis"),
            specs=[[{"secondary_y": True}, {"secondary_y": True}],
                   [{"secondary_y": False}, {"secondary_y": False}]]
        )
        
        # Detection time trend
        fig.add_trace(
            go.Scatter(x=data.index, y=data["detection_time"], 
                      name="Detection Time", line=dict(color="blue")),
            row=1, col=1
        )
        fig.add_hline(y=60, line_dash="dash", line_color="red", 
                     annotation_text="Target: 60s", row=1, col=1)
        
        # Response time trend
        fig.add_trace(
            go.Scatter(x=data.index, y=data["response_time"], 
                      name="Response Time", line=dict(color="green")),
            row=1, col=2
        )
        fig.add_hline(y=300, line_dash="dash", line_color="red", 
                     annotation_text="Target: 300s", row=1, col=2)
        
        # False positive rate
        fp_rolling = data["false_positive"].rolling(window=24).mean()
        fig.add_trace(
            go.Scatter(x=data.index, y=fp_rolling * 100, 
                      name="FP Rate (%)", line=dict(color="orange")),
            row=2, col=1
        )
        fig.add_hline(y=0.1, line_dash="dash", line_color="red", 
                     annotation_text="Target: 0.1%", row=2, col=1)
        
        # Throughput analysis
        hourly_throughput = data.groupby(data.index.hour)["incident_count"].sum()
        fig.add_trace(
            go.Bar(x=hourly_throughput.index, y=hourly_throughput.values, 
                   name="Hourly Throughput", marker_color="purple"),
            row=2, col=2
        )
        
        fig.update_layout(height=800, title="Performance Analysis Dashboard")
        visualizations.append(fig.to_html())
        
        # Generate insights
        if metrics["detection_time"]["target_compliance"] > 95:
            insights.append("Detection time targets consistently met with 95%+ compliance")
        else:
            insights.append(f"Detection time compliance at {metrics['detection_time']['target_compliance']:.1f}% - needs improvement")
            recommendations.append("Optimize detection algorithms and increase parallel processing")
        
        if metrics["false_positive_rate"]["rate"] < 0.1:
            insights.append("False positive rate exceeds target - excellent accuracy")
        else:
            insights.append("False positive rate above target threshold")
            recommendations.append("Retrain ML models with additional labeled data")
        
        # Performance regression analysis
        recent_data = data.tail(168)  # Last week
        historical_data = data.head(-168)
        
        if len(historical_data) > 0:
            recent_avg = recent_data["detection_time"].mean()
            historical_avg = historical_data["detection_time"].mean()
            change_pct = ((recent_avg - historical_avg) / historical_avg) * 100
            
            if abs(change_pct) > 10:
                insights.append(f"Significant performance change detected: {change_pct:+.1f}% in detection time")
                if change_pct > 0:
                    recommendations.append("Investigate performance degradation causes")
        
        confidence_score = self._calculate_confidence(data, ["detection_time", "response_time", "false_positive"])
        
        return AnalysisResult(
            analysis_type=AnalysisType.PERFORMANCE,
            timestamp=datetime.now(),
            metrics=metrics,
            visualizations=visualizations,
            insights=insights,
            recommendations=recommendations,
            confidence_score=confidence_score
        )
    
    async def _analyze_threat_landscape(self, data: pd.DataFrame) -> AnalysisResult:
        """Analyze threat landscape and attack patterns."""
        metrics = {}
        visualizations = []
        insights = []
        recommendations = []
        
        # Threat distribution analysis
        threat_types = data["threat_type"].value_counts()
        severity_dist = data["severity"].value_counts()
        
        metrics["threat_distribution"] = threat_types.to_dict()
        metrics["severity_distribution"] = severity_dist.to_dict()
        metrics["attack_vectors"] = data["attack_vector"].value_counts().to_dict()
        
        # Temporal threat analysis
        daily_threats = data.groupby(data["timestamp"].dt.date).size()
        metrics["threat_trend"] = {
            "daily_average": daily_threats.mean(),
            "peak_day": daily_threats.idxmax(),
            "peak_count": daily_threats.max(),
            "trend_direction": "increasing" if daily_threats.tail(7).mean() > daily_threats.head(7).mean() else "decreasing"
        }
        
        # Threat landscape visualization
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=("Threat Type Distribution", "Severity Levels", 
                          "Attack Vector Analysis", "Threat Timeline"),
            specs=[[{"type": "pie"}, {"type": "pie"}],
                   [{"type": "bar"}, {"type": "scatter"}]]
        )
        
        # Threat type pie chart
        fig.add_trace(
            go.Pie(labels=threat_types.index, values=threat_types.values, 
                   name="Threat Types"),
            row=1, col=1
        )
        
        # Severity pie chart
        fig.add_trace(
            go.Pie(labels=severity_dist.index, values=severity_dist.values, 
                   name="Severity"),
            row=1, col=2
        )
        
        # Attack vector bar chart
        attack_vectors = data["attack_vector"].value_counts()
        fig.add_trace(
            go.Bar(x=attack_vectors.index, y=attack_vectors.values, 
                   name="Attack Vectors"),
            row=2, col=1
        )
        
        # Threat timeline
        fig.add_trace(
            go.Scatter(x=daily_threats.index, y=daily_threats.values, 
                      mode="lines+markers", name="Daily Threats"),
            row=2, col=2
        )
        
        fig.update_layout(height=800, title="Threat Landscape Analysis")
        visualizations.append(fig.to_html())
        
        # Advanced pattern analysis using clustering
        if len(data) > 100:
            # Prepare features for clustering
            feature_columns = ["severity_numeric", "confidence_score", "impact_score"]
            if all(col in data.columns for col in feature_columns):
                features = data[feature_columns].fillna(0)
                scaler = StandardScaler()
                scaled_features = scaler.fit_transform(features)
                
                # DBSCAN clustering
                clustering = DBSCAN(eps=self.config["analysis_params"]["outlier_detection_eps"], 
                                  min_samples=self.config["analysis_params"]["clustering_min_samples"])
                clusters = clustering.fit_predict(scaled_features)
                
                unique_clusters = len(set(clusters)) - (1 if -1 in clusters else 0)
                outliers = np.sum(clusters == -1)
                
                metrics["pattern_analysis"] = {
                    "clusters_identified": unique_clusters,
                    "outliers_detected": outliers,
                    "outlier_percentage": (outliers / len(data)) * 100
                }
                
                if outliers > 0:
                    insights.append(f"Identified {outliers} anomalous threat patterns requiring investigation")
                    recommendations.append("Review outlier incidents for novel attack techniques")
        
        # Generate insights based on threat analysis
        top_threat = threat_types.index[0]
        top_threat_pct = (threat_types.iloc[0] / threat_types.sum()) * 100
        insights.append(f"Dominant threat type: {top_threat} ({top_threat_pct:.1f}% of incidents)")
        
        if metrics["threat_trend"]["trend_direction"] == "increasing":
            insights.append("Threat activity trending upward - enhanced monitoring recommended")
            recommendations.append("Scale detection infrastructure and analyst capacity")
        
        # Critical severity analysis
        critical_threats = data[data["severity"] == "critical"]
        if len(critical_threats) > 0:
            critical_pct = (len(critical_threats) / len(data)) * 100
            insights.append(f"Critical threats represent {critical_pct:.1f}% of all incidents")
            
            if critical_pct > 10:
                recommendations.append("Review and strengthen critical asset protection")
        
        confidence_score = self._calculate_confidence(data, ["threat_type", "severity", "attack_vector"])
        
        return AnalysisResult(
            analysis_type=AnalysisType.THREAT_LANDSCAPE,
            timestamp=datetime.now(),
            metrics=metrics,
            visualizations=visualizations,
            insights=insights,
            recommendations=recommendations,
            confidence_score=confidence_score
        )
    
    async def _analyze_cost_benefit(self, data: Dict) -> AnalysisResult:
        """Analyze cost-benefit metrics of the SOAR system."""
        metrics = {}
        visualizations = []
        insights = []
        recommendations = []
        
        # Cost calculations
        implementation_costs = data.get("implementation_costs", {})
        operational_costs = data.get("operational_costs", {})
        benefits = data.get("benefits", {})
        
        total_implementation = sum(implementation_costs.values())
        annual_operational = sum(operational_costs.values())
        annual_benefits = sum(benefits.values())
        
        # ROI calculations
        net_benefit = annual_benefits - annual_operational
        roi_percentage = (net_benefit / total_implementation) * 100
        payback_months = total_implementation / (net_benefit / 12) if net_benefit > 0 else float('inf')
        
        metrics["financial_analysis"] = {
            "total_implementation_cost": total_implementation,
            "annual_operational_cost": annual_operational,
            "annual_benefits": annual_benefits,
            "net_annual_benefit": net_benefit,
            "roi_percentage": roi_percentage,
            "payback_period_months": payback_months,
            "break_even_point": total_implementation
        }
        
        # Cost breakdown visualization
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=("Implementation Costs", "Annual Benefits", 
                          "ROI Timeline", "Cost vs Benefits"),
            specs=[[{"type": "pie"}, {"type": "pie"}],
                   [{"type": "scatter"}, {"type": "bar"}]]
        )
        
        # Implementation costs pie chart
        if implementation_costs:
            fig.add_trace(
                go.Pie(labels=list(implementation_costs.keys()), 
                      values=list(implementation_costs.values()), 
                      name="Implementation Costs"),
                row=1, col=1
            )
        
        # Benefits pie chart
        if benefits:
            fig.add_trace(
                go.Pie(labels=list(benefits.keys()), 
                      values=list(benefits.values()), 
                      name="Annual Benefits"),
                row=1, col=2
            )
        
        # ROI timeline (5-year projection)
        years = list(range(1, 6))
        cumulative_costs = [total_implementation + (annual_operational * year) for year in years]
        cumulative_benefits = [annual_benefits * year for year in years]
        net_cumulative = [benefit - cost for benefit, cost in zip(cumulative_benefits, cumulative_costs)]
        
        fig.add_trace(
            go.Scatter(x=years, y=cumulative_costs, name="Cumulative Costs", 
                      line=dict(color="red")),
            row=2, col=1
        )
        fig.add_trace(
            go.Scatter(x=years, y=cumulative_benefits, name="Cumulative Benefits", 
                      line=dict(color="green")),
            row=2, col=1
        )
        fig.add_trace(
            go.Scatter(x=years, y=net_cumulative, name="Net Benefit", 
                      line=dict(color="blue")),
            row=2, col=1
        )
        
        # Cost vs benefits comparison
        categories = ["Implementation", "Annual Operational", "Annual Benefits"]
        values = [total_implementation, annual_operational, annual_benefits]
        colors = ["red", "orange", "green"]
        
        fig.add_trace(
            go.Bar(x=categories, y=values, marker_color=colors, 
                   name="Financial Comparison"),
            row=2, col=2
        )
        
        fig.update_layout(height=800, title="Cost-Benefit Analysis")
        visualizations.append(fig.to_html())
        
        # Generate insights
        if roi_percentage > 200:
            insights.append(f"Excellent ROI of {roi_percentage:.1f}% demonstrates strong business value")
        elif roi_percentage > 100:
            insights.append(f"Positive ROI of {roi_percentage:.1f}% shows good investment return")
        else:
            insights.append(f"ROI of {roi_percentage:.1f}% may need optimization")
            recommendations.append("Review cost optimization opportunities")
        
        if payback_months < 12:
            insights.append(f"Fast payback period of {payback_months:.1f} months")
        elif payback_months < 24:
            insights.append(f"Reasonable payback period of {payback_months:.1f} months")
        else:
            insights.append(f"Extended payback period of {payback_months:.1f} months")
            recommendations.append("Consider phased implementation to accelerate benefits realization")
        
        # Efficiency metrics
        if "analyst_hours_saved" in benefits:
            hours_saved = benefits["analyst_hours_saved"]
            cost_per_hour_saved = total_implementation / hours_saved if hours_saved > 0 else 0
            metrics["efficiency_metrics"] = {
                "cost_per_hour_saved": cost_per_hour_saved,
                "hours_saved_annually": hours_saved
            }
            insights.append(f"Saving {hours_saved:,.0f} analyst hours annually")
        
        confidence_score = 0.9 if all(isinstance(v, (int, float)) and v > 0 for v in [total_implementation, annual_benefits]) else 0.6
        
        return AnalysisResult(
            analysis_type=AnalysisType.COST_BENEFIT,
            timestamp=datetime.now(),
            metrics=metrics,
            visualizations=visualizations,
            insights=insights,
            recommendations=recommendations,
            confidence_score=confidence_score
        )
    
    def _calculate_trend(self, series: pd.Series, window: int = 7) -> str:
        """Calculate trend direction for a time series."""
        if len(series) < window * 2:
            return "insufficient_data"
        
        recent = series.tail(window).mean()
        previous = series.head(-window).tail(window).mean()
        
        change_pct = ((recent - previous) / previous) * 100 if previous != 0 else 0
        
        if change_pct > 5:
            return "increasing"
        elif change_pct < -5:
            return "decreasing"
        else:
            return "stable"
    
    def _calculate_confidence(self, data: pd.DataFrame, columns: List[str]) -> float:
        """Calculate confidence score based on data quality and completeness."""
        if len(data) == 0:
            return 0.0
        
        # Data completeness
        completeness = data[columns].notna().mean().mean()
        
        # Data recency (higher score for more recent data)
        if "timestamp" in data.columns:
            latest_data = data["timestamp"].max()
            age_hours = (datetime.now() - latest_data).total_seconds() / 3600
            recency_score = max(0, 1 - (age_hours / 168))  # Decay over a week
        else:
            recency_score = 0.8  # Default if no timestamp
        
        # Sample size adequacy
        sample_score = min(1.0, len(data) / 1000)  # Full confidence at 1000+ samples
        
        # Overall confidence
        confidence = (completeness * 0.5 + recency_score * 0.3 + sample_score * 0.2)
        
        return round(confidence, 3)
    
    async def _collect_performance_data(self) -> pd.DataFrame:
        """Collect performance data from monitoring systems."""
        # This would integrate with actual monitoring systems
        # For now, return simulated data structure
        date_range = pd.date_range(start=datetime.now() - timedelta(days=30), 
                                  end=datetime.now(), freq='H')
        
        np.random.seed(42)  # For reproducible results
        data = pd.DataFrame({
            "detection_time": np.random.exponential(25, len(date_range)),
            "response_time": np.random.exponential(120, len(date_range)),
            "false_positive": np.random.random(len(date_range)) < 0.0008,
            "incident_count": np.random.poisson(2, len(date_range)),
            "containment_success": np.random.random(len(date_range)) > 0.02,
            "recovery_accuracy": np.random.beta(95, 1, len(date_range))
        }, index=date_range)
        
        return data
    
    async def _collect_incident_data(self) -> pd.DataFrame:
        """Collect incident data for analysis."""
        # Simulated incident data
        incidents = []
        for i in range(500):
            incidents.append({
                "incident_id": f"INC-{i:04d}",
                "timestamp": datetime.now() - timedelta(
                    minutes=np.random.randint(0, 43200)  # Last 30 days
                ),
                "severity": np.random.choice(["low", "medium", "high", "critical"], 
                                           p=[0.4, 0.3, 0.2, 0.1]),
                "type": np.random.choice(["malware", "phishing", "ddos", "intrusion", "data_breach"],
                                       p=[0.3, 0.25, 0.15, 0.2, 0.1]),
                "status": np.random.choice(["resolved", "investigating", "contained"],
                                         p=[0.7, 0.2, 0.1])
            })
        
        return pd.DataFrame(incidents)
    
    async def _collect_threat_data(self) -> pd.DataFrame:
        """Collect threat intelligence data."""
        threats = []
        threat_types = ["malware", "phishing", "ransomware", "apt", "insider_threat"]
        attack_vectors = ["email", "web", "network", "endpoint", "cloud"]
        
        for i in range(1000):
            threats.append({
                "threat_id": f"THR-{i:04d}",
                "timestamp": datetime.now() - timedelta(
                    hours=np.random.randint(0, 720)  # Last 30 days
                ),
                "threat_type": np.random.choice(threat_types),
                "attack_vector": np.random.choice(attack_vectors),
                "severity": np.random.choice(["low", "medium", "high", "critical"],
                                           p=[0.3, 0.4, 0.2, 0.1]),
                "confidence_score": np.random.beta(8, 2),
                "impact_score": np.random.randint(1, 11),
                "severity_numeric": np.random.randint(1, 5)
            })
        
        return pd.DataFrame(threats)
    
    async def _collect_cost_data(self) -> Dict:
        """Collect cost and benefit data."""
        return {
            "implementation_costs": {
                "development": 180000,
                "infrastructure": 45000,
                "training": 25000,
                "integration": 15000,
                "licensing": 20000
            },
            "operational_costs": {
                "maintenance": 60000,
                "cloud_services": 36000,
                "support": 24000,
                "updates": 15000
            },
            "benefits": {
                "analyst_time_savings": 280800,
                "reduced_mttr": 450000,
                "false_positive_reduction": 156000,
                "automated_response": 125000,
                "compliance_improvement": 75000
            }
        }
    
    async def _collect_risk_data(self) -> pd.DataFrame:
        """Collect risk assessment data."""
        risks = []
        risk_types = ["operational", "security", "compliance", "financial", "reputation"]
        
        for i in range(200):
            risks.append({
                "risk_id": f"RSK-{i:03d}",
                "timestamp": datetime.now() - timedelta(days=np.random.randint(0, 90)),
                "risk_type": np.random.choice(risk_types),
                "probability": np.random.beta(2, 5),
                "impact": np.random.randint(1, 11),
                "risk_score": np.random.beta(3, 7) * 100,
                "mitigation_status": np.random.choice(["planned", "in_progress", "completed"],
                                                    p=[0.3, 0.4, 0.3])
            })
        
        return pd.DataFrame(risks)
    
    async def _analyze_risk_assessment(self, data: pd.DataFrame) -> AnalysisResult:
        """Analyze risk assessment data."""
        # Implementation would analyze actual risk data
        return AnalysisResult(
            analysis_type=AnalysisType.RISK_ASSESSMENT,
            timestamp=datetime.now(),
            metrics={"placeholder": "risk_metrics"},
            visualizations=[],
            insights=["Risk analysis placeholder"],
            recommendations=["Risk recommendation placeholder"],
            confidence_score=0.8
        )
    
    async def _analyze_trends(self, data: Dict) -> AnalysisResult:
        """Analyze trends across all data types."""
        # Implementation would analyze trends
        return AnalysisResult(
            analysis_type=AnalysisType.TREND_ANALYSIS,
            timestamp=datetime.now(),
            metrics={"placeholder": "trend_metrics"},
            visualizations=[],
            insights=["Trend analysis placeholder"],
            recommendations=["Trend recommendation placeholder"],
            confidence_score=0.8
        )
    
    async def _analyze_comparative(self, data: Dict) -> AnalysisResult:
        """Perform comparative analysis against benchmarks."""
        # Implementation would compare against industry benchmarks
        return AnalysisResult(
            analysis_type=AnalysisType.COMPARATIVE,
            timestamp=datetime.now(),
            metrics={"placeholder": "comparative_metrics"},
            visualizations=[],
            insights=["Comparative analysis placeholder"],
            recommendations=["Comparative recommendation placeholder"],
            confidence_score=0.8
        )

class ReportGenerator:
    """Generate comprehensive analysis reports."""
    
    def __init__(self, template_path: str = None):
        self.template_path = template_path
    
    async def generate_executive_report(self, analysis_results: Dict[str, AnalysisResult]) -> str:
        """Generate executive summary report."""
        report = []
        
        report.append("# SOAR System Analysis - Executive Summary\n")
        report.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Key findings
        report.append("## Key Findings\n")
        
        for analysis_type, result in analysis_results.items():
            report.append(f"### {analysis_type.replace('_', ' ').title()}\n")
            
            # Top insights
            for insight in result.insights[:3]:  # Top 3 insights
                report.append(f"- {insight}\n")
            
            report.append(f"**Confidence Score:** {result.confidence_score:.1%}\n\n")
        
        # Recommendations
        report.append("## Priority Recommendations\n")
        
        all_recommendations = []
        for result in analysis_results.values():
            all_recommendations.extend(result.recommendations)
        
        for i, rec in enumerate(all_recommendations[:10], 1):  # Top 10 recommendations
            report.append(f"{i}. {rec}\n")
        
        return "".join(report)
    
    async def generate_technical_report(self, analysis_results: Dict[str, AnalysisResult]) -> str:
        """Generate detailed technical report."""
        report = []
        
        report.append("# SOAR System Technical Analysis Report\n")
        report.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        for analysis_type, result in analysis_results.items():
            report.append(f"## {analysis_type.replace('_', ' ').title()} Analysis\n\n")
            
            # Metrics
            report.append("### Metrics\n")
            for metric_name, metric_value in result.metrics.items():
                if isinstance(metric_value, dict):
                    report.append(f"**{metric_name.replace('_', ' ').title()}:**\n")
                    for sub_metric, sub_value in metric_value.items():
                        report.append(f"- {sub_metric.replace('_', ' ').title()}: {sub_value}\n")
                else:
                    report.append(f"- **{metric_name.replace('_', ' ').title()}:** {metric_value}\n")
            
            report.append("\n")
            
            # Insights
            report.append("### Insights\n")
            for insight in result.insights:
                report.append(f"- {insight}\n")
            
            report.append("\n")
            
            # Recommendations
            report.append("### Recommendations\n")
            for recommendation in result.recommendations:
                report.append(f"- {recommendation}\n")
            
            report.append("\n")
        
        return "".join(report)

# Example usage
if __name__ == "__main__":
    async def main():
        analyzer = AdvancedAnalyzer()
        
        # Perform comprehensive analysis
        results = await analyzer.comprehensive_analysis([
            AnalysisType.PERFORMANCE,
            AnalysisType.THREAT_LANDSCAPE,
            AnalysisType.COST_BENEFIT
        ])
        
        # Generate reports
        report_generator = ReportGenerator()
        executive_report = await report_generator.generate_executive_report(results)
        technical_report = await report_generator.generate_technical_report(results)
        
        print("Executive Report:")
        print(executive_report)
        print("\n" + "="*80 + "\n")
        print("Technical Report:")
        print(technical_report)
    
    asyncio.run(main())
