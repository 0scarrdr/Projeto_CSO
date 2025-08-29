"""
Metrics Collection System
Comprehensive metrics collection and performance tracking for the SOAR system
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import json
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Types of metrics collected"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


class MetricCategory(Enum):
    """Categories of metrics"""
    PERFORMANCE = "performance"
    SECURITY = "security"
    SYSTEM = "system"
    BUSINESS = "business"
    ERROR = "error"


@dataclass
class Metric:
    """Individual metric data point"""
    name: str
    value: float
    metric_type: MetricType
    category: MetricCategory
    timestamp: datetime
    tags: Dict[str, str] = field(default_factory=dict)
    description: str = ""


@dataclass
class PerformanceMetrics:
    """Performance metrics for SOAR operations"""
    detection_time: float = 0.0
    analysis_time: float = 0.0
    response_time: float = 0.0
    prediction_time: float = 0.0
    total_processing_time: float = 0.0
    
    detection_accuracy: float = 0.0
    response_success_rate: float = 0.0
    prediction_accuracy: float = 0.0
    
    incidents_processed: int = 0
    threats_detected: int = 0
    responses_executed: int = 0
    predictions_generated: int = 0


class MetricsCollector:
    """
    Comprehensive metrics collection system for monitoring SOAR performance,
    security effectiveness, and system health
    """
    
    def __init__(self, max_history_size: int = 10000):
        self.metrics_storage = defaultdict(deque)
        self.max_history_size = max_history_size
        self.performance_targets = self._initialize_performance_targets()
        self.alert_thresholds = self._initialize_alert_thresholds()
        self.aggregated_metrics = {}
        self.metric_metadata = {}
        self.collection_start_time = datetime.now()
        # simple timers per incident
        self._detection_start: Dict[str, float] = {}
        self._response_start: Dict[str, float] = {}
        
    def _initialize_performance_targets(self) -> Dict[str, float]:
        """Initialize performance targets as per assignment requirements"""
        return {
            'detection_time_target': 60.0,  # seconds - Detection < 1 minute
            'response_time_target': 300.0,  # seconds - Response < 5 minutes
            'detection_accuracy_target': 0.95,  # 95%+ accuracy
            'response_success_rate_target': 0.90,  # 90%+ success rate
            'evidence_preservation_target': 1.0,  # 100% evidence preservation
            'system_availability_target': 0.999,  # 99.9% availability
            'prediction_accuracy_target': 0.85,  # 85%+ prediction accuracy
            'false_positive_rate_target': 0.05,  # < 5% false positives
            'mean_time_to_containment': 180.0,  # 3 minutes
            'mean_time_to_recovery': 1800.0  # 30 minutes
        }
    
    def _initialize_alert_thresholds(self) -> Dict[str, Dict[str, float]]:
        """Initialize alerting thresholds for critical metrics"""
        return {
            'detection_time': {
                'warning': 45.0,  # 45 seconds
                'critical': 60.0  # 1 minute
            },
            'response_time': {
                'warning': 240.0,  # 4 minutes
                'critical': 300.0  # 5 minutes
            },
            'detection_accuracy': {
                'warning': 0.90,  # 90%
                'critical': 0.85  # 85%
            },
            'response_success_rate': {
                'warning': 0.85,  # 85%
                'critical': 0.80  # 80%
            },
            'system_cpu_usage': {
                'warning': 80.0,  # 80%
                'critical': 90.0  # 90%
            },
            'system_memory_usage': {
                'warning': 85.0,  # 85%
                'critical': 95.0  # 95%
            },
            'error_rate': {
                'warning': 0.02,  # 2%
                'critical': 0.05  # 5%
            }
        }
    
    async def initialize(self):
        """Inicializa o coletor de métricas de forma assíncrona"""
        logger.info("Initializing MetricsCollector...")
        # Aqui poderia haver inicializações assíncronas como conexões a sistemas de monitoramento
        # Por agora, apenas log de confirmação
        logger.info("MetricsCollector initialization complete")
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Verifica o estado de saúde do coletor de métricas
        
        Returns:
            Dict contendo informações sobre o estado do componente
        """
        try:
            # Verificar se há métricas sendo coletadas
            total_metrics = sum(len(deque_obj) for deque_obj in self.metrics_storage.values())
            
            # Verificar se os targets estão configurados
            targets_configured = len(self.performance_targets) > 0
            
            # Verificar se os thresholds estão configurados
            thresholds_configured = len(self.alert_thresholds) > 0
            
            # Tempo de execução
            uptime = datetime.now() - self.collection_start_time
            
            # Estado geral
            operational = targets_configured and thresholds_configured
            
            return {
                "operational": operational,
                "status": "healthy" if operational else "degraded",
                "components": {
                    "metrics_storage": {
                        "total_metrics": total_metrics,
                        "metric_types": len(self.metrics_storage),
                        "max_history_size": self.max_history_size
                    },
                    "performance_targets": {
                        "configured": targets_configured,
                        "count": len(self.performance_targets)
                    },
                    "alert_thresholds": {
                        "configured": thresholds_configured,
                        "count": len(self.alert_thresholds)
                    }
                },
                "uptime_seconds": uptime.total_seconds(),
                "last_check": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Health check failed for MetricsCollector: {str(e)}")
            return {
                "operational": False,
                "status": "error",
                "error": str(e),
                "last_check": datetime.now().isoformat()
            }

    # --- Incident timers used by core ---
    def record_detection_start(self, incident_id: str) -> None:
        self._detection_start[incident_id] = time.time()
        self.record_metric(
            'detection_started', 1, MetricType.COUNTER, MetricCategory.PERFORMANCE,
            {'incident_id': incident_id}, 'Detection started'
        )

    def record_detection_end(self, incident_id: str) -> float:
        start = self._detection_start.pop(incident_id, None)
        elapsed = (time.time() - start) if start else 0.0
        self.record_metric(
            'detection_time', elapsed, MetricType.TIMER, MetricCategory.PERFORMANCE,
            {'incident_id': incident_id}, 'Detection duration (s)'
        )
        return elapsed

    def record_response_start(self, incident_id: str) -> None:
        self._response_start[incident_id] = time.time()
        self.record_metric(
            'response_started', 1, MetricType.COUNTER, MetricCategory.PERFORMANCE,
            {'incident_id': incident_id}, 'Response started'
        )

    def record_response_end(self, incident_id: str, success: bool) -> float:
        start = self._response_start.pop(incident_id, None)
        elapsed = (time.time() - start) if start else 0.0
        self.record_metric(
            'response_time', elapsed, MetricType.TIMER, MetricCategory.PERFORMANCE,
            {'incident_id': incident_id, 'success': str(success).lower()}, 'Response duration (s)'
        )
        self.record_metric(
            'response_outcome', 1, MetricType.COUNTER, MetricCategory.PERFORMANCE,
            {'incident_id': incident_id, 'success': str(success).lower()}, 'Response outcome'
        )
        return elapsed

    # --- Summaries and exports ---
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Return a compact summary with compliance status and uptime."""
        # Aggregate last known values for key timers
        def last_value(key: str) -> Optional[float]:
            dq = self.metrics_storage.get(f"{MetricCategory.PERFORMANCE.value}.{key}")
            if dq:
                return dq[-1].value
            return None

        detection_time = last_value('detection_time') or 0.0
        response_time = last_value('response_time') or 0.0
        uptime = (datetime.now() - self.collection_start_time).total_seconds()
        summary = {
            'system_uptime': uptime,
            'last_detection_time': detection_time,
            'last_response_time': response_time,
            'total_incidents': len([m for k, dq in self.metrics_storage.items() if k.endswith('response_outcome') for m in dq if m.value == 1]),
        }
        # Compliance check vs targets
        summary['compliance_status'] = {
            'detection_under_1min': detection_time < self.performance_targets['detection_time_target'],
            'response_under_5min': response_time < self.performance_targets['response_time_target'],
        }
        return summary

    def export_metrics(self, format_type: str = 'prometheus') -> str:
        """Export collected metrics in the requested format (prometheus only)."""
        if format_type != 'prometheus':
            raise ValueError('Only prometheus export is supported')
        # Build simple Prometheus text exposition
        lines: List[str] = []
        emitted = set()
        for key, dq in self.metrics_storage.items():
            # convert key to metric name
            category, name = key.split('.', 1)
            metric_name = f"soar_{category}_{name}".replace('.', '_')
            # help/type (emit once)
            if metric_name not in emitted:
                lines.append(f"# HELP {metric_name} SOAR metric {name}")
                # Determine type from latest sample
                mtype = (dq[-1].metric_type.value if dq else 'gauge')
                prom_type = 'counter' if mtype == 'counter' else 'gauge'
                lines.append(f"# TYPE {metric_name} {prom_type}")
                emitted.add(metric_name)
            # output last sample only (keep it light)
            if dq:
                sample = dq[-1]
                # render tags as labels
                labels = ''
                if sample.tags:
                    label_parts = [f"{k}='{v}'" for k, v in sample.tags.items()]
                    labels = '{' + ','.join(label_parts) + '}'
                lines.append(f"{metric_name}{labels} {sample.value}")
        return "\n".join(lines) + "\n"
    
    def record_metric(
        self,
        name: str,
        value: float,
        metric_type: MetricType = MetricType.GAUGE,
        category: MetricCategory = MetricCategory.SYSTEM,
        tags: Optional[Dict[str, str]] = None,
        description: str = ""
    ) -> None:
        """Record a single metric"""
        if tags is None:
            tags = {}
        
        metric = Metric(
            name=name,
            value=value,
            metric_type=metric_type,
            category=category,
            timestamp=datetime.now(),
            tags=tags,
            description=description
        )
        
        # Store metric
        metric_key = f"{category.value}.{name}"
        self.metrics_storage[metric_key].append(metric)
        
        # Maintain history size limit
        if len(self.metrics_storage[metric_key]) > self.max_history_size:
            self.metrics_storage[metric_key].popleft()
        
        # Store metadata
        self.metric_metadata[metric_key] = {
            'type': metric_type.value,
            'category': category.value,
            'description': description,
            'last_updated': metric.timestamp.isoformat()
        }
        
        # Check for threshold violations
        self._check_thresholds(name, value, tags)
        
        logger.debug(f"Recorded metric: {metric_key} = {value}")
    
    def record_performance_metrics(self, performance_data: PerformanceMetrics, incident_id: str) -> None:
        """Record comprehensive performance metrics for an incident"""
        tags = {'incident_id': incident_id}
        
        # Detection metrics
        self.record_metric(
            'detection_time',
            performance_data.detection_time,
            MetricType.TIMER,
            MetricCategory.PERFORMANCE,
            tags,
            "Time taken to detect the threat"
        )
        
        self.record_metric(
            'detection_accuracy',
            performance_data.detection_accuracy,
            MetricType.GAUGE,
            MetricCategory.PERFORMANCE,
            tags,
            "Accuracy of threat detection"
        )
        
        # Analysis metrics
        self.record_metric(
            'analysis_time',
            performance_data.analysis_time,
            MetricType.TIMER,
            MetricCategory.PERFORMANCE,
            tags,
            "Time taken to analyze the incident"
        )
        
        # Response metrics
        self.record_metric(
            'response_time',
            performance_data.response_time,
            MetricType.TIMER,
            MetricCategory.PERFORMANCE,
            tags,
            "Time taken to execute response"
        )
        
        self.record_metric(
            'response_success_rate',
            performance_data.response_success_rate,
            MetricType.GAUGE,
            MetricCategory.PERFORMANCE,
            tags,
            "Success rate of response actions"
        )
        
        # Prediction metrics
        self.record_metric(
            'prediction_time',
            performance_data.prediction_time,
            MetricType.TIMER,
            MetricCategory.PERFORMANCE,
            tags,
            "Time taken to generate predictions"
        )
        
        self.record_metric(
            'prediction_accuracy',
            performance_data.prediction_accuracy,
            MetricType.GAUGE,
            MetricCategory.PERFORMANCE,
            tags,
            "Accuracy of threat predictions"
        )
        
        # Overall metrics
        self.record_metric(
            'total_processing_time',
            performance_data.total_processing_time,
            MetricType.TIMER,
            MetricCategory.PERFORMANCE,
            tags,
            "Total time to process incident"
        )
        
        # Count metrics
        self.record_metric(
            'incidents_processed',
            performance_data.incidents_processed,
            MetricType.COUNTER,
            MetricCategory.BUSINESS,
            tags,
            "Number of incidents processed"
        )
        
        self.record_metric(
            'threats_detected',
            performance_data.threats_detected,
            MetricType.COUNTER,
            MetricCategory.SECURITY,
            tags,
            "Number of threats detected"
        )
        
        self.record_metric(
            'responses_executed',
            performance_data.responses_executed,
            MetricType.COUNTER,
            MetricCategory.BUSINESS,
            tags,
            "Number of response actions executed"
        )
        
        self.record_metric(
            'predictions_generated',
            performance_data.predictions_generated,
            MetricType.COUNTER,
            MetricCategory.BUSINESS,
            tags,
            "Number of predictions generated"
        )
    
    def record_system_metrics(self) -> None:
        """Record system health and resource metrics"""
        current_time = datetime.now()
        
        # Simulate system metrics (in production, these would come from actual system monitoring)
        import psutil
        import random
        
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            self.record_metric(
                'cpu_usage_percent',
                cpu_percent,
                MetricType.GAUGE,
                MetricCategory.SYSTEM,
                {'host': 'soar_system'},
                "CPU usage percentage"
            )
            
            # Memory metrics
            memory = psutil.virtual_memory()
            self.record_metric(
                'memory_usage_percent',
                memory.percent,
                MetricType.GAUGE,
                MetricCategory.SYSTEM,
                {'host': 'soar_system'},
                "Memory usage percentage"
            )
            
            self.record_metric(
                'memory_available_bytes',
                memory.available,
                MetricType.GAUGE,
                MetricCategory.SYSTEM,
                {'host': 'soar_system'},
                "Available memory in bytes"
            )
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            self.record_metric(
                'disk_usage_percent',
                (disk.used / disk.total) * 100,
                MetricType.GAUGE,
                MetricCategory.SYSTEM,
                {'host': 'soar_system'},
                "Disk usage percentage"
            )
            
        except ImportError:
            # Fallback to simulated metrics if psutil is not available
            self.record_metric(
                'cpu_usage_percent',
                random.uniform(20, 80),
                MetricType.GAUGE,
                MetricCategory.SYSTEM,
                {'host': 'soar_system'},
                "CPU usage percentage (simulated)"
            )
            
            self.record_metric(
                'memory_usage_percent',
                random.uniform(50, 85),
                MetricType.GAUGE,
                MetricCategory.SYSTEM,
                {'host': 'soar_system'},
                "Memory usage percentage (simulated)"
            )
        
        # Application-specific metrics
        uptime_seconds = (current_time - self.collection_start_time).total_seconds()
        self.record_metric(
            'system_uptime_seconds',
            uptime_seconds,
            MetricType.GAUGE,
            MetricCategory.SYSTEM,
            {'component': 'soar_main'},
            "System uptime in seconds"
        )
        
        # Queue and processing metrics
        self.record_metric(
            'metrics_queue_size',
            sum(len(queue) for queue in self.metrics_storage.values()),
            MetricType.GAUGE,
            MetricCategory.SYSTEM,
            {'component': 'metrics_collector'},
            "Number of metrics in storage"
        )
    
    def record_security_metrics(self, threats_blocked: int, false_positives: int, false_negatives: int) -> None:
        """Record security-specific metrics"""
        
        # Threat detection metrics
        self.record_metric(
            'threats_blocked_total',
            threats_blocked,
            MetricType.COUNTER,
            MetricCategory.SECURITY,
            {'action': 'blocked'},
            "Total number of threats blocked"
        )
        
        self.record_metric(
            'false_positives_total',
            false_positives,
            MetricType.COUNTER,
            MetricCategory.SECURITY,
            {'classification': 'false_positive'},
            "Total number of false positive detections"
        )
        
        self.record_metric(
            'false_negatives_total',
            false_negatives,
            MetricType.COUNTER,
            MetricCategory.SECURITY,
            {'classification': 'false_negative'},
            "Total number of false negative detections"
        )
        
        # Calculate derived security metrics
        total_detections = threats_blocked + false_positives
        if total_detections > 0:
            false_positive_rate = false_positives / total_detections
            self.record_metric(
                'false_positive_rate',
                false_positive_rate,
                MetricType.GAUGE,
                MetricCategory.SECURITY,
                {'metric_type': 'derived'},
                "False positive rate (FP / (TP + FP))"
            )
        
        # Security posture score (simplified calculation)
        posture_score = max(0.0, 1.0 - (false_positives * 0.1 + false_negatives * 0.2) / max(1, threats_blocked))
        self.record_metric(
            'security_posture_score',
            posture_score,
            MetricType.GAUGE,
            MetricCategory.SECURITY,
            {'metric_type': 'composite'},
            "Overall security posture score"
        )
    
    def record_error_metrics(self, component: str, error_type: str, error_count: int = 1) -> None:
        """Record error and exception metrics"""
        tags = {
            'component': component,
            'error_type': error_type
        }
        
        self.record_metric(
            'error_count',
            error_count,
            MetricType.COUNTER,
            MetricCategory.ERROR,
            tags,
            f"Error count for {component}"
        )
        
        # Calculate error rate
        component_metrics = self._get_metrics_by_component(component)
        total_operations = len(component_metrics)
        
        if total_operations > 0:
            error_rate = error_count / total_operations
            self.record_metric(
                'error_rate',
                error_rate,
                MetricType.GAUGE,
                MetricCategory.ERROR,
                tags,
                f"Error rate for {component}"
            )
    
    def get_metrics_summary(self, time_window: Optional[timedelta] = None) -> Dict[str, Any]:
        """Get comprehensive metrics summary"""
        if time_window is None:
            time_window = timedelta(hours=1)  # Default to last hour
        
        cutoff_time = datetime.now() - time_window
        summary = {
            'collection_period': {
                'start_time': cutoff_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration_seconds': time_window.total_seconds()
            },
            'performance_summary': {},
            'security_summary': {},
            'system_summary': {},
            'error_summary': {},
            'compliance_status': {},
            'trends': {},
            'alerts': []
        }
        
        # Performance summary
        summary['performance_summary'] = self._calculate_performance_summary(cutoff_time)
        
        # Security summary
        summary['security_summary'] = self._calculate_security_summary(cutoff_time)
        
        # System summary
        summary['system_summary'] = self._calculate_system_summary(cutoff_time)
        
        # Error summary
        summary['error_summary'] = self._calculate_error_summary(cutoff_time)
        
        # Compliance status against targets
        summary['compliance_status'] = self._calculate_compliance_status(cutoff_time)
        
        # Trend analysis
        summary['trends'] = self._calculate_trends(cutoff_time)
        
        # Active alerts
        summary['alerts'] = self._get_active_alerts()
        
        return summary
    
    def _calculate_performance_summary(self, cutoff_time: datetime) -> Dict[str, Any]:
        """Calculate performance metrics summary"""
        performance_metrics = [
            'detection_time', 'analysis_time', 'response_time', 'prediction_time',
            'total_processing_time', 'detection_accuracy', 'response_success_rate',
            'prediction_accuracy'
        ]
        
        summary = {}
        for metric_name in performance_metrics:
            metric_key = f"performance.{metric_name}"
            recent_metrics = self._get_recent_metrics(metric_key, cutoff_time)
            
            if recent_metrics:
                values = [m.value for m in recent_metrics]
                summary[metric_name] = {
                    'count': len(values),
                    'mean': sum(values) / len(values),
                    'min': min(values),
                    'max': max(values),
                    'latest': values[-1] if values else 0,
                    'target': self.performance_targets.get(f"{metric_name}_target"),
                    'target_compliance': self._check_target_compliance(metric_name, values[-1] if values else 0)
                }
        
        return summary
    
    def _calculate_security_summary(self, cutoff_time: datetime) -> Dict[str, Any]:
        """Calculate security metrics summary"""
        security_metrics = [
            'threats_blocked_total', 'false_positives_total', 'false_negatives_total',
            'false_positive_rate', 'security_posture_score'
        ]
        
        summary = {}
        for metric_name in security_metrics:
            metric_key = f"security.{metric_name}"
            recent_metrics = self._get_recent_metrics(metric_key, cutoff_time)
            
            if recent_metrics:
                values = [m.value for m in recent_metrics]
                if 'total' in metric_name:
                    # For counters, sum the values
                    summary[metric_name] = {
                        'total': sum(values),
                        'rate_per_hour': sum(values) / (len(recent_metrics) * 24),  # Approximate
                        'latest': values[-1] if values else 0
                    }
                else:
                    # For rates and scores, use statistical measures
                    summary[metric_name] = {
                        'mean': sum(values) / len(values),
                        'latest': values[-1] if values else 0,
                        'trend': 'improving' if len(values) > 1 and values[-1] < values[0] else 'stable'
                    }
        
        return summary
    
    def _calculate_system_summary(self, cutoff_time: datetime) -> Dict[str, Any]:
        """Calculate system health summary"""
        system_metrics = [
            'cpu_usage_percent', 'memory_usage_percent', 'disk_usage_percent',
            'system_uptime_seconds', 'metrics_queue_size'
        ]
        
        summary = {}
        for metric_name in system_metrics:
            metric_key = f"system.{metric_name}"
            recent_metrics = self._get_recent_metrics(metric_key, cutoff_time)
            
            if recent_metrics:
                values = [m.value for m in recent_metrics]
                summary[metric_name] = {
                    'current': values[-1] if values else 0,
                    'average': sum(values) / len(values),
                    'peak': max(values),
                    'status': self._determine_system_status(metric_name, values[-1] if values else 0)
                }
        
        return summary
    
    def _calculate_error_summary(self, cutoff_time: datetime) -> Dict[str, Any]:
        """Calculate error metrics summary"""
        error_metrics = self._get_metrics_by_category(MetricCategory.ERROR, cutoff_time)
        
        summary = {
            'total_errors': 0,
            'error_rate': 0.0,
            'errors_by_component': {},
            'errors_by_type': {},
            'critical_errors': []
        }
        
        for metric in error_metrics:
            summary['total_errors'] += metric.value
            
            # Group by component
            component = metric.tags.get('component', 'unknown')
            if component not in summary['errors_by_component']:
                summary['errors_by_component'][component] = 0
            summary['errors_by_component'][component] += metric.value
            
            # Group by error type
            error_type = metric.tags.get('error_type', 'unknown')
            if error_type not in summary['errors_by_type']:
                summary['errors_by_type'][error_type] = 0
            summary['errors_by_type'][error_type] += metric.value
            
            # Identify critical errors
            if metric.value > 10:  # Arbitrary threshold for critical errors
                summary['critical_errors'].append({
                    'component': component,
                    'error_type': error_type,
                    'count': metric.value,
                    'timestamp': metric.timestamp.isoformat()
                })
        
        # Calculate overall error rate
        total_operations = len(self._get_all_recent_metrics(cutoff_time))
        if total_operations > 0:
            summary['error_rate'] = summary['total_errors'] / total_operations
        
        return summary
    
    def _calculate_compliance_status(self, cutoff_time: datetime) -> Dict[str, Any]:
        """Calculate compliance status against performance targets"""
        compliance = {
            'overall_compliance_score': 0.0,
            'targets_met': 0,
            'targets_total': 0,
            'compliance_details': {}
        }
        
        for target_name, target_value in self.performance_targets.items():
            metric_name = target_name.replace('_target', '')
            category = 'performance'  # Most targets are performance-related
            
            metric_key = f"{category}.{metric_name}"
            recent_metrics = self._get_recent_metrics(metric_key, cutoff_time)
            
            if recent_metrics:
                latest_value = recent_metrics[-1].value
                is_compliant = self._check_target_compliance(metric_name, latest_value)
                
                compliance['compliance_details'][metric_name] = {
                    'target': target_value,
                    'current': latest_value,
                    'compliant': is_compliant,
                    'variance': ((latest_value - target_value) / target_value) * 100 if target_value != 0 else 0
                }
                
                compliance['targets_total'] += 1
                if is_compliant:
                    compliance['targets_met'] += 1
        
        # Calculate overall compliance score
        if compliance['targets_total'] > 0:
            compliance['overall_compliance_score'] = compliance['targets_met'] / compliance['targets_total']
        
        return compliance
    
    def _calculate_trends(self, cutoff_time: datetime) -> Dict[str, Any]:
        """Calculate metric trends over time"""
        trends = {}
        
        key_metrics = [
            'performance.detection_time',
            'performance.response_time',
            'performance.detection_accuracy',
            'security.false_positive_rate',
            'system.cpu_usage_percent',
            'system.memory_usage_percent'
        ]
        
        for metric_key in key_metrics:
            recent_metrics = self._get_recent_metrics(metric_key, cutoff_time)
            
            if len(recent_metrics) >= 2:
                values = [m.value for m in recent_metrics]
                
                # Simple trend calculation (slope of linear regression)
                n = len(values)
                x_values = list(range(n))
                
                # Calculate trend
                x_mean = sum(x_values) / n
                y_mean = sum(values) / n
                
                numerator = sum((x_values[i] - x_mean) * (values[i] - y_mean) for i in range(n))
                denominator = sum((x_values[i] - x_mean) ** 2 for i in range(n))
                
                if denominator != 0:
                    slope = numerator / denominator
                    trend_direction = 'increasing' if slope > 0.1 else 'decreasing' if slope < -0.1 else 'stable'
                else:
                    slope = 0
                    trend_direction = 'stable'
                
                trends[metric_key.replace('.', '_')] = {
                    'direction': trend_direction,
                    'slope': slope,
                    'start_value': values[0],
                    'end_value': values[-1],
                    'change_percent': ((values[-1] - values[0]) / values[0]) * 100 if values[0] != 0 else 0
                }
        
        return trends
    
    def _get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get currently active alerts based on threshold violations"""
        alerts = []
        
        for metric_name, thresholds in self.alert_thresholds.items():
            # Find the appropriate metric key
            metric_key = None
            for category in ['performance', 'security', 'system', 'error']:
                potential_key = f"{category}.{metric_name}"
                if potential_key in self.metrics_storage:
                    metric_key = potential_key
                    break
            
            if metric_key and self.metrics_storage[metric_key]:
                latest_metric = self.metrics_storage[metric_key][-1]
                current_value = latest_metric.value
                
                # Check thresholds
                if 'critical' in thresholds and self._violates_threshold(metric_name, current_value, thresholds['critical']):
                    alerts.append({
                        'severity': 'critical',
                        'metric': metric_name,
                        'current_value': current_value,
                        'threshold': thresholds['critical'],
                        'timestamp': latest_metric.timestamp.isoformat(),
                        'message': f"{metric_name} has exceeded critical threshold: {current_value} > {thresholds['critical']}"
                    })
                elif 'warning' in thresholds and self._violates_threshold(metric_name, current_value, thresholds['warning']):
                    alerts.append({
                        'severity': 'warning',
                        'metric': metric_name,
                        'current_value': current_value,
                        'threshold': thresholds['warning'],
                        'timestamp': latest_metric.timestamp.isoformat(),
                        'message': f"{metric_name} has exceeded warning threshold: {current_value} > {thresholds['warning']}"
                    })
        
        return alerts
    
    def _check_thresholds(self, metric_name: str, value: float, tags: Dict[str, str]) -> None:
        """Check if metric value violates any thresholds"""
        if metric_name in self.alert_thresholds:
            thresholds = self.alert_thresholds[metric_name]
            
            if 'critical' in thresholds and self._violates_threshold(metric_name, value, thresholds['critical']):
                logger.critical(f"Critical threshold violation: {metric_name} = {value} (threshold: {thresholds['critical']})")
            elif 'warning' in thresholds and self._violates_threshold(metric_name, value, thresholds['warning']):
                logger.warning(f"Warning threshold violation: {metric_name} = {value} (threshold: {thresholds['warning']})")
    
    def _violates_threshold(self, metric_name: str, value: float, threshold: float) -> bool:
        """Check if a value violates a threshold (handles different comparison directions)"""
        # For accuracy metrics, violation is when value is BELOW threshold
        if 'accuracy' in metric_name or 'success_rate' in metric_name:
            return value < threshold
        
        # For most other metrics, violation is when value is ABOVE threshold
        return value > threshold
    
    def _check_target_compliance(self, metric_name: str, value: float) -> bool:
        """Check if metric value meets performance target"""
        target_key = f"{metric_name}_target"
        if target_key not in self.performance_targets:
            return True  # No target defined, assume compliant
        
        target = self.performance_targets[target_key]
        
        # For accuracy and rate metrics, value should be >= target
        if 'accuracy' in metric_name or 'success_rate' in metric_name or 'preservation' in metric_name or 'availability' in metric_name:
            return value >= target
        
        # For time and error rate metrics, value should be <= target
        return value <= target
    
    def _determine_system_status(self, metric_name: str, value: float) -> str:
        """Determine system status based on metric value"""
        if metric_name in self.alert_thresholds:
            thresholds = self.alert_thresholds[metric_name]
            
            if 'critical' in thresholds and self._violates_threshold(metric_name, value, thresholds['critical']):
                return 'critical'
            elif 'warning' in thresholds and self._violates_threshold(metric_name, value, thresholds['warning']):
                return 'warning'
        
        return 'healthy'
    
    def _get_recent_metrics(self, metric_key: str, cutoff_time: datetime) -> List[Metric]:
        """Get metrics for a specific key since cutoff time"""
        if metric_key not in self.metrics_storage:
            return []
        
        return [m for m in self.metrics_storage[metric_key] if m.timestamp >= cutoff_time]
    
    def _get_metrics_by_category(self, category: MetricCategory, cutoff_time: datetime) -> List[Metric]:
        """Get all metrics for a specific category since cutoff time"""
        category_metrics = []
        
        for metric_key, metrics in self.metrics_storage.items():
            if metric_key.startswith(category.value):
                category_metrics.extend([m for m in metrics if m.timestamp >= cutoff_time])
        
        return category_metrics
    
    def _get_metrics_by_component(self, component: str) -> List[Metric]:
        """Get all metrics for a specific component"""
        component_metrics = []
        
        for metrics in self.metrics_storage.values():
            component_metrics.extend([m for m in metrics if m.tags.get('component') == component])
        
        return component_metrics
    
    def _get_all_recent_metrics(self, cutoff_time: datetime) -> List[Metric]:
        """Get all metrics since cutoff time"""
        all_metrics = []
        
        for metrics in self.metrics_storage.values():
            all_metrics.extend([m for m in metrics if m.timestamp >= cutoff_time])
        
        return all_metrics
    
    def export_metrics(self, format_type: str = 'json', time_window: Optional[timedelta] = None) -> str:
        """Export metrics in specified format"""
        if time_window is None:
            time_window = timedelta(hours=24)  # Default to last 24 hours
        
        summary = self.get_metrics_summary(time_window)
        
        if format_type.lower() == 'json':
            return json.dumps(summary, indent=2, default=str)
        elif format_type.lower() == 'prometheus':
            return self._export_prometheus_format(summary)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
    
    def _export_prometheus_format(self, summary: Dict[str, Any]) -> str:
        """Export metrics in Prometheus format"""
        prometheus_lines = []
        
        # Add performance metrics
        performance = summary.get('performance_summary', {})
        for metric_name, metric_data in performance.items():
            if isinstance(metric_data, dict) and 'latest' in metric_data:
                prometheus_lines.append(f"soar_performance_{metric_name} {metric_data['latest']}")
        
        # Add system metrics
        system = summary.get('system_summary', {})
        for metric_name, metric_data in system.items():
            if isinstance(metric_data, dict) and 'current' in metric_data:
                prometheus_lines.append(f"soar_system_{metric_name} {metric_data['current']}")
        
        # Add security metrics
        security = summary.get('security_summary', {})
        for metric_name, metric_data in security.items():
            if isinstance(metric_data, dict) and 'latest' in metric_data:
                prometheus_lines.append(f"soar_security_{metric_name} {metric_data['latest']}")
        
        return '\n'.join(prometheus_lines)
    
    def clear_old_metrics(self, retention_period: timedelta = timedelta(days=7)) -> int:
        """Clear metrics older than retention period"""
        cutoff_time = datetime.now() - retention_period
        total_removed = 0
        
        for metric_key in list(self.metrics_storage.keys()):
            metrics_queue = self.metrics_storage[metric_key]
            original_size = len(metrics_queue)
            
            # Remove old metrics
            while metrics_queue and metrics_queue[0].timestamp < cutoff_time:
                metrics_queue.popleft()
                total_removed += 1
            
            # Remove empty queues
            if not metrics_queue:
                del self.metrics_storage[metric_key]
                if metric_key in self.metric_metadata:
                    del self.metric_metadata[metric_key]
        
        logger.info(f"Cleaned up {total_removed} old metrics (retention: {retention_period})")
        return total_removed
    
    def record_response_start(self, incident_id: str, response_type: str = "automated") -> str:
        """
        Record the start of a response operation
        
        Args:
            incident_id: ID do incidente
            response_type: Tipo de resposta (automated, manual, hybrid)
            
        Returns:
            Response ID para rastreamento
        """
        response_id = f"{incident_id}_{response_type}_{int(time.time())}"
        
        self.record_metric(
            'response_started',
            1,
            MetricType.COUNTER,
            MetricCategory.PERFORMANCE,
            {
                'incident_id': incident_id,
                'response_type': response_type,
                'response_id': response_id
            },
            f"Response started for incident {incident_id}"
        )
        
        # Store start time for response duration calculation
        if not hasattr(self, '_response_start_times'):
            self._response_start_times = {}
        self._response_start_times[response_id] = time.time()
        
        logger.debug(f"Response started: {response_id}")
        return response_id
    
    def record_response_end(self, response_id: str, success: bool = True, actions_executed: int = 0) -> float:
        """
        Record the end of a response operation
        
        Args:
            response_id: ID da resposta (retornado por record_response_start)
            success: Se a resposta foi bem-sucedida
            actions_executed: Número de ações executadas
            
        Returns:
            Response duration in seconds
        """
        end_time = time.time()
        
        # Calculate response duration
        if not hasattr(self, '_response_start_times'):
            self._response_start_times = {}
            
        start_time = self._response_start_times.get(response_id, end_time)
        duration = end_time - start_time
        
        # Extract info from response_id
        parts = response_id.split('_')
        incident_id = '_'.join(parts[:-2]) if len(parts) > 2 else response_id
        response_type = parts[-2] if len(parts) > 2 else "unknown"
        
        tags = {
            'incident_id': incident_id,
            'response_type': response_type,
            'response_id': response_id,
            'success': str(success)
        }
        
        # Record response completion
        self.record_metric(
            'response_completed',
            1,
            MetricType.COUNTER,
            MetricCategory.PERFORMANCE,
            tags,
            f"Response completed for incident {incident_id}"
        )
        
        # Record response duration
        self.record_metric(
            'response_duration',
            duration,
            MetricType.TIMER,
            MetricCategory.PERFORMANCE,
            tags,
            f"Duration of response for incident {incident_id}"
        )
        
        # Record success/failure
        self.record_metric(
            'response_success_rate',
            1.0 if success else 0.0,
            MetricType.GAUGE,
            MetricCategory.PERFORMANCE,
            tags,
            f"Success rate for response {response_id}"
        )
        
        # Record actions executed
        if actions_executed > 0:
            self.record_metric(
                'response_actions_executed',
                actions_executed,
                MetricType.COUNTER,
                MetricCategory.PERFORMANCE,
                tags,
                f"Number of actions executed in response {response_id}"
            )
        
        # Clean up start time
        if response_id in self._response_start_times:
            del self._response_start_times[response_id]
        
        logger.debug(f"Response ended: {response_id}, duration: {duration:.3f}s, success: {success}")
        return duration

    def record_detection_start(self, incident_id: str) -> str:
        """
        Record the start of a detection operation
        
        Args:
            incident_id: ID do incidente
            
        Returns:
            Detection ID para rastreamento
        """
        detection_id = f"{incident_id}_detection_{int(time.time())}"
        
        self.record_metric(
            'detection_started',
            1,
            MetricType.COUNTER,
            MetricCategory.PERFORMANCE,
            {
                'incident_id': incident_id,
                'detection_id': detection_id
            },
            f"Detection started for incident {incident_id}"
        )
        
        # Store start time for detection duration calculation
        if not hasattr(self, '_detection_start_times'):
            self._detection_start_times = {}
        self._detection_start_times[incident_id] = time.time()
        
        logger.debug(f"Detection started: {detection_id}")
        return detection_id

    def record_detection_end(self, incident_id: str, success: bool = True) -> float:
        """
        Record the end of a detection operation
        
        Args:
            incident_id: ID do incidente
            success: Se a detecção foi bem-sucedida
            
        Returns:
            Detection duration in seconds
        """
        end_time = time.time()
        
        # Calculate detection duration
        if not hasattr(self, '_detection_start_times'):
            self._detection_start_times = {}
            
        start_time = self._detection_start_times.get(incident_id, end_time)
        duration = end_time - start_time
        
        tags = {
            'incident_id': incident_id,
            'success': str(success)
        }
        
        # Record detection completion
        self.record_metric(
            'detection_completed',
            1,
            MetricType.COUNTER,
            MetricCategory.PERFORMANCE,
            tags,
            f"Detection completed for incident {incident_id}"
        )
        
        # Record detection duration
        self.record_metric(
            'detection_duration',
            duration,
            MetricType.TIMER,
            MetricCategory.PERFORMANCE,
            tags,
            f"Duration of detection for incident {incident_id}"
        )
        
        # Record success/failure
        self.record_metric(
            'detection_success_rate',
            1.0 if success else 0.0,
            MetricType.GAUGE,
            MetricCategory.PERFORMANCE,
            tags,
            f"Success rate for detection {incident_id}"
        )
        
        # Clean up start time
        if incident_id in self._detection_start_times:
            del self._detection_start_times[incident_id]
        
        logger.debug(f"Detection ended: {incident_id}, duration: {duration:.3f}s, success: {success}")
        return duration
