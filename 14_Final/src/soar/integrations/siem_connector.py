"""
SIEM Integration using Elasticsearch
Provides comprehensive SIEM capabilities for the SOAR system
"""

import asyncio
import aiohttp
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
import hashlib

logger = logging.getLogger(__name__)

class SIEMConnector:
    """
    SIEM Connector for Elasticsearch integration
    
    Provides comprehensive SIEM capabilities including:
    - Incident logging and storage
    - Historical data analysis
    - Threat pattern detection
    - Alert management
    - Dashboard data generation
    """
    
    def __init__(self, elasticsearch_url: str = "http://localhost:9200"):
        """
        Initialize SIEM connector with Elasticsearch
        
        Args:
            elasticsearch_url: Elasticsearch endpoint URL
        """
        self.elasticsearch_url = elasticsearch_url.rstrip('/')
        self.session = None
        self.logger = logger
        self.initialized = False
        
    async def initialize(self) -> bool:
        """Initialize SIEM connector and test connection"""
        try:
            self.session = aiohttp.ClientSession()
            
            # Test Elasticsearch connection
            async with self.session.get(f"{self.elasticsearch_url}/_cluster/health") as response:
                if response.status == 200:
                    health_data = await response.json()
                    self.logger.info(f"Connected to Elasticsearch cluster: {health_data.get('cluster_name', 'unknown')}")
                    
                    # Create index templates for SOAR data
                    await self._create_index_templates()
                    
                    self.initialized = True
                    self.logger.info("SIEM connector initialized successfully")
                    return True
                else:
                    self.logger.error(f"Elasticsearch health check failed: {response.status}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Failed to initialize SIEM connector: {e}")
            return False
    
    async def _create_index_templates(self):
        """Create index templates for SOAR data structure"""
        try:
            # Template for incidents
            incident_template = {
                "index_patterns": ["soar-incidents-*"],
                "template": {
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 0
                    },
                    "mappings": {
                        "properties": {
                            "timestamp": {"type": "date"},
                            "incident_id": {"type": "keyword"},
                            "incident_type": {"type": "keyword"},
                            "severity": {"type": "keyword"},
                            "status": {"type": "keyword"},
                            "source_ip": {"type": "ip"},
                            "destination_ip": {"type": "ip"},
                            "description": {"type": "text"},
                            "risk_score": {"type": "float"},
                            "detection_time": {"type": "float"},
                            "response_time": {"type": "float"},
                            "actions_taken": {"type": "keyword"},
                            "source": {"type": "keyword"}
                        }
                    }
                }
            }
            
            # Template for alerts
            alert_template = {
                "index_patterns": ["soar-alerts-*"],
                "template": {
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 0
                    },
                    "mappings": {
                        "properties": {
                            "timestamp": {"type": "date"},
                            "alert_type": {"type": "keyword"},
                            "severity": {"type": "keyword"},
                            "message": {"type": "text"},
                            "source": {"type": "keyword"},
                            "incident_id": {"type": "keyword"},
                            "details": {"type": "object"}
                        }
                    }
                }
            }
            
            # Template for metrics
            metrics_template = {
                "index_patterns": ["soar-metrics-*"],
                "template": {
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 0
                    },
                    "mappings": {
                        "properties": {
                            "timestamp": {"type": "date"},
                            "metric_type": {"type": "keyword"},
                            "metric_name": {"type": "keyword"},
                            "value": {"type": "float"},
                            "unit": {"type": "keyword"},
                            "incident_id": {"type": "keyword"},
                            "component": {"type": "keyword"}
                        }
                    }
                }
            }
            
            # Apply templates
            for template_name, template_body in [
                ("soar-incidents", incident_template),
                ("soar-alerts", alert_template),
                ("soar-metrics", metrics_template)
            ]:
                async with self.session.put(
                    f"{self.elasticsearch_url}/_index_template/{template_name}",
                    json=template_body
                ) as response:
                    if response.status in [200, 201]:
                        self.logger.info(f"Created index template: {template_name}")
                    else:
                        self.logger.warning(f"Failed to create template {template_name}: {response.status}")
                        
        except Exception as e:
            self.logger.error(f"Failed to create index templates: {e}")
    
    async def send_incident_to_siem(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send incident data to SIEM (Elasticsearch)
        
        Args:
            incident_data: Incident information dictionary
            
        Returns:
            Result dictionary with success status and SIEM document ID
        """
        try:
            if not self.initialized:
                raise Exception("SIEM connector not initialized")
            
            # Prepare incident document for Elasticsearch
            doc = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "incident_id": incident_data.get("id"),
                "incident_type": incident_data.get("incident_type"),
                "severity": incident_data.get("severity"),
                "status": incident_data.get("status", "detected"),
                "source_ip": incident_data.get("source_ip"),
                "destination_ip": incident_data.get("destination_ip"),
                "description": incident_data.get("description", ""),
                "risk_score": float(incident_data.get("risk_score", 0.0)),
                "detection_time": float(incident_data.get("detection_time", 0.0)),
                "response_time": float(incident_data.get("response_time", 0.0)),
                "actions_taken": incident_data.get("actions_taken", []),
                "analysis_results": incident_data.get("analysis_results"),
                "predictions": incident_data.get("predictions"),
                "source": "SOAR-System",
                "host": incident_data.get("host", "unknown"),
                "user": incident_data.get("user", "unknown"),
                "process": incident_data.get("process", "unknown"),
                "file_path": incident_data.get("file_path", ""),
                "command_line": incident_data.get("command_line", ""),
                "parent_process": incident_data.get("parent_process", ""),
                "network_connections": incident_data.get("network_connections", []),
                "registry_changes": incident_data.get("registry_changes", []),
                "file_changes": incident_data.get("file_changes", [])
            }
            
            # Generate document ID based on incident ID
            doc_id = hashlib.md5(str(incident_data.get("id", "")).encode()).hexdigest()
            
            # Index the document in Elasticsearch
            index_name = f"soar-incidents-{datetime.now().strftime('%Y-%m')}"
            
            async with self.session.put(
                f"{self.elasticsearch_url}/{index_name}/_doc/{doc_id}",
                json=doc
            ) as response:
                if response.status in [200, 201]:
                    result_data = await response.json()
                    
                    self.logger.info(f"Incident {incident_data.get('id')} sent to SIEM")
                    
                    return {
                        "success": True,
                        "siem_id": result_data["_id"],
                        "index": result_data["_index"],
                        "incident_id": incident_data.get("id"),
                        "version": result_data.get("_version", 1)
                    }
                else:
                    error_text = await response.text()
                    raise Exception(f"Elasticsearch returned {response.status}: {error_text}")
            
        except Exception as e:
            self.logger.error(f"Failed to send incident to SIEM: {e}")
            return {
                "success": False,
                "error": str(e),
                "incident_id": incident_data.get("id")
            }
    
    async def send_alert_to_siem(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send alert to SIEM
        
        Args:
            alert_data: Alert information dictionary
            
        Returns:
            Result dictionary with success status and alert ID
        """
        try:
            if not self.initialized:
                raise Exception("SIEM connector not initialized")
            
            doc = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alert_type": alert_data.get("type", "security_alert"),
                "severity": alert_data.get("severity", "medium"),
                "message": alert_data.get("message", ""),
                "source": alert_data.get("source", "SOAR"),
                "details": alert_data.get("details", {}),
                "incident_id": alert_data.get("incident_id"),
                "component": alert_data.get("component", "unknown"),
                "action": alert_data.get("action", "alert"),
                "target": alert_data.get("target", ""),
                "result": alert_data.get("result", "unknown")
            }
            
            index_name = f"soar-alerts-{datetime.now().strftime('%Y-%m')}"
            
            async with self.session.post(
                f"{self.elasticsearch_url}/{index_name}/_doc",
                json=doc
            ) as response:
                if response.status in [200, 201]:
                    result_data = await response.json()
                    
                    self.logger.info(f"Alert sent to SIEM: {alert_data.get('type')}")
                    
                    return {
                        "success": True,
                        "alert_id": result_data["_id"],
                        "index": result_data["_index"]
                    }
                else:
                    error_text = await response.text()
                    raise Exception(f"Elasticsearch returned {response.status}: {error_text}")
            
        except Exception as e:
            self.logger.error(f"Failed to send alert to SIEM: {e}")
            return {"success": False, "error": str(e)}
    
    async def send_metrics_to_siem(self, metrics_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send performance metrics to SIEM
        
        Args:
            metrics_data: Metrics information dictionary
            
        Returns:
            Result dictionary with success status
        """
        try:
            if not self.initialized:
                raise Exception("SIEM connector not initialized")
            
            doc = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metric_type": metrics_data.get("type", "performance"),
                "metric_name": metrics_data.get("name"),
                "value": float(metrics_data.get("value", 0.0)),
                "unit": metrics_data.get("unit", "count"),
                "incident_id": metrics_data.get("incident_id"),
                "component": metrics_data.get("component", "system"),
                "threshold": metrics_data.get("threshold"),
                "status": metrics_data.get("status", "normal")
            }
            
            index_name = f"soar-metrics-{datetime.now().strftime('%Y-%m')}"
            
            async with self.session.post(
                f"{self.elasticsearch_url}/{index_name}/_doc",
                json=doc
            ) as response:
                if response.status in [200, 201]:
                    return {"success": True}
                else:
                    error_text = await response.text()
                    raise Exception(f"Elasticsearch returned {response.status}: {error_text}")
            
        except Exception as e:
            self.logger.error(f"Failed to send metrics to SIEM: {e}")
            return {"success": False, "error": str(e)}
    
    async def query_siem_logs(self, query: str, time_range: str = "1h", 
                             size: int = 100, index_pattern: str = "soar-*") -> Dict[str, Any]:
        """
        Query SIEM for historical data
        
        Args:
            query: Elasticsearch query string
            time_range: Time range for search (e.g., "1h", "24h", "7d")
            size: Maximum number of results
            index_pattern: Index pattern to search
            
        Returns:
            Query results dictionary
        """
        try:
            if not self.initialized:
                raise Exception("SIEM connector not initialized")
            
            # Build Elasticsearch query
            search_query = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "query_string": {
                                    "query": query
                                }
                            },
                            {
                                "range": {
                                    "timestamp": {
                                        "gte": f"now-{time_range}"
                                    }
                                }
                            }
                        ]
                    }
                },
                "size": size,
                "sort": [
                    {
                        "timestamp": {
                            "order": "desc"
                        }
                    }
                ]
            }
            
            async with self.session.post(
                f"{self.elasticsearch_url}/{index_pattern}/_search",
                json=search_query
            ) as response:
                if response.status == 200:
                    result_data = await response.json()
                    
                    hits = result_data["hits"]["hits"]
                    documents = [hit["_source"] for hit in hits]
                    
                    return {
                        "success": True,
                        "total_hits": result_data["hits"]["total"]["value"],
                        "documents": documents,
                        "query": query,
                        "took_ms": result_data.get("took", 0)
                    }
                else:
                    error_text = await response.text()
                    raise Exception(f"Search failed: {response.status} - {error_text}")
            
        except Exception as e:
            self.logger.error(f"Failed to query SIEM: {e}")
            return {
                "success": False,
                "error": str(e),
                "query": query
            }
    
    async def get_incident_history(self, incident_type: str = None, 
                                  severity: str = None, days: int = 7) -> List[Dict[str, Any]]:
        """
        Get incident history from SIEM
        
        Args:
            incident_type: Filter by incident type
            severity: Filter by severity level
            days: Number of days to look back
            
        Returns:
            List of historical incidents
        """
        try:
            if not self.initialized:
                raise Exception("SIEM connector not initialized")
            
            must_clauses = [
                {
                    "range": {
                        "timestamp": {
                            "gte": f"now-{days}d"
                        }
                    }
                }
            ]
            
            if incident_type:
                must_clauses.append({
                    "term": {"incident_type": incident_type}
                })
            
            if severity:
                must_clauses.append({
                    "term": {"severity": severity}
                })
            
            query = {
                "query": {
                    "bool": {
                        "must": must_clauses
                    }
                },
                "size": 1000,
                "sort": [{"timestamp": {"order": "desc"}}]
            }
            
            async with self.session.post(
                f"{self.elasticsearch_url}/soar-incidents-*/_search",
                json=query
            ) as response:
                if response.status == 200:
                    result_data = await response.json()
                    return [hit["_source"] for hit in result_data["hits"]["hits"]]
                else:
                    self.logger.error(f"Failed to get incident history: {response.status}")
                    return []
            
        except Exception as e:
            self.logger.error(f"Failed to get incident history: {e}")
            return []
    
    async def get_threat_patterns(self, source_ip: str = None, 
                                 days: int = 30) -> Dict[str, Any]:
        """
        Analyze threat patterns from SIEM data
        
        Args:
            source_ip: Filter by specific source IP
            days: Number of days to analyze
            
        Returns:
            Threat pattern analysis results
        """
        try:
            if not self.initialized:
                raise Exception("SIEM connector not initialized")
            
            # Build aggregation query to find patterns
            must_clauses = [
                {
                    "range": {
                        "timestamp": {
                            "gte": f"now-{days}d"
                        }
                    }
                }
            ]
            
            if source_ip:
                must_clauses.append({
                    "term": {"source_ip": source_ip}
                })
            
            agg_query = {
                "size": 0,
                "query": {
                    "bool": {
                        "must": must_clauses
                    }
                },
                "aggs": {
                    "incident_types": {
                        "terms": {
                            "field": "incident_type.keyword",
                            "size": 10
                        }
                    },
                    "source_ips": {
                        "terms": {
                            "field": "source_ip",
                            "size": 20
                        }
                    },
                    "severity_distribution": {
                        "terms": {
                            "field": "severity.keyword"
                        }
                    },
                    "daily_incidents": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "day"
                        }
                    },
                    "hourly_pattern": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "hour"
                        }
                    },
                    "avg_risk_score": {
                        "avg": {
                            "field": "risk_score"
                        }
                    }
                }
            }
            
            async with self.session.post(
                f"{self.elasticsearch_url}/soar-incidents-*/_search",
                json=agg_query
            ) as response:
                if response.status == 200:
                    result_data = await response.json()
                    
                    return {
                        "success": True,
                        "analysis_period_days": days,
                        "patterns": {
                            "top_incident_types": result_data["aggregations"]["incident_types"]["buckets"],
                            "top_source_ips": result_data["aggregations"]["source_ips"]["buckets"],
                            "severity_distribution": result_data["aggregations"]["severity_distribution"]["buckets"],
                            "daily_trend": result_data["aggregations"]["daily_incidents"]["buckets"],
                            "hourly_pattern": result_data["aggregations"]["hourly_pattern"]["buckets"],
                            "average_risk_score": result_data["aggregations"]["avg_risk_score"]["value"]
                        }
                    }
                else:
                    error_text = await response.text()
                    raise Exception(f"Pattern analysis failed: {response.status} - {error_text}")
            
        except Exception as e:
            self.logger.error(f"Failed to analyze threat patterns: {e}")
            return {"success": False, "error": str(e)}
    
    async def create_siem_dashboard_data(self, time_range: str = "24h") -> Dict[str, Any]:
        """
        Create data for SIEM dashboard visualization
        
        Args:
            time_range: Time range for dashboard data
            
        Returns:
            Dashboard data dictionary
        """
        try:
            if not self.initialized:
                raise Exception("SIEM connector not initialized")
            
            # Get comprehensive statistics
            stats_query = {
                "size": 0,
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": f"now-{time_range}"
                        }
                    }
                },
                "aggs": {
                    "total_incidents": {
                        "value_count": {
                            "field": "incident_id.keyword"
                        }
                    },
                    "unique_incidents": {
                        "cardinality": {
                            "field": "incident_id.keyword"
                        }
                    },
                    "severity_breakdown": {
                        "terms": {
                            "field": "severity.keyword"
                        }
                    },
                    "status_breakdown": {
                        "terms": {
                            "field": "status.keyword"
                        }
                    },
                    "avg_response_time": {
                        "avg": {
                            "field": "response_time"
                        }
                    },
                    "avg_detection_time": {
                        "avg": {
                            "field": "detection_time"
                        }
                    },
                    "max_risk_score": {
                        "max": {
                            "field": "risk_score"
                        }
                    },
                    "avg_risk_score": {
                        "avg": {
                            "field": "risk_score"
                        }
                    },
                    "incidents_over_time": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "1h"
                        }
                    }
                }
            }
            
            async with self.session.post(
                f"{self.elasticsearch_url}/soar-incidents-*/_search",
                json=stats_query
            ) as response:
                if response.status == 200:
                    result_data = await response.json()
                    
                    # Also get alert statistics
                    alert_stats = await self._get_alert_statistics(time_range)
                    
                    return {
                        "success": True,
                        "time_range": time_range,
                        "dashboard_data": {
                            "incidents": {
                                "total_events": result_data["aggregations"]["total_incidents"]["value"],
                                "unique_incidents": result_data["aggregations"]["unique_incidents"]["value"],
                                "severity_breakdown": result_data["aggregations"]["severity_breakdown"]["buckets"],
                                "status_breakdown": result_data["aggregations"]["status_breakdown"]["buckets"],
                                "timeline": result_data["aggregations"]["incidents_over_time"]["buckets"]
                            },
                            "performance": {
                                "avg_response_time": result_data["aggregations"]["avg_response_time"]["value"],
                                "avg_detection_time": result_data["aggregations"]["avg_detection_time"]["value"],
                                "max_risk_score": result_data["aggregations"]["max_risk_score"]["value"],
                                "avg_risk_score": result_data["aggregations"]["avg_risk_score"]["value"]
                            },
                            "alerts": alert_stats
                        }
                    }
                else:
                    error_text = await response.text()
                    raise Exception(f"Dashboard data query failed: {response.status} - {error_text}")
            
        except Exception as e:
            self.logger.error(f"Failed to create dashboard data: {e}")
            return {"success": False, "error": str(e)}
    
    async def _get_alert_statistics(self, time_range: str) -> Dict[str, Any]:
        """Get alert statistics for dashboard"""
        try:
            alert_query = {
                "size": 0,
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": f"now-{time_range}"
                        }
                    }
                },
                "aggs": {
                    "total_alerts": {
                        "value_count": {
                            "field": "alert_type.keyword"
                        }
                    },
                    "alert_types": {
                        "terms": {
                            "field": "alert_type.keyword"
                        }
                    },
                    "alert_severity": {
                        "terms": {
                            "field": "severity.keyword"
                        }
                    }
                }
            }
            
            async with self.session.post(
                f"{self.elasticsearch_url}/soar-alerts-*/_search",
                json=alert_query
            ) as response:
                if response.status == 200:
                    result_data = await response.json()
                    return {
                        "total_alerts": result_data["aggregations"]["total_alerts"]["value"],
                        "alert_types": result_data["aggregations"]["alert_types"]["buckets"],
                        "alert_severity": result_data["aggregations"]["alert_severity"]["buckets"]
                    }
                else:
                    return {"total_alerts": 0, "alert_types": [], "alert_severity": []}
        except:
            return {"total_alerts": 0, "alert_types": [], "alert_severity": []}
    
    async def search_similar_incidents(self, incident_data: Dict[str, Any], 
                                      days: int = 30, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Search for similar incidents in SIEM data
        
        Args:
            incident_data: Current incident data to find similarities
            days: Number of days to search back
            limit: Maximum number of similar incidents to return
            
        Returns:
            List of similar incidents
        """
        try:
            if not self.initialized:
                raise Exception("SIEM connector not initialized")
            
            # Build similarity query based on incident characteristics
            should_clauses = []
            
            if incident_data.get("incident_type"):
                should_clauses.append({
                    "term": {"incident_type": incident_data["incident_type"]}
                })
            
            if incident_data.get("source_ip"):
                should_clauses.append({
                    "term": {"source_ip": incident_data["source_ip"]}
                })
            
            if incident_data.get("destination_ip"):
                should_clauses.append({
                    "term": {"destination_ip": incident_data["destination_ip"]}
                })
            
            similarity_query = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "timestamp": {
                                        "gte": f"now-{days}d"
                                    }
                                }
                            }
                        ],
                        "should": should_clauses,
                        "minimum_should_match": 1
                    }
                },
                "size": limit,
                "sort": [
                    {"_score": {"order": "desc"}},
                    {"timestamp": {"order": "desc"}}
                ]
            }
            
            async with self.session.post(
                f"{self.elasticsearch_url}/soar-incidents-*/_search",
                json=similarity_query
            ) as response:
                if response.status == 200:
                    result_data = await response.json()
                    similar_incidents = []
                    
                    for hit in result_data["hits"]["hits"]:
                        incident = hit["_source"]
                        incident["similarity_score"] = hit["_score"]
                        similar_incidents.append(incident)
                    
                    return similar_incidents
                else:
                    self.logger.error(f"Similar incident search failed: {response.status}")
                    return []
            
        except Exception as e:
            self.logger.error(f"Failed to search similar incidents: {e}")
            return []
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Check SIEM health and connectivity
        
        Returns:
            Health status dictionary
        """
        try:
            if not self.session:
                return {
                    "operational": False,
                    "status": "not_initialized",
                    "error": "SIEM connector not initialized"
                }
            
            async with self.session.get(f"{self.elasticsearch_url}/_cluster/health") as response:
                if response.status == 200:
                    health_data = await response.json()
                    
                    return {
                        "operational": True,
                        "status": health_data.get("status", "unknown"),
                        "cluster_name": health_data.get("cluster_name", "unknown"),
                        "number_of_nodes": health_data.get("number_of_nodes", 0),
                        "active_shards": health_data.get("active_shards", 0),
                        "elasticsearch_url": self.elasticsearch_url
                    }
                else:
                    return {
                        "operational": False,
                        "status": "connection_failed",
                        "error": f"HTTP {response.status}"
                    }
                    
        except Exception as e:
            return {
                "operational": False,
                "status": "error",
                "error": str(e)
            }
    
    async def close(self):
        """Close SIEM connector and cleanup resources"""
        if self.session:
            await self.session.close()
            self.session = None
        
        self.initialized = False
        self.logger.info("SIEM connector closed")
