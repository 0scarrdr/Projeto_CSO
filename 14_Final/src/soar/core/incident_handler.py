"""
Main Incident Handler
Implements the core incident handling logic according to assignment requirements

This is the main orchestrator that implements the exact pattern from the assignment:

class IncidentHandler:
    def __init__(self):
        self.detector = ThreatDetector()
        self.analyzer = IncidentAnalyzer()
        self.responder = AutomatedResponder()
        self.predictor = ThreatPredictor()

    async def handle_incident(self, event):
        # Initial detection and classification
        incident = self.detector.classify(event)

        # Parallel processing of response and analysis
        async with asyncio.TaskGroup() as tg:
            response_task = tg.create_task(
                self.responder.execute_playbook(incident)
            )
            analysis_task = tg.create_task(
                self.analyzer.deep_analysis(incident)
            )
            prediction_task = tg.create_task(
                self.predictor.forecast_related_threats(incident)
            )

        return self.compile_results(
            response_task.result(),
            analysis_task.result(),
            prediction_task.result()
        )
"""

import asyncio
import time
from datetime import datetime
from typing import Dict, Any, Optional
import logging

# Import all components as specified in assignment
from ..models.incident import Incident, IncidentType, IncidentSeverity, IncidentStatus
from ..detection.threat_detector import ThreatDetector
from ..analysis.incident_analyzer import IncidentAnalyzer
from ..response.automated_responder import AutomatedResponder
from ..prediction.threat_predictor import ThreatPredictor
from ..utils.metrics import MetricsCollector

logger = logging.getLogger(__name__)

class IncidentHandler:
    """
    Main Incident Handler implementing the exact pattern from assignment
    
    Orchestrates the complete incident response workflow:
    1. Detection and classification
    2. Parallel response and analysis processing
    3. Threat prediction
    4. Results compilation
    """
    
    def __init__(self):
        """Initialize all components as specified in assignment"""
        # Core components from assignment pattern
        self.detector = ThreatDetector()
        self.analyzer = IncidentAnalyzer()
        self.responder = AutomatedResponder()
        self.predictor = ThreatPredictor()
        
        # Metrics collector for performance tracking
        self.metrics = MetricsCollector()
        
        # System state
        self.is_initialized = False
        self.active_incidents = {}
        
        logger.info("IncidentHandler initialized with all core components")
    
    async def initialize(self):
        """Initialize all system components"""
        try:
            logger.info("Initializing SOAR system components...")
            
            # Initialize each component
            await self.detector.initialize()
            await self.analyzer.initialize()
            await self.responder.initialize()
            await self.predictor.initialize()
            await self.metrics.initialize()
            
            self.is_initialized = True
            logger.info("All SOAR components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize SOAR components: {e}")
            raise
    
    async def handle_incident(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main incident handling method implementing EXACT assignment pattern
        
        Args:
            event: Raw security event data
            
        Returns:
            Complete incident processing results
        """
        start_time = time.time()
        incident_id = event.get('id', f"inc_{int(start_time)}")
        
        try:
            logger.info(f"Starting incident handling for event {incident_id}")
            
            # Record detection start time for metrics
            self.metrics.record_detection_start(incident_id)
            
            # STEP 1: Initial detection and classification (as per assignment)
            incident = await self.detector.classify(event)
            
            # Record detection completion
            detection_time = self.metrics.record_detection_end(incident_id)
            incident.processing_metrics['detection_time'] = detection_time
            
            # Update incident status
            incident.update_status(IncidentStatus.DETECTED)
            self.active_incidents[incident.id] = incident
            
            # Record response start time
            self.metrics.record_response_start(incident_id)
            incident.update_status(IncidentStatus.RESPONDING)
            
            # STEP 2: Parallel processing of response and analysis (EXACT assignment pattern)
            async with asyncio.TaskGroup() as tg:
                response_task = tg.create_task(
                    self.responder.execute_playbook(incident)
                )
                analysis_task = tg.create_task(
                    self.analyzer.deep_analysis(incident)
                )
                prediction_task = tg.create_task(
                    self.predictor.forecast_related_threats(incident)
                )
            
            # Record response completion
            response_time = self.metrics.record_response_end(incident_id, True)
            incident.processing_metrics['response_time'] = response_time
            
            # STEP 3: Compile results (as per assignment)
            result = self.compile_results(
                response_task.result(),
                analysis_task.result(), 
                prediction_task.result()
            )
            
            # Calculate total processing time
            total_time = time.time() - start_time
            incident.processing_metrics['total_time'] = total_time
            
            # Update final incident status
            incident.update_status(IncidentStatus.CLOSED)
            
            # Add processing metadata to result
            result.update({
                "success": True,
                "incident_id": incident.id,
                "processing_time": total_time,
                "performance_metrics": {
                    "detection_time": detection_time,
                    "response_time": response_time,
                    "total_time": total_time,
                    "targets_met": {
                        "detection_under_1min": detection_time < 60,
                        "response_under_5min": response_time < 300
                    }
                }
            })
            
            logger.info(f"Incident {incident_id} processed successfully in {total_time:.2f}s")
            return result
            
        except Exception as e:
            # Record failed response
            self.metrics.record_response_end(incident_id, False)
            
            error_time = time.time() - start_time
            logger.error(f"Error handling incident {incident_id}: {e}")
            
            return {
                "success": False,
                "incident_id": incident_id,
                "error": str(e),
                "processing_time": error_time,
                "response": {"status": "failed", "error": str(e)},
                "analysis": {"status": "failed", "error": str(e)},
                "predictions": {"status": "failed", "error": str(e)}
            }
    
    def compile_results(self, response_result: Dict[str, Any], 
                       analysis_result: Dict[str, Any], 
                       prediction_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compile results from all processing components
        
        Args:
            response_result: Results from automated response
            analysis_result: Results from deep analysis
            prediction_result: Results from threat prediction
            
        Returns:
            Compiled results dictionary
        """
        return {
            "response": response_result,
            "analysis": analysis_result,
            "predictions": prediction_result,
            "compiled_at": datetime.now().isoformat(),
            "processing_summary": {
                "response_success": response_result.get("success", False),
                "analysis_success": analysis_result.get("success", False),
                "prediction_success": prediction_result.get("success", False),
                "actions_taken": response_result.get("actions_taken", 0),
                "threats_identified": len(analysis_result.get("threats", [])),
                "future_threats_predicted": len(prediction_result.get("predicted_threats", []))
            }
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Check health of all system components"""
        try:
            if not self.is_initialized:
                return {"operational": False, "reason": "System not initialized"}
            
            # Check each component
            detector_health = await self.detector.health_check()
            analyzer_health = await self.analyzer.health_check()
            responder_health = await self.responder.health_check()
            predictor_health = await self.predictor.health_check()
            
            all_healthy = all([
                detector_health.get("operational", False),
                analyzer_health.get("operational", False),
                responder_health.get("operational", False),
                predictor_health.get("operational", False)
            ])
            
            return {
                "operational": all_healthy,
                "components": {
                    "detector": detector_health,
                    "analyzer": analyzer_health,
                    "responder": responder_health,
                    "predictor": predictor_health
                },
                "active_incidents": len(self.active_incidents),
                "system_initialized": self.is_initialized
            }
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {"operational": False, "error": str(e)}
    
    async def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics"""
        try:
            # Use MetricsCollector summary (sync) in a thread if needed
            return self.metrics.get_metrics_summary()
        except Exception as e:
            logger.error(f"Error getting metrics: {e}")
            return {"error": str(e)}
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get detailed system status"""
        try:
            health = await self.health_check()
            metrics = await self.get_performance_metrics()
            
            return {
                "health": health,
                "metrics": metrics,
                "active_incidents": len(self.active_incidents),
                "system_uptime": metrics.get("system_uptime", 0),
                "total_incidents_processed": metrics.get("total_incidents", 0)
            }
            
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return {"error": str(e)}
    
    async def shutdown(self):
        """Graceful system shutdown"""
        try:
            logger.info("Shutting down SOAR system...")
            
            # Shutdown all components
            await self.detector.shutdown()
            await self.analyzer.shutdown()
            await self.responder.shutdown()
            await self.predictor.shutdown()
            await self.metrics.shutdown()
            
            self.is_initialized = False
            logger.info("SOAR system shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
            raise
