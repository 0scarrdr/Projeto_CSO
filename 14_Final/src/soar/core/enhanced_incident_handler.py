"""
Enhanced Incident Handler with 25 Different Flows Support
Implements specialized handling for different incident scenarios as per assignment requirements
"""

import asyncio
import time
from datetime import datetime
from typing import Dict, Any, Optional, List
import logging
from enum import Enum

# Import base models and components
from ..models.incident import Incident, IncidentType, IncidentSeverity, IncidentStatus
from ..detection.threat_detector import ThreatDetector
from ..analysis.incident_analyzer import IncidentAnalyzer
from ..response.automated_responder import AutomatedResponder
from ..prediction.threat_predictor import ThreatPredictor
from ..utils.metrics import MetricsCollector

logger = logging.getLogger(__name__)

class FlowType(Enum):
    """25 Different flow types based on assignment scenarios"""
    
    KNOWN_MALWARE = "known_malware"
    UNKNOWN_MALWARE = "unknown_malware"
    PHISHING_EMAIL = "phishing_email"
    RANSOMWARE = "ransomware"
    DATA_EXFILTRATION = "data_exfiltration"
    INSIDER_THREAT = "insider_threat"
    DDOS_ATTACK = "ddos_attack"
    POLICY_VIOLATION = "policy_violation"
    SYSTEM_FAILURE = "system_failure"
    SERVICE_DISRUPTION = "service_disruption"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    
    ZERO_DAY_EXPLOIT = "zero_day_exploit"
    APT_CAMPAIGN = "apt_campaign"
    MULTI_VECTOR_ATTACK = "multi_vector_attack"
    SUPPLY_CHAIN_ATTACK = "supply_chain_attack"
    CLOUD_BREACH = "cloud_breach"
    IOT_COMPROMISE = "iot_compromise"
    AI_POISONING = "ai_poisoning"
    CRYPTO_MINING = "crypto_mining"
    SOCIAL_ENGINEERING = "social_engineering"
    PHYSICAL_BREACH = "physical_breach"
    DNS_HIJACKING = "dns_hijacking"
    MAN_IN_MIDDLE = "man_in_middle"
    CASCADE_FAILURE = "cascade_failure"

class FlowConfiguration:
    """Configuration for each specific flow type"""
    
    def __init__(self, flow_type: FlowType):
        self.flow_type = flow_type
        self.priority = self._get_priority()
        self.required_components = self._get_required_components()
        self.processing_strategy = self._get_processing_strategy()
        self.response_urgency = self._get_response_urgency()
        self.analysis_depth = self._get_analysis_depth()
        self.prediction_scope = self._get_prediction_scope()
    
    def _get_priority(self) -> int:
        """Get priority level (1=highest, 5=lowest)"""
        high_priority = [
            FlowType.RANSOMWARE, FlowType.ZERO_DAY_EXPLOIT, FlowType.APT_CAMPAIGN,
            FlowType.DATA_EXFILTRATION, FlowType.MULTI_VECTOR_ATTACK, FlowType.CASCADE_FAILURE
        ]
        medium_high = [
            FlowType.UNKNOWN_MALWARE, FlowType.INSIDER_THREAT, FlowType.DDOS_ATTACK,
            FlowType.SUPPLY_CHAIN_ATTACK, FlowType.CLOUD_BREACH
        ]
        medium = [
            FlowType.KNOWN_MALWARE, FlowType.PHISHING_EMAIL, FlowType.UNAUTHORIZED_ACCESS,
            FlowType.PRIVILEGE_ESCALATION, FlowType.IOT_COMPROMISE
        ]
        
        if self.flow_type in high_priority:
            return 1
        elif self.flow_type in medium_high:
            return 2
        elif self.flow_type in medium:
            return 3
        else:
            return 4
    
    def _get_required_components(self) -> List[str]:
        """Get list of required components for this flow"""
        all_components = ["detector", "analyzer", "responder", "predictor"]
        
        # Some flows might skip certain components
        lightweight_flows = [FlowType.POLICY_VIOLATION, FlowType.SYSTEM_FAILURE]
        if self.flow_type in lightweight_flows:
            return ["detector", "responder"]
        
        return all_components
    
    def _get_processing_strategy(self) -> str:
        """Get processing strategy: parallel, sequential, hybrid"""
        sequential_flows = [
            FlowType.ZERO_DAY_EXPLOIT, FlowType.APT_CAMPAIGN, FlowType.CASCADE_FAILURE
        ]
        
        if self.flow_type in sequential_flows:
            return "sequential"
        else:
            return "parallel"
    
    def _get_response_urgency(self) -> str:
        """Get response urgency: immediate, fast, normal, delayed"""
        immediate = [FlowType.RANSOMWARE, FlowType.DDOS_ATTACK, FlowType.CASCADE_FAILURE]
        fast = [FlowType.ZERO_DAY_EXPLOIT, FlowType.DATA_EXFILTRATION, FlowType.APT_CAMPAIGN]
        
        if self.flow_type in immediate:
            return "immediate"
        elif self.flow_type in fast:
            return "fast"
        else:
            return "normal"
    
    def _get_analysis_depth(self) -> str:
        """Get analysis depth: surface, standard, deep, forensic"""
        forensic = [FlowType.ZERO_DAY_EXPLOIT, FlowType.APT_CAMPAIGN, FlowType.INSIDER_THREAT]
        deep = [FlowType.UNKNOWN_MALWARE, FlowType.MULTI_VECTOR_ATTACK, FlowType.SUPPLY_CHAIN_ATTACK]
        
        if self.flow_type in forensic:
            return "forensic"
        elif self.flow_type in deep:
            return "deep"
        else:
            return "standard"
    
    def _get_prediction_scope(self) -> str:
        """Get prediction scope: local, network, global, tactical"""
        global_scope = [FlowType.APT_CAMPAIGN, FlowType.SUPPLY_CHAIN_ATTACK, FlowType.CASCADE_FAILURE]
        network_scope = [FlowType.MULTI_VECTOR_ATTACK, FlowType.DDOS_ATTACK, FlowType.IOT_COMPROMISE]
        
        if self.flow_type in global_scope:
            return "global"
        elif self.flow_type in network_scope:
            return "network"
        else:
            return "local"

class EnhancedIncidentHandler:
    """
    Enhanced Incident Handler supporting 25 different flows
    Implements specialized processing based on incident type and characteristics
    """
    
    def __init__(self):
        """Initialize enhanced handler with flow-specific capabilities"""
        # Core components from assignment pattern
        self.detector = ThreatDetector()
        self.analyzer = IncidentAnalyzer()
        self.responder = AutomatedResponder()
        self.predictor = ThreatPredictor()
        
        # Enhanced components
        self.metrics = MetricsCollector()
        self.flow_configurations = self._initialize_flow_configurations()
        
        # System state
        self.is_initialized = False
        self.active_incidents = {}
        self.processing_threads = {}
        
        logger.info("EnhancedIncidentHandler initialized with 25 flow support")
    
    def _initialize_flow_configurations(self) -> Dict[FlowType, FlowConfiguration]:
        """Initialize configurations for all 25 flow types"""
        configurations = {}
        for flow_type in FlowType:
            configurations[flow_type] = FlowConfiguration(flow_type)
        return configurations
    
    async def initialize(self):
        """Initialize all system components"""
        try:
            logger.info("Initializing enhanced SOAR system components...")
            
            # Initialize each component
            await self.detector.initialize()
            await self.analyzer.initialize()
            await self.responder.initialize()
            await self.predictor.initialize()
            await self.metrics.initialize()
            
            self.is_initialized = True
            logger.info("All enhanced SOAR components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize enhanced SOAR components: {e}")
            raise
    
    def determine_flow_type(self, event: Dict[str, Any]) -> FlowType:
        """Determine the appropriate flow type based on event characteristics"""
        # Accept both 'event_type' and legacy 'type'
        event_type = (event.get('event_type') or event.get('type') or '').lower()
        event_data = event.get('data', {})
        source = event.get('source', '').lower()
        
        # Map event characteristics to flow types
        if 'ransomware' in event_type or 'ransom' in str(event_data):
            return FlowType.RANSOMWARE
        elif 'phishing' in event_type or 'phish' in str(event_data):
            return FlowType.PHISHING_EMAIL
        elif 'ddos' in event_type or event_data.get('packet_rate', 0) > 50000:
            return FlowType.DDOS_ATTACK
        elif 'exfiltration' in event_type or 'exfil' in event_type:
            return FlowType.DATA_EXFILTRATION
        elif 'insider' in event_type or event_data.get('risk_score', 0) > 0.8:
            return FlowType.INSIDER_THREAT
        elif 'malware' in event_type:
            if event_data.get('malware_family') in ['unknown', 'zero_day']:
                return FlowType.UNKNOWN_MALWARE
            else:
                return FlowType.KNOWN_MALWARE
        elif 'zero_day' in event_type or 'exploit' in event_type:
            return FlowType.ZERO_DAY_EXPLOIT
        elif 'apt' in event_type or 'advanced' in event_type:
            return FlowType.APT_CAMPAIGN
        elif 'multi' in event_type or 'vector' in event_type:
            return FlowType.MULTI_VECTOR_ATTACK
        elif 'supply' in event_type or 'chain' in event_type:
            return FlowType.SUPPLY_CHAIN_ATTACK
        elif 'cloud' in source or 'aws' in source or 'azure' in source:
            return FlowType.CLOUD_BREACH
        elif 'iot' in source or 'device' in event_type:
            return FlowType.IOT_COMPROMISE
        elif 'policy' in event_type or 'violation' in event_type:
            return FlowType.POLICY_VIOLATION
        elif 'failure' in event_type or 'system' in event_type:
            return FlowType.SYSTEM_FAILURE
        elif 'access' in event_type and 'unauthorized' in str(event_data):
            return FlowType.UNAUTHORIZED_ACCESS
        elif 'privilege' in event_type or 'escalation' in event_type:
            return FlowType.PRIVILEGE_ESCALATION
        elif 'service' in event_type and 'disruption' in str(event_data):
            return FlowType.SERVICE_DISRUPTION
        elif 'crypto' in event_type or 'mining' in event_type:
            return FlowType.CRYPTO_MINING
        elif 'social' in event_type or 'engineering' in event_type:
            return FlowType.SOCIAL_ENGINEERING
        elif 'physical' in event_type or 'breach' in source:
            return FlowType.PHYSICAL_BREACH
        elif 'dns' in event_type or 'hijack' in event_type:
            return FlowType.DNS_HIJACKING
        elif 'mitm' in event_type or 'man_in_middle' in event_type:
            return FlowType.MAN_IN_MIDDLE
        elif 'cascade' in event_type or 'chain_failure' in event_type:
            return FlowType.CASCADE_FAILURE
        else:
            # Default to policy violation for unknown types
            return FlowType.POLICY_VIOLATION
    
    async def handle_incident(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enhanced incident handling with flow-specific processing
        
        Args:
            event: Raw security event data
            
        Returns:
            Complete incident processing results with flow information
        """
        start_time = time.time()
        incident_id = event.get('id', f"inc_{int(start_time)}")
        
        try:
            # Determine the appropriate flow type
            flow_type = self.determine_flow_type(event)
            flow_config = self.flow_configurations[flow_type]
            
            logger.info(f"Processing incident {incident_id} using flow: {flow_type.value}")
            logger.info(f"Flow priority: {flow_config.priority}, Strategy: {flow_config.processing_strategy}")
            
            # Record metrics
            self.metrics.record_detection_start(incident_id)
            
            # STEP 1: Enhanced detection and classification
            incident = await self.detector.classify(event)
            incident.flow_type = flow_type.value
            incident.processing_strategy = flow_config.processing_strategy
            
            detection_time = self.metrics.record_detection_end(incident_id)
            incident.processing_metrics['detection_time'] = detection_time
            incident.processing_metrics['flow_type'] = flow_type.value
            
            # Update status
            incident.update_status(IncidentStatus.DETECTED)
            self.active_incidents[incident.id] = incident
            
            # Record response start
            self.metrics.record_response_start(incident_id)
            incident.update_status(IncidentStatus.RESPONDING)
            
            # STEP 2: Flow-specific processing
            if flow_config.processing_strategy == "parallel":
                result = await self._process_parallel(incident, flow_config)
            elif flow_config.processing_strategy == "sequential":
                result = await self._process_sequential(incident, flow_config)
            else:
                result = await self._process_hybrid(incident, flow_config)
            
            # Record completion
            response_time = self.metrics.record_response_end(incident_id, True)
            incident.processing_metrics['response_time'] = response_time
            
            # STEP 3: Compile enhanced results
            final_result = self.compile_results(
                result.get('response', {}),
                result.get('analysis', {}),
                result.get('predictions', {}),
                flow_type,
                flow_config
            )
            
            # Final status update
            incident.update_status(IncidentStatus.RESOLVED)
            total_time = time.time() - start_time
            
            logger.info(f"Incident {incident_id} ({flow_type.value}) processed in {total_time:.2f}s")
            
            return final_result
            
        except Exception as e:
            # Record failed response
            self.metrics.record_response_end(incident_id, False)
            
            error_time = time.time() - start_time
            logger.error(f"Error handling incident {incident_id}: {e}")
            
            return {
                "success": False,
                "incident_id": incident_id,
                "flow_type": flow_type.value if 'flow_type' in locals() else "unknown",
                "error": str(e),
                "processing_time": error_time,
                "response": {"status": "failed", "error": str(e)},
                "analysis": {"status": "failed", "error": str(e)},
                "predictions": {"status": "failed", "error": str(e)}
            }
    
    async def _process_parallel(self, incident: Incident, flow_config: FlowConfiguration) -> Dict[str, Any]:
        """Process incident using parallel strategy (original assignment pattern)"""
        async with asyncio.TaskGroup() as tg:
            tasks = {}
            
            if "responder" in flow_config.required_components:
                tasks['response'] = tg.create_task(
                    self.responder.execute_playbook(incident)
                )
            
            if "analyzer" in flow_config.required_components:
                tasks['analysis'] = tg.create_task(
                    self.analyzer.deep_analysis(incident)
                )
            
            if "predictor" in flow_config.required_components:
                tasks['predictions'] = tg.create_task(
                    self.predictor.forecast_related_threats(incident)
                )
        
        # Safely extract results only for tasks that were actually created.
        if 'response' in tasks:
            try:
                response_result = tasks['response'].result()
            except Exception as e:
                logger.warning(f"Response task failed to produce result: {e}")
                response_result = {"status": "failed", "error": str(e)}
        else:
            response_result = {"status": "skipped"}

        if 'analysis' in tasks:
            try:
                analysis_result = tasks['analysis'].result()
            except Exception as e:
                logger.warning(f"Analysis task failed to produce result: {e}")
                analysis_result = {"status": "failed", "error": str(e)}
        else:
            analysis_result = {"status": "skipped"}

        if 'predictions' in tasks:
            try:
                predictions_result = tasks['predictions'].result()
            except Exception as e:
                logger.warning(f"Predictions task failed to produce result: {e}")
                predictions_result = {"status": "failed", "error": str(e)}
        else:
            predictions_result = {"status": "skipped"}

        return {
            'response': response_result,
            'analysis': analysis_result,
            'predictions': predictions_result
        }
    
    async def _process_sequential(self, incident: Incident, flow_config: FlowConfiguration) -> Dict[str, Any]:
        """Process incident using sequential strategy for complex flows"""
        result = {}
        
        # Step 1: Response (if urgent)
        if flow_config.response_urgency in ["immediate", "fast"]:
            if "responder" in flow_config.required_components:
                result['response'] = await self.responder.execute_playbook(incident)
        
        # Step 2: Deep analysis
        if "analyzer" in flow_config.required_components:
            result['analysis'] = await self.analyzer.deep_analysis(incident)
        
        # Step 3: Predictions based on analysis
        if "predictor" in flow_config.required_components:
            result['predictions'] = await self.predictor.forecast_related_threats(incident)
        
        # Step 4: Response (if not urgent)
        if flow_config.response_urgency not in ["immediate", "fast"]:
            if "responder" in flow_config.required_components:
                result['response'] = await self.responder.execute_playbook(incident)
        
        return result
    
    async def _process_hybrid(self, incident: Incident, flow_config: FlowConfiguration) -> Dict[str, Any]:
        """Process incident using hybrid strategy"""
        # Start with immediate response if needed
        if flow_config.response_urgency == "immediate":
            response_result = await self.responder.execute_playbook(incident)
        else:
            response_result = None
        
        # Parallel analysis and prediction
        async with asyncio.TaskGroup() as tg:
            analysis_task = tg.create_task(
                self.analyzer.deep_analysis(incident)
            ) if "analyzer" in flow_config.required_components else None
            
            prediction_task = tg.create_task(
                self.predictor.forecast_related_threats(incident)
            ) if "predictor" in flow_config.required_components else None
        
        # Complete response if not done
        if response_result is None and "responder" in flow_config.required_components:
            response_result = await self.responder.execute_playbook(incident)
        
        return {
            'response': response_result or {"status": "skipped"},
            'analysis': analysis_task.result() if analysis_task else {"status": "skipped"},
            'predictions': prediction_task.result() if prediction_task else {"status": "skipped"}
        }
    
    def compile_results(self, response_result: Dict[str, Any], 
                       analysis_result: Dict[str, Any],
                       prediction_result: Dict[str, Any],
                       flow_type: FlowType,
                       flow_config: FlowConfiguration) -> Dict[str, Any]:
        """Compile results with enhanced flow information"""
        
        success = all([
            response_result.get('status') == 'completed',
            analysis_result.get('status') in ['completed', 'skipped'],
            prediction_result.get('status') in ['completed', 'skipped']
        ])
        
        return {
            "success": success,
            "flow_type": flow_type.value,
            "flow_configuration": {
                "priority": flow_config.priority,
                "strategy": flow_config.processing_strategy,
                "urgency": flow_config.response_urgency,
                "analysis_depth": flow_config.analysis_depth,
                "prediction_scope": flow_config.prediction_scope,
                "components_used": flow_config.required_components
            },
            "response": response_result,
            "analysis": analysis_result,
            "predictions": prediction_result,
            "processing_metrics": {
                "flow_optimized": True,
                "components_active": len(flow_config.required_components)
            }
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Enhanced health check with flow capability status"""
        if not self.is_initialized:
            return {"status": "not_initialized", "operational": False}
        
        component_health = {}
        if hasattr(self.detector, 'health_check'):
            component_health['detector'] = await self.detector.health_check()
        if hasattr(self.analyzer, 'health_check'):
            component_health['analyzer'] = await self.analyzer.health_check()
        if hasattr(self.responder, 'health_check'):
            component_health['responder'] = await self.responder.health_check()
        if hasattr(self.predictor, 'health_check'):
            component_health['predictor'] = await self.predictor.health_check()
        if hasattr(self.metrics, 'health_check'):
            component_health['metrics'] = await self.metrics.health_check()
        
        all_healthy = all(
            status.get('status') == 'healthy' 
            for status in component_health.values()
        )
        
        return {
            "status": "healthy" if all_healthy else "degraded",
            "operational": all_healthy,
            "components": component_health,
            "flows_supported": len(self.flow_configurations),
            "active_incidents": len(self.active_incidents),
            "flow_types_available": [flow.value for flow in FlowType]
        }

    async def get_performance_metrics(self) -> Dict[str, Any]:
        """Expose metrics summary via MetricsCollector for API consumption."""
        try:
            # Last 24h summary by default
            return self.metrics.get_metrics_summary()
        except Exception as e:
            logger.error(f"Error getting performance metrics: {e}")
            return {"error": str(e)}

    async def get_system_status(self) -> Dict[str, Any]:
        """Aggregate health and metrics into a system status payload."""
        try:
            health = await self.health_check()
            metrics = self.metrics.get_metrics_summary()
            return {
                "health": health,
                "metrics": metrics,
                "active_incidents": len(self.active_incidents),
                "flows_supported": len(self.flow_configurations),
            }
        except Exception as e:
            logger.error(f"Error building system status: {e}")
            return {"error": str(e)}
    
    async def shutdown(self):
        """
        Graceful shutdown of the enhanced incident handler
        """
        logger.info("Shutting down EnhancedIncidentHandler...")
        
        try:
            # Wait for any active incident processing to complete
            if self.active_incidents:
                logger.info(f"Waiting for {len(self.active_incidents)} active incidents to complete...")
                await asyncio.sleep(2)  # Give some time for completion
            
            # Shutdown components that support it
            components = [
                ('detector', self.detector),
                ('analyzer', self.analyzer), 
                ('responder', self.responder),
                ('predictor', self.predictor)
            ]
            
            for name, component in components:
                if hasattr(component, 'shutdown'):
                    try:
                        await component.shutdown()
                        logger.info(f"{name} shutdown complete")
                    except Exception as e:
                        logger.error(f"Error shutting down {name}: {e}")
            
            # Clear active incidents
            self.active_incidents.clear()
            
            logger.info("EnhancedIncidentHandler shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
            raise
