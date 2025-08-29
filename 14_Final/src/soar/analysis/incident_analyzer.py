"""
Incident Analyzer Module

Este módulo fornece funcionalidades para análise de incidentes de segurança.
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

from ..integrations.threat_intel_client import ThreatIntelligenceClient

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    """Resultado da análise de um incidente"""
    severity: str
    risk_score: float
    recommendations: List[str]
    affected_systems: List[str]
    threat_indicators: List[str]
    analysis_timestamp: datetime
    confidence_level: float

    def to_dict(self) -> Dict[str, Any]:
        """Converte o resultado para dicionário"""
        result = asdict(self)
        result['analysis_timestamp'] = self.analysis_timestamp.isoformat()
        return result


class IncidentAnalyzer:
    """
    Analisador de incidentes de segurança
    
    Esta classe fornece funcionalidades para analisar incidentes,
    calcular scores de risco e gerar recomendações.
    """

    def __init__(self):
        """Inicializa o analisador de incidentes"""
        self.threat_patterns = {
            'malware': ['virus', 'trojan', 'worm', 'ransomware', 'spyware'],
            'network': ['ddos', 'intrusion', 'scanning', 'brute_force'],
            'data': ['exfiltration', 'leak', 'breach', 'unauthorized_access'],
            'system': ['privilege_escalation', 'lateral_movement', 'persistence']
        }
        
        self.severity_weights = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4,
            'info': 0.2
        }
        
        # Initialize threat intelligence client
        self.threat_intel = ThreatIntelligenceClient()
        
        logger.info("IncidentAnalyzer initialized")

    async def initialize(self):
        """Inicializa o analisador de incidentes de forma assíncrona"""
        logger.info("Initializing IncidentAnalyzer...")
        
        # Initialize threat intelligence client
        await self.threat_intel.initialize()
        
        logger.info("IncidentAnalyzer initialization complete")

    async def health_check(self) -> Dict[str, Any]:
        """
        Verifica o estado de saúde do analisador de incidentes
        
        Returns:
            Dict contendo informações sobre o estado do componente
        """
        try:
            # Verificar se os padrões de ameaça estão carregados
            patterns_loaded = len(self.threat_patterns) > 0
            
            # Verificar se os pesos de severidade estão configurados
            weights_configured = len(self.severity_weights) > 0
            
            # Estado geral
            operational = patterns_loaded and weights_configured
            
            return {
                "operational": operational,
                "status": "healthy" if operational else "degraded",
                "components": {
                    "threat_patterns": {
                        "loaded": patterns_loaded,
                        "count": len(self.threat_patterns),
                        "categories": list(self.threat_patterns.keys())
                    },
                    "severity_weights": {
                        "configured": weights_configured,
                        "levels": list(self.severity_weights.keys())
                    }
                },
                "last_check": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Health check failed for IncidentAnalyzer: {str(e)}")
            return {
                "operational": False,
                "status": "error",
                "error": str(e),
                "last_check": datetime.utcnow().isoformat()
            }

    def analyze_incident(self, incident_data: Dict[str, Any]) -> AnalysisResult:
        """
        Analisa um incidente e retorna o resultado da análise
        
        Args:
            incident_data: Dados do incidente a ser analisado
            
        Returns:
            AnalysisResult: Resultado da análise
        """
        try:
            logger.info(f"Analyzing incident: {incident_data.get('id', 'unknown')}")
            
            # Extrai informações básicas
            incident_type = incident_data.get('type', '').lower()
            description = incident_data.get('description', '').lower()
            severity = incident_data.get('severity', 'medium').lower()
            
            # Calcula score de risco
            risk_score = self._calculate_risk_score(incident_data)
            
            # Identifica indicadores de ameaça
            threat_indicators = self._identify_threat_indicators(description, incident_type)
            
            # Identifica sistemas afetados
            affected_systems = self._extract_affected_systems(incident_data)
            
            # Gera recomendações
            recommendations = self._generate_recommendations(incident_type, severity, threat_indicators)
            
            # Calcula nível de confiança
            confidence_level = self._calculate_confidence_level(incident_data)
            
            result = AnalysisResult(
                severity=self._normalize_severity(severity),
                risk_score=risk_score,
                recommendations=recommendations,
                affected_systems=affected_systems,
                threat_indicators=threat_indicators,
                analysis_timestamp=datetime.utcnow(),
                confidence_level=confidence_level
            )
            
            logger.info(f"Analysis completed for incident {incident_data.get('id', 'unknown')}")
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing incident: {str(e)}")
            # Retorna resultado padrão em caso de erro
            return AnalysisResult(
                severity='medium',
                risk_score=0.5,
                recommendations=['Review incident details', 'Contact security team'],
                affected_systems=[],
                threat_indicators=[],
                analysis_timestamp=datetime.utcnow(),
                confidence_level=0.3
            )

    async def deep_analysis(self, incident) -> Dict[str, Any]:
        """
        Performs deep analysis of an incident as specified in assignment
        
        Args:
            incident: The incident object to analyze
            
        Returns:
            Dict containing detailed analysis results
        """
        try:
            logger.info(f"Starting deep analysis for incident {incident.id}")
            
            # Convert incident to dict for analysis
            incident_data = {
                'id': incident.id,
                'type': incident.incident_type.value if hasattr(incident.incident_type, 'value') else str(incident.incident_type),
                'severity': incident.severity.value if hasattr(incident.severity, 'value') else str(incident.severity),
                'source_ip': getattr(incident, 'source_ip', None),
                'target_ip': getattr(incident, 'target_ip', None),
                'destination_ip': getattr(incident, 'destination_ip', None),
                'domain': getattr(incident, 'domain', None),
                'file_hash': getattr(incident, 'file_hash', None),
                'affected_systems': getattr(incident, 'affected_systems', []),
                'threat_indicators': getattr(incident, 'threat_indicators', []),
                'timestamp': incident.timestamp,
                'data': getattr(incident, 'data', {}),
                'description': getattr(incident, 'description', '')
            }
            
            # Enrich with threat intelligence
            threat_intel_enrichment = await self.threat_intel.enrich_incident_with_threat_intel(incident_data)
            
            # Perform detailed analysis using existing method
            analysis_result = self.analyze_incident(incident_data)
            
            # Enhance analysis with threat intelligence data
            enhanced_risk_score = analysis_result.risk_score
            enhanced_severity = analysis_result.severity
            enhanced_recommendations = list(analysis_result.recommendations)
            
            # Apply threat intelligence insights
            if threat_intel_enrichment.get('threat_score', 0) > 0.5:
                enhanced_risk_score = min(enhanced_risk_score + 0.3, 1.0)
                
                # Upgrade severity if threat intel indicates high risk
                if threat_intel_enrichment['threat_score'] > 0.8:
                    if enhanced_severity == 'low':
                        enhanced_severity = 'medium'
                    elif enhanced_severity == 'medium':
                        enhanced_severity = 'high'
                
                # Add threat intelligence recommendations
                if threat_intel_enrichment.get('malicious_indicators'):
                    enhanced_recommendations.append(f"Block malicious indicators: {', '.join(threat_intel_enrichment['malicious_indicators'])}")
                
                if threat_intel_enrichment.get('threat_categories'):
                    enhanced_recommendations.append(f"Investigate {', '.join(threat_intel_enrichment['threat_categories'])} threats")
            
            # Convert to dict format expected by assignment
            deep_analysis_result = {
                'status': 'completed',
                'analysis_id': f"analysis_{incident.id}_{int(datetime.utcnow().timestamp())}",
                'incident_id': incident.id,
                'severity_assessment': enhanced_severity,
                'risk_score': enhanced_risk_score,
                'confidence_level': analysis_result.confidence_level,
                'recommendations': enhanced_recommendations,
                'affected_systems': analysis_result.affected_systems,
                'threat_indicators': analysis_result.threat_indicators,
                'analysis_timestamp': analysis_result.analysis_timestamp.isoformat(),
                'threat_intelligence': threat_intel_enrichment,
                'detailed_findings': {
                    'attack_vector': self._identify_attack_vector(incident_data),
                    'potential_impact': self._assess_potential_impact(incident_data),
                    'containment_status': self._assess_containment_status(incident_data),
                    'forensic_artifacts': self._collect_forensic_artifacts(incident_data)
                }
            }
            
            logger.info(f"Deep analysis completed for incident {incident.id}")
            return deep_analysis_result
            
        except Exception as e:
            logger.error(f"Error in deep analysis for incident {incident.id}: {str(e)}")
            return {
                'status': 'failed',
                'incident_id': incident.id,
                'error': str(e),
                'analysis_timestamp': datetime.utcnow().isoformat()
            }

    def _identify_attack_vector(self, incident_data: Dict[str, Any]) -> str:
        """Identify the attack vector based on incident data"""
        incident_type = incident_data.get('type', '').lower()
        
        if 'malware' in incident_type:
            return 'malware_infection'
        elif 'brute_force' in incident_type:
            return 'credential_attack'
        elif 'ddos' in incident_type:
            return 'network_attack'
        elif 'exfiltration' in incident_type:
            return 'data_theft'
        else:
            return 'unknown_vector'

    def _assess_potential_impact(self, incident_data: Dict[str, Any]) -> str:
        """Assess the potential impact of the incident"""
        risk_score = self._calculate_risk_score(incident_data)
        
        if risk_score >= 0.8:
            return 'critical_impact'
        elif risk_score >= 0.6:
            return 'high_impact'
        elif risk_score >= 0.4:
            return 'medium_impact'
        else:
            return 'low_impact'

    def _assess_containment_status(self, incident_data: Dict[str, Any]) -> str:
        """Assess if the incident is contained"""
        # Simple logic - can be enhanced based on actual containment data
        affected_systems = incident_data.get('affected_systems', [])
        
        if len(affected_systems) <= 1:
            return 'contained'
        elif len(affected_systems) <= 5:
            return 'partially_contained'
        else:
            return 'spreading'

    def _collect_forensic_artifacts(self, incident_data: Dict[str, Any]) -> List[str]:
        """Collect relevant forensic artifacts"""
        artifacts = []
        
        if incident_data.get('source_ip'):
            artifacts.append(f"source_ip: {incident_data['source_ip']}")
        
        if incident_data.get('target_ip'):
            artifacts.append(f"target_ip: {incident_data['target_ip']}")
        
        threat_indicators = incident_data.get('threat_indicators', [])
        for indicator in threat_indicators:
            artifacts.append(f"ioc: {indicator}")
        
        return artifacts

    def _calculate_risk_score(self, incident_data: Dict[str, Any]) -> float:
        """Calcula o score de risco baseado nos dados do incidente"""
        base_score = 0.5
        
        # Ajusta baseado na severidade
        severity = incident_data.get('severity', 'medium').lower()
        severity_multiplier = self.severity_weights.get(severity, 0.6)
        
        # Ajusta baseado no tipo de incidente
        incident_type = incident_data.get('type', '').lower()
        type_multiplier = 1.0
        
        if any(pattern in incident_type for pattern in self.threat_patterns['malware']):
            type_multiplier = 1.2
        elif any(pattern in incident_type for pattern in self.threat_patterns['data']):
            type_multiplier = 1.3
        elif any(pattern in incident_type for pattern in self.threat_patterns['system']):
            type_multiplier = 1.1
        
        # Ajusta baseado no número de sistemas afetados
        affected_count = len(incident_data.get('affected_systems', []))
        if affected_count > 10:
            count_multiplier = 1.3
        elif affected_count > 5:
            count_multiplier = 1.2
        elif affected_count > 1:
            count_multiplier = 1.1
        else:
            count_multiplier = 1.0
        
        final_score = min(1.0, base_score * severity_multiplier * type_multiplier * count_multiplier)
        return round(final_score, 2)

    def _identify_threat_indicators(self, description: str, incident_type: str) -> List[str]:
        """Identifica indicadores de ameaça no incidente"""
        indicators = []
        
        for category, patterns in self.threat_patterns.items():
            for pattern in patterns:
                if pattern in description or pattern in incident_type:
                    indicators.append(f"{category}:{pattern}")
        
        return indicators

    def _extract_affected_systems(self, incident_data: Dict[str, Any]) -> List[str]:
        """Extrai lista de sistemas afetados"""
        systems = incident_data.get('affected_systems', [])
        if isinstance(systems, str):
            return [systems]
        elif isinstance(systems, list):
            return systems
        else:
            return []

    def _generate_recommendations(self, incident_type: str, severity: str, threat_indicators: List[str]) -> List[str]:
        """Gera recomendações baseadas na análise"""
        recommendations = []
        
        # Recomendações baseadas na severidade
        if severity in ['critical', 'high']:
            recommendations.extend([
                'Isolate affected systems immediately',
                'Notify security team and management',
                'Begin incident response procedures'
            ])
        elif severity == 'medium':
            recommendations.extend([
                'Monitor affected systems closely',
                'Review security logs',
                'Consider containment measures'
            ])
        else:
            recommendations.extend([
                'Document the incident',
                'Review for patterns',
                'Update monitoring rules'
            ])
        
        # Recomendações baseadas no tipo
        if 'malware' in incident_type:
            recommendations.extend([
                'Run full antivirus scan',
                'Check for lateral movement',
                'Update threat signatures'
            ])
        elif 'network' in incident_type:
            recommendations.extend([
                'Review firewall rules',
                'Check network traffic patterns',
                'Validate access controls'
            ])
        elif 'data' in incident_type:
            recommendations.extend([
                'Assess data exposure',
                'Review access logs',
                'Consider regulatory notifications'
            ])
        
        # Remove duplicatas e retorna
        return list(set(recommendations))

    def _calculate_confidence_level(self, incident_data: Dict[str, Any]) -> float:
        """Calcula o nível de confiança da análise"""
        confidence = 0.7  # Base confidence
        
        # Aumenta confiança se há mais dados disponíveis
        if incident_data.get('description'):
            confidence += 0.1
        if incident_data.get('source_ip'):
            confidence += 0.1
        if incident_data.get('timestamp'):
            confidence += 0.05
        if incident_data.get('affected_systems'):
            confidence += 0.05
        
        return min(1.0, round(confidence, 2))

    def _normalize_severity(self, severity: str) -> str:
        """Normaliza o valor de severidade"""
        severity = severity.lower()
        valid_severities = ['critical', 'high', 'medium', 'low', 'info']
        
        if severity in valid_severities:
            return severity
        else:
            return 'medium'

    def get_analysis_stats(self) -> Dict[str, Any]:
        """Retorna estatísticas da análise"""
        return {
            'threat_patterns_count': sum(len(patterns) for patterns in self.threat_patterns.values()),
            'severity_levels': list(self.severity_weights.keys()),
            'analyzer_version': '1.0.0',
            'last_updated': datetime.utcnow().isoformat()
        }
