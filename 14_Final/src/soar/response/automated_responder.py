"""
Automated Responder Module

Este módulo fornece funcionalidades de resposta automatizada a incidentes de segurança.
"""

import json
import logging
import yaml
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path

from .orchestrator import ResponseOrchestrator
from ..integrations.siem_connector import SIEMConnector
from ..integrations.threat_intel_client import ThreatIntelligenceClient
from ..integrations.azure_firewall_manager import AzureFirewallManager
from ..integrations.azure_vm_manager import AzureVMManager
from ..integrations.azure_nsg_manager import AzureNSGManager
from ..integrations.azure_backup_manager import AzureBackupManager
from ..integrations.azure_ad_manager import AzureADManager

logger = logging.getLogger(__name__)


class PlaybookLibrary:
    """
    Playbook Library as specified in assignment requirements
    
    Manages and selects appropriate response playbooks based on incident type
    """
    
    def __init__(self, root: str = None):
        """Initialize playbook library with root directory"""
        if root is None:
            self.root = Path(__file__).resolve().parent.parent / "playbooks"
        else:
            self.root = Path(root)
        
        logger.info(f"PlaybookLibrary initialized with root: {self.root}")
    
    def select_playbook(self, incident) -> dict:
        """
        Select appropriate playbook based on incident type
        
        Args:
            incident: Incident object with type information
            
        Returns:
            Playbook dictionary loaded from YAML
        """
        # Prefer flow_type when available, else map by incident_type
        flow_type = getattr(incident, 'flow_type', None)
        incident_type = getattr(incident, 'incident_type', None)
        if incident_type and hasattr(incident_type, 'value'):
            incident_type = incident_type.value
        elif incident_type:
            incident_type = str(incident_type)
        else:
            incident_type = "unknown"

        filename_mapping = {
            "brute_force": "block_bruteforce.yml",
            "network_attack": "block_bruteforce.yml",
            "malware": "quarantine.yml",
            "malware_alert": "quarantine.yml",
            "data_exfiltration": "block_exfiltration.yml",
            "data_breach": "block_exfiltration.yml",
            "network_anomaly": "investigate.yml",
            "zero_day": "investigate.yml",
            "policy_violation": "policy_violation.yml",
            # recovery and system failures
            "system_failure": "restore_from_backup.yml"
        }

        flow_mapping = {
            "ransomware": "ransomware_recovery.yml",
            "cascade_failure": "restore_from_backup.yml"
        }

        filename = None
        if isinstance(flow_type, str) and flow_type:
            filename = flow_mapping.get(flow_type.lower())
        if not filename:
            filename = filename_mapping.get((incident_type or "").lower(), "investigate.yml")
        playbook_path = self.root / filename

        try:
            if playbook_path.exists():
                with open(playbook_path, 'r', encoding='utf-8') as f:
                    playbook = yaml.safe_load(f)
                logger.info(f"Loaded playbook {filename} for incident type {incident_type}")
                return playbook
            else:
                logger.warning(f"Playbook file not found: {playbook_path}")
                return self._get_default_playbook(incident_type)
        except Exception as e:
            logger.error(f"Error loading playbook {filename}: {e}")
            return self._get_default_playbook(incident_type)
    
    def _get_default_playbook(self, incident_type: str) -> dict:
        """Return a default playbook for fallback"""
        return {
            "name": f"Default Response for {incident_type}",
            "description": "Fallback playbook when specific playbook is not available",
            "version": "1.0",
            "steps": [
                {
                    "name": "Send Alert",
                    "action": "alert.send_alert",
                    "params": {
                        "severity": "medium"
                    }
                },
                {
                    "name": "Create Ticket",
                    "action": "alert.create_ticket",
                    "params": {
                        "priority": "medium"
                    }
                }
            ]
        }


class ResponseAction(Enum):
    """Tipos de ações de resposta disponíveis"""
    ISOLATE = "isolate"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    ALERT = "alert"
    NOTIFY = "notify"
    SCAN = "scan"
    MONITOR = "monitor"
    PATCH = "patch"
    RESET = "reset"


@dataclass
class ResponseResult:
    """Resultado de uma ação de resposta"""
    action: str
    success: bool
    message: str
    timestamp: datetime
    affected_systems: List[str]
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Converte o resultado para dicionário"""
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result


class AutomatedResponder:
    """
    Sistema de resposta automatizada a incidentes
    
    Esta classe fornece funcionalidades para executar respostas
    automatizadas baseadas no tipo e severidade do incidente.
    
    Implements the exact pattern from assignment requirements:
    - self.playbooks = PlaybookLibrary()
    - self.orchestrator = ResponseOrchestrator()
    - async def execute_playbook(self, incident)
    """

    def __init__(self):
        """Inicializa o sistema de resposta automatizada conforme enunciado"""
        # Assignment required components
        self.playbooks = PlaybookLibrary()
        self.orchestrator = ResponseOrchestrator()
        
        # SIEM integration for incident logging and analysis
        self.siem = SIEMConnector()
        
        # Threat intelligence integration for enrichment
        self.threat_intel = ThreatIntelligenceClient()
        
        # Azure integrations for comprehensive incident response
        self.azure_firewall = AzureFirewallManager()
        self.azure_vm = AzureVMManager()
        self.azure_nsg = AzureNSGManager()
        self.azure_backup = AzureBackupManager()
        self.azure_ad = AzureADManager()
        
        # Legacy response templates (mantido para compatibilidade)
        self.response_templates = {
            'malware': {
                'critical': [ResponseAction.ISOLATE, ResponseAction.QUARANTINE, ResponseAction.NOTIFY],
                'high': [ResponseAction.QUARANTINE, ResponseAction.SCAN, ResponseAction.ALERT],
                'medium': [ResponseAction.SCAN, ResponseAction.MONITOR, ResponseAction.ALERT],
                'low': [ResponseAction.MONITOR, ResponseAction.ALERT]
            },
            'network': {
                'critical': [ResponseAction.BLOCK, ResponseAction.ISOLATE, ResponseAction.NOTIFY],
                'high': [ResponseAction.BLOCK, ResponseAction.MONITOR, ResponseAction.ALERT],
                'medium': [ResponseAction.MONITOR, ResponseAction.ALERT],
                'low': [ResponseAction.MONITOR]
            },
            'data': {
                'critical': [ResponseAction.ISOLATE, ResponseAction.BLOCK, ResponseAction.NOTIFY],
                'high': [ResponseAction.BLOCK, ResponseAction.MONITOR, ResponseAction.NOTIFY],
                'medium': [ResponseAction.MONITOR, ResponseAction.ALERT],
                'low': [ResponseAction.MONITOR]
            },
            'system': {
                'critical': [ResponseAction.ISOLATE, ResponseAction.PATCH, ResponseAction.NOTIFY],
                'high': [ResponseAction.PATCH, ResponseAction.MONITOR, ResponseAction.ALERT],
                'medium': [ResponseAction.MONITOR, ResponseAction.ALERT],
                'low': [ResponseAction.MONITOR]
            }
        }
        
        self.executed_responses = []
        logger.info("AutomatedResponder initialized")

    async def initialize(self):
        """Inicializa o sistema de resposta automatizada de forma assíncrona"""
        logger.info("Initializing AutomatedResponder...")
        
        # Initialize SIEM connection
        try:
            await self.siem.initialize()
            logger.info("SIEM connector initialized successfully")
        except Exception as e:
            logger.warning(f"SIEM initialization failed: {e}. Continuing without SIEM integration.")
        
        # Initialize threat intelligence
        try:
            await self.threat_intel.initialize()
            logger.info("Threat intelligence initialized successfully")
        except Exception as e:
            logger.warning(f"Threat intelligence initialization failed: {e}. Continuing without threat intel.")
        
        # Initialize Azure Firewall
        try:
            self.azure_firewall.initialize()  # SYNCHRONOUS - NO AWAIT
            logger.info("Azure Firewall manager initialized successfully")
        except Exception as e:
            logger.warning(f"Azure Firewall initialization failed: {e}. Continuing without Azure Firewall integration.")
        
        logger.info("AutomatedResponder initialization complete")

    async def execute_playbook(self, incident):
        """
        Execute response playbook as specified in assignment requirements
        
        This is the exact method signature from the assignment:
        async def execute_playbook(self, incident):
            playbook = self.playbooks.select_playbook(incident)
            return await self.orchestrator.execute(playbook)
        
        Args:
            incident: Incident object to process
            
        Returns:
            Playbook execution results
        """
        try:
            logger.info(f"Executing playbook for incident {getattr(incident, 'id', 'unknown')}")
            
            # Enrich incident with threat intelligence before processing
            threat_intel_data = None
            try:
                incident_data = {
                    'source_ip': getattr(incident, 'source_ip', None),
                    'destination_ip': getattr(incident, 'destination_ip', None),
                    'domain': getattr(incident, 'domain', None),
                    'file_hash': getattr(incident, 'file_hash', None),
                    'description': getattr(incident, 'description', ''),
                    'title': getattr(incident, 'title', '')
                }
                
                threat_intel_data = await self.threat_intel.enrich_incident_with_threat_intel(incident_data)
                if threat_intel_data.get('threat_score', 0) > 0.5:
                    logger.info(f"High threat score detected ({threat_intel_data['threat_score']:.2f}) for incident {getattr(incident, 'id', 'unknown')}")
                    
                    # Store threat intel data in incident for later use
                    if hasattr(incident, 'threat_intel_data'):
                        incident.threat_intel_data = threat_intel_data
                    
            except Exception as ti_error:
                logger.warning(f"Failed to enrich incident with threat intelligence: {ti_error}")
            
            # Log incident to SIEM with threat intelligence data
            try:
                siem_data = {
                    "incident_id": getattr(incident, 'id', 'unknown'),
                    "title": getattr(incident, 'title', 'unknown'),
                    "description": getattr(incident, 'description', ''),
                    "severity": getattr(incident, 'severity', 'unknown'),
                    "incident_type": getattr(incident, 'incident_type', 'unknown'),
                    "timestamp": datetime.now().isoformat(),
                    "source": getattr(incident, 'source', 'unknown'),
                    "status": "processing"
                }
                
                # Add threat intelligence data if available
                if threat_intel_data:
                    siem_data["threat_intelligence"] = {
                        "threat_score": threat_intel_data.get('threat_score', 0),
                        "malicious_indicators": threat_intel_data.get('malicious_indicators', []),
                        "threat_categories": threat_intel_data.get('threat_categories', []),
                        "external_lookups": threat_intel_data.get('external_lookups_performed', 0)
                    }
                
                await self.siem.send_incident_to_siem(siem_data)
            except Exception as siem_error:
                logger.warning(f"Failed to log incident to SIEM: {siem_error}")
            
            # Select appropriate playbook based on incident
            playbook = self.playbooks.select_playbook(incident)
            
            # Execute playbook using orchestrator
            result = await self.orchestrator.execute(playbook, incident)
            
            # Automated Azure Firewall Response based on threat intelligence
            firewall_actions = []
            if threat_intel_data and threat_intel_data.get('threat_score', 0) > 0.7:
                logger.info(f"High threat score ({threat_intel_data['threat_score']:.2f}) detected - initiating automatic firewall blocking")
                
                # Block malicious IPs automatically
                malicious_ips = []
                
                # Extract IPs from incident
                if hasattr(incident, 'source_ip') and incident.source_ip:
                    malicious_ips.append(incident.source_ip)
                if hasattr(incident, 'destination_ip') and incident.destination_ip:
                    malicious_ips.append(incident.destination_ip)
                
                # Extract IPs from threat intel malicious indicators
                for indicator in threat_intel_data.get('malicious_indicators', []):
                    if indicator.get('type') == 'ip':
                        malicious_ips.append(indicator.get('value'))
                
                # Remove duplicates and filter valid IPs
                unique_ips = list(set(filter(None, malicious_ips)))
                
                for ip in unique_ips:
                    try:
                        block_result = self.azure_firewall.block_ip_address(  # SYNCHRONOUS - NO AWAIT
                            ip_address=ip,
                            reason=f"Automated block - Threat score: {threat_intel_data['threat_score']:.2f}",
                            incident_id=getattr(incident, 'id', 'unknown')
                        )
                        
                        if block_result.get('success'):
                            firewall_actions.append({
                                'action': 'block_ip',
                                'ip': ip,
                                'status': 'success',
                                'rule_name': block_result.get('rule_name'),
                                'timestamp': datetime.now().isoformat()
                            })
                            logger.info(f"Successfully blocked malicious IP {ip} in Azure Firewall")
                        else:
                            firewall_actions.append({
                                'action': 'block_ip',
                                'ip': ip,
                                'status': 'failed',
                                'error': block_result.get('error'),
                                'timestamp': datetime.now().isoformat()
                            })
                            logger.warning(f"Failed to block IP {ip}: {block_result.get('error')}")
                            
                    except Exception as fw_error:
                        firewall_actions.append({
                            'action': 'block_ip',
                            'ip': ip,
                            'status': 'error',
                            'error': str(fw_error),
                            'timestamp': datetime.now().isoformat()
                        })
                        logger.error(f"Error blocking IP {ip} in Azure Firewall: {fw_error}")
            
            # Add firewall actions to result
            if firewall_actions:
                result['azure_firewall_actions'] = firewall_actions
            
            # Log response result to SIEM
            try:
                await self.siem.send_incident_to_siem({
                    "incident_id": getattr(incident, 'id', 'unknown'),
                    "playbook_name": getattr(playbook, 'name', 'unknown'),
                    "result": result,
                    "timestamp": datetime.now().isoformat(),
                    "status": "completed"
                })
            except Exception as siem_error:
                logger.warning(f"Failed to log response result to SIEM: {siem_error}")
            
            logger.info(f"Playbook execution completed for incident {getattr(incident, 'id', 'unknown')}")
            return result
            
        except Exception as e:
            logger.error(f"Error executing playbook for incident {getattr(incident, 'id', 'unknown')}: {e}")
            
            # Log error to SIEM
            try:
                await self.siem.send_incident_to_siem({
                    "incident_id": getattr(incident, 'id', 'unknown'),
                    "status": "failed",
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                })
            except:
                pass  # Don't fail the main process if SIEM logging fails
                
            return {
                "status": "failed",
                "error": str(e),
                "steps": []
            }

    async def health_check(self) -> Dict[str, Any]:
        """
        Verifica o estado de saúde do sistema de resposta automatizada
        
        Returns:
            Dict contendo informações sobre o estado do componente
        """
        try:
            # Verificar se os templates de resposta estão carregados
            templates_loaded = len(self.response_templates) > 0
            
            # Verificar se há ações disponíveis
            total_actions = sum(len(severity_actions) for incident_type in self.response_templates.values() 
                               for severity_actions in incident_type.values())
            
            # Verificar estado do SIEM
            siem_status = {"operational": False, "error": None}
            try:
                # Simple connectivity check
                siem_status["operational"] = hasattr(self.siem, 'es_client')
            except Exception as e:
                siem_status["error"] = str(e)
            
            # Verificar estado do Threat Intelligence
            threat_intel_status = {"operational": False, "error": None}
            try:
                threat_intel_status["operational"] = hasattr(self.threat_intel, 'api_key') and self.threat_intel.api_key is not None
            except Exception as e:
                threat_intel_status["error"] = str(e)
            
            # Verificar estado do Azure Firewall
            azure_firewall_status = {"operational": False, "error": None}
            try:
                azure_firewall_status["operational"] = hasattr(self.azure_firewall, 'network_client') 
            except Exception as e:
                azure_firewall_status["error"] = str(e)
            
            # Estado geral
            operational = (templates_loaded and total_actions > 0 and 
                          siem_status["operational"] and threat_intel_status["operational"])
            
            return {
                "operational": operational,
                "status": "healthy" if operational else "degraded",
                "components": {
                    "response_templates": {
                        "loaded": templates_loaded,
                        "incident_types": list(self.response_templates.keys()),
                        "total_actions": total_actions
                    },
                    "siem_connector": siem_status,
                    "threat_intelligence": threat_intel_status,
                    "azure_firewall": azure_firewall_status,
                    "executed_responses": {
                        "count": len(self.executed_responses),
                        "last_execution": self.executed_responses[-1].timestamp.isoformat() if self.executed_responses else None
                    }
                },
                "last_check": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Health check failed for AutomatedResponder: {str(e)}")
            return {
                "operational": False,
                "status": "error", 
                "error": str(e),
                "last_check": datetime.utcnow().isoformat()
            }

    def respond_to_incident(self, incident_data: Dict[str, Any]) -> List[ResponseResult]:
        """
        Executa resposta automatizada para um incidente
        
        Args:
            incident_data: Dados do incidente
            
        Returns:
            List[ResponseResult]: Lista de resultados das ações executadas
        """
        try:
            logger.info(f"Responding to incident: {incident_data.get('id', 'unknown')}")
            
            incident_type = self._classify_incident_type(incident_data)
            severity = incident_data.get('severity', 'medium').lower()
            affected_systems = incident_data.get('affected_systems', [])
            
            # Obter ações recomendadas
            recommended_actions = self._get_recommended_actions(incident_type, severity)
            
            # Executar ações
            results = []
            for action in recommended_actions:
                result = self._execute_action(action, incident_data, affected_systems)
                results.append(result)
                self.executed_responses.append(result)
            
            logger.info(f"Completed response to incident {incident_data.get('id', 'unknown')}")
            return results
            
        except Exception as e:
            logger.error(f"Error responding to incident: {str(e)}")
            return [ResponseResult(
                action="error",
                success=False,
                message=f"Error in automated response: {str(e)}",
                timestamp=datetime.utcnow(),
                affected_systems=[],
                details={}
            )]

    def _classify_incident_type(self, incident_data: Dict[str, Any]) -> str:
        """Classifica o tipo de incidente baseado nos dados"""
        incident_type = incident_data.get('type', '').lower()
        description = incident_data.get('description', '').lower()
        
        # Mapeamento de palavras-chave para tipos
        type_keywords = {
            'malware': ['virus', 'trojan', 'malware', 'ransomware', 'worm'],
            'network': ['ddos', 'intrusion', 'network', 'firewall', 'traffic'],
            'data': ['breach', 'leak', 'exfiltration', 'unauthorized', 'access'],
            'system': ['privilege', 'escalation', 'vulnerability', 'patch', 'system']
        }
        
        # Verificar palavras-chave no tipo e descrição
        for category, keywords in type_keywords.items():
            if any(keyword in incident_type or keyword in description for keyword in keywords):
                return category
        
        return 'system'  # Tipo padrão

    def _get_recommended_actions(self, incident_type: str, severity: str) -> List[ResponseAction]:
        """Obtém ações recomendadas baseadas no tipo e severidade"""
        if incident_type in self.response_templates:
            template = self.response_templates[incident_type]
            if severity in template:
                return template[severity]
            else:
                return template.get('medium', [ResponseAction.MONITOR])
        else:
            return [ResponseAction.MONITOR, ResponseAction.ALERT]

    def _execute_action(self, action: ResponseAction, incident_data: Dict[str, Any], 
                       affected_systems: List[str]) -> ResponseResult:
        """
        Executa uma ação de resposta específica
        
        Args:
            action: Ação a ser executada
            incident_data: Dados do incidente
            affected_systems: Sistemas afetados
            
        Returns:
            ResponseResult: Resultado da execução
        """
        try:
            if action == ResponseAction.ISOLATE:
                return self._isolate_systems(affected_systems, incident_data)
            elif action == ResponseAction.BLOCK:
                return self._block_threats(incident_data)
            elif action == ResponseAction.QUARANTINE:
                return self._quarantine_files(incident_data)
            elif action == ResponseAction.ALERT:
                return self._send_alert(incident_data)
            elif action == ResponseAction.NOTIFY:
                return self._notify_teams(incident_data)
            elif action == ResponseAction.SCAN:
                return self._initiate_scan(affected_systems)
            elif action == ResponseAction.MONITOR:
                return self._enhance_monitoring(affected_systems)
            elif action == ResponseAction.PATCH:
                return self._apply_patches(affected_systems)
            elif action == ResponseAction.RESET:
                return self._reset_credentials(affected_systems)
            else:
                return ResponseResult(
                    action=action.value,
                    success=False,
                    message=f"Unknown action: {action}",
                    timestamp=datetime.utcnow(),
                    affected_systems=affected_systems,
                    details={}
                )
                
        except Exception as e:
            logger.error(f"Error executing action {action}: {str(e)}")
            return ResponseResult(
                action=action.value,
                success=False,
                message=f"Error executing {action}: {str(e)}",
                timestamp=datetime.utcnow(),
                affected_systems=affected_systems,
                details={}
            )

    def _isolate_systems(self, systems: List[str], incident_data: Dict[str, Any]) -> ResponseResult:
        """Simula isolamento de sistemas"""
        logger.info(f"Isolating systems: {systems}")
        return ResponseResult(
            action=ResponseAction.ISOLATE.value,
            success=True,
            message=f"Successfully isolated {len(systems)} system(s)",
            timestamp=datetime.utcnow(),
            affected_systems=systems,
            details={
                'isolation_method': 'network_quarantine',
                'incident_id': incident_data.get('id'),
                'automated': True
            }
        )

    def _block_threats(self, incident_data: Dict[str, Any]) -> ResponseResult:
        """Simula bloqueio de ameaças"""
        source_ip = incident_data.get('source_ip', 'unknown')
        logger.info(f"Blocking threat from: {source_ip}")
        return ResponseResult(
            action=ResponseAction.BLOCK.value,
            success=True,
            message=f"Blocked threat from {source_ip}",
            timestamp=datetime.utcnow(),
            affected_systems=[],
            details={
                'blocked_ip': source_ip,
                'rule_applied': True,
                'firewall_updated': True
            }
        )

    def _quarantine_files(self, incident_data: Dict[str, Any]) -> ResponseResult:
        """Simula quarentena de arquivos"""
        file_hash = incident_data.get('file_hash', 'unknown')
        logger.info(f"Quarantining file: {file_hash}")
        return ResponseResult(
            action=ResponseAction.QUARANTINE.value,
            success=True,
            message=f"File quarantined: {file_hash}",
            timestamp=datetime.utcnow(),
            affected_systems=[],
            details={
                'file_hash': file_hash,
                'quarantine_location': '/quarantine/',
                'original_location': incident_data.get('file_path', 'unknown')
            }
        )

    def _send_alert(self, incident_data: Dict[str, Any]) -> ResponseResult:
        """Simula envio de alerta"""
        logger.info("Sending security alert")
        return ResponseResult(
            action=ResponseAction.ALERT.value,
            success=True,
            message="Security alert sent successfully",
            timestamp=datetime.utcnow(),
            affected_systems=[],
            details={
                'alert_level': incident_data.get('severity', 'medium'),
                'notification_channels': ['email', 'sms', 'slack'],
                'incident_id': incident_data.get('id')
            }
        )

    def _notify_teams(self, incident_data: Dict[str, Any]) -> ResponseResult:
        """Simula notificação de equipes"""
        logger.info("Notifying security teams")
        return ResponseResult(
            action=ResponseAction.NOTIFY.value,
            success=True,
            message="Security teams notified",
            timestamp=datetime.utcnow(),
            affected_systems=[],
            details={
                'teams_notified': ['SOC', 'CERT', 'Management'],
                'notification_method': 'automated_escalation',
                'severity': incident_data.get('severity', 'medium')
            }
        )

    def _initiate_scan(self, systems: List[str]) -> ResponseResult:
        """Simula início de scan"""
        logger.info(f"Initiating security scan on: {systems}")
        return ResponseResult(
            action=ResponseAction.SCAN.value,
            success=True,
            message=f"Security scan initiated on {len(systems)} system(s)",
            timestamp=datetime.utcnow(),
            affected_systems=systems,
            details={
                'scan_type': 'comprehensive_security_scan',
                'estimated_duration': '30 minutes',
                'scan_id': f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            }
        )

    def _enhance_monitoring(self, systems: List[str]) -> ResponseResult:
        """Simula melhoria do monitoramento"""
        logger.info(f"Enhancing monitoring for: {systems}")
        return ResponseResult(
            action=ResponseAction.MONITOR.value,
            success=True,
            message=f"Enhanced monitoring activated for {len(systems)} system(s)",
            timestamp=datetime.utcnow(),
            affected_systems=systems,
            details={
                'monitoring_level': 'enhanced',
                'duration': '24 hours',
                'additional_metrics': ['network_traffic', 'file_access', 'process_activity']
            }
        )

    def _apply_patches(self, systems: List[str]) -> ResponseResult:
        """Simula aplicação de patches"""
        logger.info(f"Applying security patches to: {systems}")
        return ResponseResult(
            action=ResponseAction.PATCH.value,
            success=True,
            message=f"Security patches scheduled for {len(systems)} system(s)",
            timestamp=datetime.utcnow(),
            affected_systems=systems,
            details={
                'patch_type': 'security_update',
                'scheduled_time': 'next_maintenance_window',
                'patches_available': ['CVE-2024-001', 'CVE-2024-002']
            }
        )

    def _reset_credentials(self, systems: List[str]) -> ResponseResult:
        """Simula reset de credenciais"""
        logger.info(f"Resetting credentials for: {systems}")
        return ResponseResult(
            action=ResponseAction.RESET.value,
            success=True,
            message=f"Credential reset initiated for {len(systems)} system(s)",
            timestamp=datetime.utcnow(),
            affected_systems=systems,
            details={
                'reset_type': 'forced_password_reset',
                'affected_accounts': len(systems) * 2,  # Estimativa
                'mfa_required': True
            }
        )

    def get_response_history(self) -> List[Dict[str, Any]]:
        """Retorna histórico de respostas executadas"""
        return [response.to_dict() for response in self.executed_responses]

    def get_response_stats(self) -> Dict[str, Any]:
        """Retorna estatísticas das respostas"""
        if not self.executed_responses:
            return {
                'total_responses': 0,
                'success_rate': 0.0,
                'most_common_action': None,
                'last_response': None
            }
        
        total = len(self.executed_responses)
        successful = sum(1 for r in self.executed_responses if r.success)
        
        # Ação mais comum
        actions = [r.action for r in self.executed_responses]
        most_common = max(set(actions), key=actions.count) if actions else None
        
        return {
            'total_responses': total,
            'success_rate': round(successful / total, 2) if total > 0 else 0.0,
            'most_common_action': most_common,
            'last_response': self.executed_responses[-1].timestamp.isoformat() if self.executed_responses else None
        }
