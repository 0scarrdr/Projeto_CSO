"""
Incident Data Model
Core incident representation for the SOAR system
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional
from enum import Enum
import uuid

class IncidentType(Enum):
    """Types of security incidents according to assignment and tests"""
    MALWARE = "malware"
    NETWORK_ATTACK = "network_attack"
    DATA_BREACH = "data_breach"
    DATA_EXFILTRATION = "data_exfiltration"
    BRUTE_FORCE = "brute_force"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    UNKNOWN = "unknown"
    SYSTEM_FAILURE = "system_failure"
    POLICY_VIOLATION = "policy_violation"
    ZERO_DAY = "zero_day"

class IncidentSeverity(Enum):
    """Incident severity levels (ordered for comparisons)"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    # Enable semantic comparisons like >= between severities
    _order = {LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4}

    def __lt__(self, other):
        if isinstance(other, IncidentSeverity):
            return self._order[self] < self._order[other]
        return NotImplemented

    def __le__(self, other):
        if isinstance(other, IncidentSeverity):
            return self._order[self] <= self._order[other]
        return NotImplemented

    def __gt__(self, other):
        if isinstance(other, IncidentSeverity):
            return self._order[self] > self._order[other]
        return NotImplemented

    def __ge__(self, other):
        if isinstance(other, IncidentSeverity):
            return self._order[self] >= self._order[other]
        return NotImplemented

class IncidentStatus(Enum):
    """Incident processing status"""
    NEW = "new"
    DETECTED = "detected"
    ANALYZING = "analyzing"
    RESPONDING = "responding"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"

@dataclass
class Incident:
    """
    Core incident data model
    Represents a security incident throughout its lifecycle
    """
    
    # Basic identification
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Classification
    incident_type: Optional[IncidentType] = None
    severity: Optional[IncidentSeverity] = None
    status: IncidentStatus = IncidentStatus.NEW
    
    # Source information
    source_system: str = ""
    detection_method: str = ""
    
    # Description
    title: str = ""
    description: str = ""
    
    # Technical data
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    affected_systems: List[str] = field(default_factory=list)
    threat_indicators: List[Dict[str, Any]] = field(default_factory=list)
    
    # Analysis results
    confidence_score: float = 0.0
    risk_score: float = 0.0
    impact_assessment: Dict[str, Any] = field(default_factory=dict)
    analysis_results: Dict[str, Any] = field(default_factory=dict)
    
    # Response tracking
    response_actions: List[Dict[str, Any]] = field(default_factory=list)
    containment_status: bool = False
    eradication_complete: bool = False
    recovery_complete: bool = False
    
    # Timeline
    detection_time: Optional[datetime] = None
    response_start_time: Optional[datetime] = None
    containment_time: Optional[datetime] = None
    eradication_time: Optional[datetime] = None
    recovery_time: Optional[datetime] = None
    closure_time: Optional[datetime] = None
    
    # Metrics
    processing_metrics: Dict[str, float] = field(default_factory=dict)
    
    # Evidence and artifacts
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    
    # Predictions and related threats
    predicted_threats: List[Dict[str, Any]] = field(default_factory=list)
    related_incidents: List[str] = field(default_factory=list)
    
    # Additional metadata
    tags: List[str] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization processing"""
        if self.detection_time is None:
            self.detection_time = self.timestamp
    
    def update_status(self, new_status: IncidentStatus, timestamp: Optional[datetime] = None):
        """Update incident status with timestamp tracking"""
        if timestamp is None:
            timestamp = datetime.now()
            
        self.status = new_status
        
        # Update relevant timestamps
        if new_status == IncidentStatus.RESPONDING and self.response_start_time is None:
            self.response_start_time = timestamp
        elif new_status == IncidentStatus.CONTAINED and self.containment_time is None:
            self.containment_time = timestamp
            self.containment_status = True
        elif new_status == IncidentStatus.ERADICATED and self.eradication_time is None:
            self.eradication_time = timestamp
            self.eradication_complete = True
        elif new_status == IncidentStatus.RECOVERED and self.recovery_time is None:
            self.recovery_time = timestamp
            self.recovery_complete = True
        elif new_status == IncidentStatus.CLOSED and self.closure_time is None:
            self.closure_time = timestamp
    
    def add_response_action(self, action_type: str, description: str, result: str = "pending"):
        """Add a response action to the incident"""
        action = {
            "type": action_type,
            "description": description,
            "result": result,
            "timestamp": datetime.now().isoformat()
        }
        self.response_actions.append(action)
    
    def add_evidence(self, evidence_type: str, data: Dict[str, Any], source: str = ""):
        """Add evidence to the incident"""
        evidence_item = {
            "type": evidence_type,
            "data": data,
            "source": source,
            "timestamp": datetime.now().isoformat(),
            "id": str(uuid.uuid4())
        }
        self.evidence.append(evidence_item)
    
    def calculate_risk_score(self) -> float:
        """Calculate overall risk score based on various factors"""
        base_score = 0.0
        
        # Severity contribution
        severity_weights = {
            IncidentSeverity.LOW: 0.25,
            IncidentSeverity.MEDIUM: 0.5,
            IncidentSeverity.HIGH: 0.75,
            IncidentSeverity.CRITICAL: 1.0
        }
        
        if self.severity:
            base_score += severity_weights[self.severity] * 40
        
        # Confidence score contribution
        base_score += self.confidence_score * 30
        
        # Impact factors
        if len(self.affected_systems) > 0:
            base_score += min(len(self.affected_systems) * 5, 20)
        
        # Threat indicators
        if len(self.threat_indicators) > 0:
            base_score += min(len(self.threat_indicators) * 2, 10)
        
        self.risk_score = min(base_score, 100.0)
        return self.risk_score
