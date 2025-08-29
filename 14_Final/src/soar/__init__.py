"""
SOAR (Security Orchestration, Automation and Response) System
Complete implementation following assignment specifications
"""

__version__ = "1.0.0"
__author__ = "SOAR Team"
__description__ = "Complete SOAR system per assignment specifications"

# API
from .api.app import app

# Core Components
from .core.incident_handler import IncidentHandler
from .models.incident import Incident, IncidentSeverity, IncidentStatus, IncidentType

# Detection
from .detection.threat_detector import ThreatDetector

# Analysis
from .analysis.incident_analyzer import IncidentAnalyzer

# Response
from .response.automated_responder import AutomatedResponder

# Prediction
from .prediction.threat_predictor import ThreatPredictor

# Utils
from .utils.metrics import MetricsCollector
from .utils.logger import setup_logging

__all__ = [
    # API
    'app',
    
    # Core
    'IncidentHandler',
    'Incident',
    'IncidentSeverity',
    'IncidentStatus', 
    'IncidentType',
    
    # Detection
    'ThreatDetector',
    
    # Analysis
    'IncidentAnalyzer',
    
    # Response
    'AutomatedResponder',
    
    # Prediction
    'ThreatPredictor',
    
    # Utils
    'MetricsCollector',
    'setup_logging'
]
