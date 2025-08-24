from .log_detector import LogDetector
from .network_detector import NetworkDetector

class ThreatDetector:
    def __init__(self): self.detectors = [LogDetector(), NetworkDetector()]
    def classify(self, event: dict):
        for d in self.detectors:
            inc = d.classify(event)
            if inc: return inc
        return None
