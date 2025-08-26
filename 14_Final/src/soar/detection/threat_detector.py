from .log_detector import LogDetector
from .network_detector import NetworkDetector

class ThreatDetector:

    def __init__(self):
        self.detectors = [LogDetector(), NetworkDetector()]
        self.custom_rules = []
        # Integração Threat Intelligence
        from soar.integrations.threat_intel import check_ip_threat, check_domain_threat
        self.threat_intel = [lambda event: check_ip_threat(event.get("src_ip")),
                             lambda event: check_domain_threat(event.get("domain"))]

    def add_custom_rule(self, func, label):
        self.custom_rules.append((func, label))

    def add_threat_intel(self, ti_func):
        self.threat_intel.append(ti_func)

    def classify(self, event: dict):
        # Detetores principais
        for d in self.detectors:
            inc = d.classify(event)
            if inc: return inc
        # Regras customizadas
        for func, label in self.custom_rules:
            if func(event):
                return {"type": label, "event": event}
        # Threat Intelligence
        for ti_func in self.threat_intel:
            ti_result = ti_func(event)
            if ti_result:
                return ti_result
        return None
