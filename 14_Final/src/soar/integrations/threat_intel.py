"""
Threat Intelligence integration: exemplo de consulta a feeds externos.
"""
def check_ip_threat(ip):
    # Simulação: IPs maliciosos conhecidos
    malicious_ips = {"192.168.1.1", "10.0.0.2"}
    if ip in malicious_ips:
        return {"type": "threat_intel", "severity": "critical", "ip": ip, "malicious": True}
    return None

def check_domain_threat(domain):
    # Simulação: domínios maliciosos conhecidos
    malicious_domains = {"bad.com", "evil.org"}
    if domain in malicious_domains:
        return {"type": "threat_intel", "severity": "critical", "domain": domain, "malicious": True}
    return None
