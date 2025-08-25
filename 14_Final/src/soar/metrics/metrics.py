"""
Metrics collection for SOAR system using Prometheus client.
"""

from prometheus_client import Counter, Histogram

# Contador de incidentes por tipo
INCIDENTS_TOTAL = Counter(
    "soar_incidents_total",
    "Total de incidentes processados",
    ["type"]
)

# Latência total do pipeline (deteção → resposta)
INCIDENT_LATENCY = Histogram(
    "soar_incident_latency_seconds",
    "Latência do processamento do incidente"
)

# Contador de ações executadas
ACTIONS_TOTAL = Counter(
    "soar_actions_total",
    "Total de ações executadas",
    ["action"]
)
