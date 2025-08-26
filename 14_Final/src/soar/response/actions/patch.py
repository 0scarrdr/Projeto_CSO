"""
Ação de patch/configuração para ResponseOrchestrator: aciona soar.integrations.patch.apply_patch
"""
from soar.integrations.patch import apply_patch

def patch(incident, runbook=None, parameters=None):
    runbook = runbook or getattr(incident, 'runbook', None)
    parameters = parameters or getattr(incident, 'parameters', None)
    return apply_patch(runbook_name=runbook, parameters=parameters)
