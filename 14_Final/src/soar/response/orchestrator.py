import asyncio, importlib
import logging, traceback

class ResponseOrchestrator:
    def __init__(self): self.cache = {}
    def _resolve(self, dotted: str):
        if dotted in self.cache: return self.cache[dotted]
        ns, fn = dotted.rsplit(".", 1)
        # Suporte para patch/configuração
        if ns == "patch":
            mod = importlib.import_module(f".actions.patch", package="soar.response")
        else:
            mod = importlib.import_module(f".actions.{ns}", package="soar.response")
        f = getattr(mod, fn); self.cache[dotted] = f; return f
    async def execute(self, playbook: dict, incident) -> dict:
        
        logger = logging.getLogger("orchestrator")
        results = []
        try:
            for step in playbook.get("steps", []):
                action = step["action"]; params = dict(step.get("params", {}))
                for k, v in list(params.items()):
                    if isinstance(v, str) and v.startswith("INCIDENT_"):
                        key = v.replace("INCIDENT_","").lower()
                        params[k] = incident.attributes.get(key) or getattr(incident, key, None)
                fn = self._resolve(action)
                res = await fn(incident, **params) if asyncio.iscoroutinefunction(fn) else fn(incident, **params)
                results.append({"action": action, "result": res})
            return {"status": "completed", "steps": results}
        except Exception as e:
            logger.error(f"Erro em orchestrator.execute: {e}\nTraceback:\n{traceback.format_exc()}")
            raise
