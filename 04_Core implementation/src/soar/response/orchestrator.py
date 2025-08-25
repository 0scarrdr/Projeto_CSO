import asyncio, importlib

class ResponseOrchestrator:
    def __init__(self): self.cache = {}
    def _resolve(self, dotted: str):
        if dotted in self.cache: return self.cache[dotted]
        ns, fn = dotted.rsplit(".", 1)
        mod = importlib.import_module(f".actions.{ns}", package="soar.response")
        f = getattr(mod, fn); self.cache[dotted] = f; return f
    async def execute(self, playbook: dict, incident) -> dict:
        results = []
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
