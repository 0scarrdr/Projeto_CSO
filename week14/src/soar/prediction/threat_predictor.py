from collections import deque, Counter
class ThreatPredictor:
    def __init__(self, window=200): self.h = deque(maxlen=window)
    async def forecast_related_threats(self, incident) -> dict:
        self.h.append(incident.type); c = Counter(self.h); t = sum(c.values()) or 1
        return {"top_related": {k: round(v/t,3) for k,v in c.most_common(5)}}
