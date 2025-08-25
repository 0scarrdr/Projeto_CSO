from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List

@dataclass
class Incident:
    id: str
    type: str
    severity: str
    source: str
    detected_at: datetime
    attributes: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[str] = field(default_factory=list)
