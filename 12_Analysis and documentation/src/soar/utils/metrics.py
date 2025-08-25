import time, csv, os
from collections import defaultdict
class Metrics:
    def __init__(self, path: str = ".outbox/metrics.csv"):
        self.path = path; os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._start = time.monotonic()
    def observe(self, name: str, value: float):
        with open(self.path, "a", newline="") as f: csv.writer(f).writerow(["gauge", name, value, int(time.time())])
    def latency(self, name: str):
        d = time.monotonic() - self._start
        with open(self.path, "a", newline="") as f: csv.writer(f).writerow(["latency", name, d, int(time.time())])
        self._start = time.monotonic()
