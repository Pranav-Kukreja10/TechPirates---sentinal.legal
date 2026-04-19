import logging
import json
from collections import defaultdict

class AuditLogger:
    def __init__(self):
        self.logger = logging.getLogger("SentinalLegal.Audit")
        self.logger.setLevel(logging.INFO)
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter(
            '{"ts":"%(asctime)s","svc":"audit","msg":%(message)s}',
            datefmt="%Y-%m-%dT%H:%M:%SZ"
        ))
        self.logger.addHandler(h)
        self._metrics: dict[str, list] = defaultdict(list)

    def log(self, event: str, **kw):
        self.logger.info(json.dumps({"event": event, **kw}))

    def record_latency(self, label: str, seconds: float):
        self._metrics[label].append(round(seconds, 3))
        if len(self._metrics[label]) > 500:
            self._metrics[label] = self._metrics[label][-500:]

    def get_metrics(self) -> dict:
        out = {}
        for label, vals in self._metrics.items():
            if vals:
                out[label] = {
                    "count": len(vals),
                    "avg_s": round(sum(vals) / len(vals), 3),
                    "min_s": min(vals),
                    "max_s": max(vals),
                    "p95_s": sorted(vals)[int(len(vals) * 0.95)] if len(vals) >= 20 else None,
                }
        return out

audit = AuditLogger()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SentinalLegal.App")
