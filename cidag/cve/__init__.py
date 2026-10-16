"""CVE correlation: NVD mirror, CPE matching, and service->CVE engine."""
from .cpe import DetectedService, version_lt, version_lte, version_gte, match_cpe
from .nvd import CVE, NVDClient
from .engine import CVEEngine, SEED_RULES

__all__ = [
    "DetectedService",
    "CVE",
    "NVDClient",
    "CVEEngine",
    "SEED_RULES",
    "version_lt",
    "version_lte",
    "version_gte",
    "match_cpe",
]
