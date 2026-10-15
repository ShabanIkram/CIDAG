import json
from pathlib import Path


class BaseCollector:
    def collect(self) -> dict:
        raise NotImplementedError


class MockCollector(BaseCollector):
    def __init__(self, path: str | None = None):
        self.path = Path(path) if path else Path(__file__).resolve().parents[1] / "data" / "mock_aws.json"

    def collect(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8"))
