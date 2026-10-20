import json
from pathlib import Path


class CloudCredentialsError(RuntimeError):
    """Live collection requested but cloud credentials do not resolve."""


class CloudCollectionError(RuntimeError):
    """A cloud collector failed (missing SDK, denied API, partial inventory).

    Continuing with a partial/empty inventory would silently turn "we could not
    query" into findings like "No CloudTrail configured" -- fabricated positives.
    """


class BaseCollector:
    def collect(self) -> dict:
        raise NotImplementedError


class MockCollector(BaseCollector):
    def __init__(self, path: str | None = None, cloud: str = "aws"):
        data_dir = Path(__file__).resolve().parents[1] / "data"
        self.path = Path(path) if path else data_dir / f"mock_{cloud}.json"

    def collect(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8"))
