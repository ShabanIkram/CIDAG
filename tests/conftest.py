import json
from pathlib import Path

import pytest

DATA = Path(__file__).resolve().parents[1] / "cidag" / "data" / "mock_aws.json"


@pytest.fixture
def inventory() -> dict:
    return json.loads(DATA.read_text(encoding="utf-8"))