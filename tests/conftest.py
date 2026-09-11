import pytest

from cwe.config import Settings
from cwe.sandbox import FakeSandbox
from cwe.session import SessionManager


@pytest.fixture
def manager(tmp_path):
    settings = Settings(storage_uri=str(tmp_path / "store"), enable_llm_judge=False)
    return SessionManager(settings=settings, sandbox_factory=lambda p: FakeSandbox())
