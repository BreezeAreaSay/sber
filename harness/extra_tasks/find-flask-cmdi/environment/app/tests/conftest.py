import httpx, pytest

@pytest.fixture
def client():
    return httpx.Client(base_url="http://127.0.0.1:5000", timeout=10.0)
