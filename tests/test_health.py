from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_check_endpoint():
    """Test that GET /api/v1/health responds with 200 and expected health stats."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    
    data = response.json()
    assert data["success"] is True
    assert data["status"] == "healthy"
    assert "services" in data
    assert "mongodb" in data["services"]
    assert "redis" in data["services"]
