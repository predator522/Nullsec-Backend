import pytest
from app.schemas.analysis import UnifiedAnalysisRequest
from app.services.analysis.service import AnalysisService


def test_analysis_request_validation():
    payload = UnifiedAnalysisRequest(target="Example.COM", include=["dns", "dns"])
    assert payload.target == "example.com"
    assert payload.include == ["dns"]


def test_analysis_request_rejects_unknown_tool():
    with pytest.raises(ValueError):
        UnifiedAnalysisRequest(target="example.com", include=["nmap"])

@pytest.mark.asyncio
async def test_analysis_aggregates_results(monkeypatch):
    class FakeDNS:
        @staticmethod
        def lookup(domain):
            class R:
                def model_dump(self): return {"A": ["93.184.216.34"]}
            return R()
    monkeypatch.setattr('app.services.analysis.service.DNSService', FakeDNS)
    payload = UnifiedAnalysisRequest(target="example.com", include=["dns"], save_history=False)
    result = await AnalysisService.run(payload)
    assert result["status"] == "completed"
    assert "dns" in result["tool_results"]
