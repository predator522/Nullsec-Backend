from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
import pytest
import dns.resolver
from app.main import app
from app.services.dns.service import DNSService
from app.core.exceptions import DNSError

client = TestClient(app)

class MockARecord:
    def __init__(self, ip):
        self.address = ip

class MockMXRecord:
    def __init__(self, pref, exch):
        self.preference = pref
        self.exchange = MagicMock()
        self.exchange.to_text.return_value = exch

class MockNSRecord:
    def __init__(self, target):
        self.target = MagicMock()
        self.target.to_text.return_value = target

class MockTXTRecord:
    def __init__(self, text):
        self.strings = [text.encode()]

class MockSOARecord:
    def __init__(self):
        self.mname = MagicMock()
        self.mname.to_text.return_value = "ns1.example.com"
        self.rname = MagicMock()
        self.rname.to_text.return_value = "hostmaster.example.com"
        self.serial = 2023102401
        self.refresh = 7200
        self.retry = 3600
        self.expire = 1209600
        self.minimum = 86400

def mock_resolver_resolve(qname, rdatatype):
    """Mocks standard DNS resolver behavior for testing."""
    if qname == "nonexistent.com":
        raise dns.resolver.NXDOMAIN()
        
    if rdatatype == "A":
        return [MockARecord("93.184.216.34")]
    elif rdatatype == "AAAA":
        return [MockARecord("2606:2800:220:1:248:1893:25c8:1946")]
    elif rdatatype == "MX":
        return [MockMXRecord(10, "mail.example.com")]
    elif rdatatype == "NS":
        return [MockNSRecord("ns1.example.com")]
    elif rdatatype == "TXT":
        return [MockTXTRecord("v=spf1 -all")]
    elif rdatatype == "CNAME":
        return [MockNSRecord("cname.example.com")]
    elif rdatatype == "SOA":
        return [MockSOARecord()]
        
    raise dns.resolver.NoAnswer()

@patch("dns.resolver.Resolver.resolve", side_effect=mock_resolver_resolve)
@patch("app.services.dns.service.check_ssrf_and_get_ip", return_value="93.184.216.34")
def test_dns_service_lookup_success(mock_ssrf, mock_resolve):
    """Test that DNSService correctly aggregates and parses records on valid lookups."""
    records = DNSService.lookup("example.com")
    
    assert "93.184.216.34" in records.A
    assert "2606:2800:220:1:248:1893:25c8:1946" in records.AAAA
    assert "10 mail.example.com" in records.MX
    assert "ns1.example.com" in records.NS
    assert "v=spf1 -all" in records.TXT
    assert "cname.example.com" in records.CNAME
    assert "mname=ns1.example.com" in records.SOA[0]

@patch("dns.resolver.Resolver.resolve", side_effect=mock_resolver_resolve)
@patch("app.services.dns.service.check_ssrf_and_get_ip", return_value="93.184.216.34")
def test_dns_endpoint_success(mock_ssrf, mock_resolve):
    """Test that POST /api/v1/dns/lookup successfully processes payload and yields output."""
    response = client.post("/api/v1/dns/lookup", json={"domain": "example.com"})
    assert response.status_code == 200
    
    data = response.json()
    assert data["success"] is True
    assert data["domain"] == "example.com"
    assert "records" in data
    assert "A" in data["records"]
    assert "93.184.216.34" in data["records"]["A"]

def test_dns_endpoint_validation_failure():
    """Test that POST /api/v1/dns/lookup rejects invalid domains with standard 400 validation error."""
    # Invalid domain string
    response = client.post("/api/v1/dns/lookup", json={"domain": "invalid_domain!!!"})
    assert response.status_code == 400
    
    data = response.json()
    assert data["success"] is False
    assert data["error"]["code"] == "INVALID_TARGET"

@patch("dns.resolver.Resolver.resolve", side_effect=mock_resolver_resolve)
def test_dns_endpoint_ssrf_failure(mock_resolve):
    """Test that POST /api/v1/dns/lookup rejects loopback/private destinations."""
    response = client.post("/api/v1/dns/lookup", json={"domain": "localhost"})
    assert response.status_code == 400  # Validation checks syntactic localness first
    
    data = response.json()
    assert data["success"] is False
    assert data["error"]["code"] == "INVALID_TARGET"
