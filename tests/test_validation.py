import pytest
from app.utils.validation import (
    is_valid_domain,
    is_valid_ip,
    is_private_ip,
    validate_domain_or_ip,
    validate_domain_only,
    validate_port,
    validate_cve_id,
    validate_url_safe
)
from app.core.exceptions import ValidationError, SSRFError

def test_domain_validation():
    """Verify syntactic validation of domains, rejecting internal addresses."""
    assert is_valid_domain("example.com") is True
    assert is_valid_domain("sub.domain.co.uk") is True
    assert is_valid_domain("localhost") is False
    assert is_valid_domain("my-internal.local") is False
    assert is_valid_domain("onion-address.onion") is False
    assert is_valid_domain("not_a_domain") is False

def test_ip_validation():
    """Verify identification of valid IPv4 and IPv6 addresses."""
    assert is_valid_ip("1.1.1.1") is True
    assert is_valid_ip("2606:4700:4700::1111") is True
    assert is_valid_ip("999.999.999.999") is False
    assert is_valid_ip("abc") is False

def test_private_ip_detection():
    """Ensure private and loopback ranges are flagged as private for SSRF prevention."""
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("192.168.1.50") is True
    assert is_private_ip("169.254.169.254") is True
    assert is_private_ip("8.8.8.8") is False

def test_validate_domain_or_ip():
    """Test standard target input validation."""
    assert validate_domain_or_ip("example.com") == "example.com"
    assert validate_domain_or_ip("8.8.8.8") == "8.8.8.8"
    
    with pytest.raises(ValidationError):
        validate_domain_or_ip("127.0.0.1")
        
    with pytest.raises(ValidationError):
        validate_domain_or_ip("not-a-valid-target!!")

def test_validate_domain_only():
    """Ensure strict domain-only checker rejects IPs or paths."""
    assert validate_domain_only("example.com") == "example.com"
    with pytest.raises(ValidationError):
        validate_domain_only("8.8.8.8")
    with pytest.raises(ValidationError):
        validate_domain_only("http://example.com")

def test_validate_port():
    """Test port bounds."""
    assert validate_port(80) == 80
    assert validate_port(65535) == 65535
    with pytest.raises(ValidationError):
        validate_port(0)
    with pytest.raises(ValidationError):
        validate_port(70000)

def test_validate_cve_id():
    """Test CVE format correctness."""
    assert validate_cve_id("CVE-2023-1234") == "CVE-2023-1234"
    assert validate_cve_id("cve-1999-99999") == "CVE-1999-99999"
    with pytest.raises(ValidationError):
        validate_cve_id("CVE-ABC-1234")
    with pytest.raises(ValidationError):
        validate_cve_id("1234-CVE-2023")

def test_validate_url_safe():
    """Verify URL checks block SSRF targets and invalid structures."""
    assert validate_url_safe("https://example.com/api") == "https://example.com/api"
    
    with pytest.raises(ValidationError):
        validate_url_safe("ftp://example.com")
        
    with pytest.raises(SSRFError):
        validate_url_safe("http://127.0.0.1/metadata")
