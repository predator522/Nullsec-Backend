import pytest
from app.services.crypto.service import CryptoService
from app.core.exceptions import ValidationError

def test_crypto_hashing():
    """Verify standard md5 and sha hashing returns correct values."""
    assert CryptoService.hash_data("test", "md5") == "098f6bcd4621d373cade4e832627b4f6"
    assert CryptoService.hash_data("hello", "sha256") == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    
    with pytest.raises(ValidationError):
        CryptoService.hash_data("hello", "invalid_algorithm")

def test_base64_conversion():
    """Verify correct encoding and decoding under base64."""
    assert CryptoService.base64_op("hello world", "encode") == "aGVsbG8gd29ybGQ="
    assert CryptoService.base64_op("aGVsbG8gd29ybGQ=", "decode") == "hello world"

def test_url_conversion():
    """Verify correct url encoding/decoding."""
    assert CryptoService.url_op("hello?name=world&val=ok", "encode") == "hello%3Fname%3Dworld%26val%3Dok"
    assert CryptoService.url_op("hello%3Fname%3Dworld%26val%3Dok", "decode") == "hello?name=world&val=ok"

def test_hex_conversion():
    """Verify correct hex encoding/decoding."""
    assert CryptoService.hex_op("hello", "encode") == "68656c6c6f"
    assert CryptoService.hex_op("68656c6c6f", "decode") == "hello"

def test_jwt_decoder():
    """Verify safe JWT header/payload decoding without signature check."""
    # A standard JWT header and payload mock (without signature)
    # Header: {"alg":"HS256","typ":"JWT"}
    # Payload: {"sub":"1234567890","name":"John Doe","admin":true}
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.sig_part"
    
    res = CryptoService.inspect_jwt(token)
    assert res.header["alg"] == "HS256"
    assert res.payload["name"] == "John Doe"
    assert res.payload["admin"] is True
    assert res.signature_hex is not None
