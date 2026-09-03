import hashlib
import base64
import json
import urllib.parse
from app.schemas.crypto import JwtAnalysis
from app.core.exceptions import ValidationError

class CryptoService:
    """Service to handle secure local cryptographic utility functions and JWT inspection."""

    @staticmethod
    def hash_data(data: str, algorithm: str) -> str:
        """Hash string data using a specified cryptographic algorithm."""
        raw_bytes = data.encode("utf-8")
        if algorithm == "md5":
            return hashlib.md5(raw_bytes).hexdigest()
        elif algorithm == "sha1":
            return hashlib.sha1(raw_bytes).hexdigest()
        elif algorithm == "sha256":
            return hashlib.sha256(raw_bytes).hexdigest()
        elif algorithm == "sha384":
            return hashlib.sha384(raw_bytes).hexdigest()
        elif algorithm == "sha512":
            return hashlib.sha512(raw_bytes).hexdigest()
        raise ValidationError("Unsupported hash algorithm requested.")

    @staticmethod
    def base64_op(data: str, operation: str) -> str:
        """Encode or decode base64 structures defensively."""
        try:
            if operation == "encode":
                return base64.b64encode(data.encode("utf-8")).decode("utf-8")
            elif operation == "decode":
                # Add padding if needed
                padded_data = data + "=" * (-len(data) % 4)
                return base64.b64decode(padded_data.encode("utf-8")).decode("utf-8", errors="replace")
        except Exception as e:
            raise ValidationError(f"Base64 operation failed: {str(e)}")
        raise ValidationError("Unsupported Base64 operation.")

    @staticmethod
    def url_op(data: str, operation: str) -> str:
        """Encode or decode URL query representations."""
        try:
            if operation == "encode":
                return urllib.parse.quote(data)
            elif operation == "decode":
                return urllib.parse.unquote(data)
        except Exception as e:
            raise ValidationError(f"URL encoding operation failed: {str(e)}")
        raise ValidationError("Unsupported URL operation.")

    @staticmethod
    def hex_op(data: str, operation: str) -> str:
        """Encode or decode hexadecimal data representations."""
        try:
            if operation == "encode":
                return data.encode("utf-8").hex()
            elif operation == "decode":
                return bytes.fromhex(data).decode("utf-8", errors="replace")
        except Exception as e:
            raise ValidationError(f"Hexadecimal conversion failed: {str(e)}")
        raise ValidationError("Unsupported Hex operation.")

    @classmethod
    def inspect_jwt(cls, token: str) -> JwtAnalysis:
        """Inspect and parse a JSON Web Token safely without validation or key requirements."""
        parts = token.strip().split(".")
        if len(parts) < 2 or len(parts) > 3:
            raise ValidationError("Invalid JWT structure. Must contain header, payload, and optional signature parts separated by dots.")
            
        header_raw, payload_raw = parts[0], parts[1]
        signature_raw = parts[2] if len(parts) == 3 else None
        
        try:
            # Decode header
            header_padded = header_raw + "=" * (-len(header_raw) % 4)
            header_bytes = base64.urlsafe_b64decode(header_padded)
            header = json.loads(header_bytes)
            
            # Decode payload
            payload_padded = payload_raw + "=" * (-len(payload_raw) % 4)
            payload_bytes = base64.urlsafe_b64decode(payload_padded)
            payload = json.loads(payload_bytes)
        except Exception as e:
            raise ValidationError(f"Failed to decode or parse JWT segments: {str(e)}")
            
        # Get signature hex if present
        sig_hex = None
        if signature_raw:
            try:
                sig_padded = signature_raw + "=" * (-len(signature_raw) % 4)
                sig_hex = base64.urlsafe_b64decode(sig_padded).hex()
            except Exception:
                sig_hex = "[Non-standard Signature segment]"
                
        return JwtAnalysis(
            header=header,
            payload=payload,
            signature_hex=sig_hex
        )
