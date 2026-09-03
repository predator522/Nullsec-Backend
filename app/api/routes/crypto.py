from fastapi import APIRouter, Depends
from app.schemas.crypto import (
    HashRequest, HashResponse,
    Base64Request, Base64Response,
    UrlRequest, UrlResponse,
    HexRequest, HexResponse,
    JwtInspectRequest, JwtInspectResponse
)
from app.services.crypto.service import CryptoService

router = APIRouter()

@router.post("/hash", response_model=HashResponse)
async def crypto_hash(payload: HashRequest):
    """Generate MD5 or SHA cryptographic checksums locally."""
    res = CryptoService.hash_data(payload.data, payload.algorithm)
    return HashResponse(
        success=True,
        algorithm=payload.algorithm,
        hash_result=res
    )

@router.post("/base64", response_model=Base64Response)
async def crypto_base64(payload: Base64Request):
    """Safely encode or decode strings to/from Base64 notation locally."""
    res = CryptoService.base64_op(payload.data, payload.operation)
    return Base64Response(
        success=True,
        operation=payload.operation,
        result=res
    )

@router.post("/url", response_model=UrlResponse)
async def crypto_url(payload: UrlRequest):
    """Safely url-encode or url-decode query parameter segments locally."""
    res = CryptoService.url_op(payload.data, payload.operation)
    return UrlResponse(
        success=True,
        operation=payload.operation,
        result=res
    )

@router.post("/hex", response_model=HexResponse)
async def crypto_hex(payload: HexRequest):
    """Convert raw text to and from Hexadecimal notation locally."""
    res = CryptoService.hex_op(payload.data, payload.operation)
    return HexResponse(
        success=True,
        operation=payload.operation,
        result=res
    )

@router.post("/jwt", response_model=JwtInspectResponse)
async def crypto_jwt(payload: JwtInspectRequest):
    """Surgically parse and decode JWT payload and header segments locally without validating signatures."""
    res = CryptoService.inspect_jwt(payload.token)
    return JwtInspectResponse(
        success=True,
        analysis=res
    )
