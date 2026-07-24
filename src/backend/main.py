"""
MiniVault — FastAPI entry point.

Run with:
    uvicorn main:app --reload
"""

from fastapi import FastAPI

app = FastAPI(title="MiniVault", version="1.0.0")


@app.get("/")
def root() -> dict:
    """Health check."""
    return {"service": "MiniVault", "status": "ok"}

from typing import Any
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

from src.kv import engine as kv_engine
from src.core.vault import VaultLocked
from src.auth.session import Unauthenticated
from src.kv.engine import PermissionDenied, NotFound, TagMismatch

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def get_token(token: str = Depends(oauth2_scheme)) -> str:
    return token

def handle_common_exceptions(exc: Exception):
    if isinstance(exc, VaultLocked):
        raise HTTPException(status_code=423, detail="VAULT_LOCKED")
    if isinstance(exc, Unauthenticated):
        raise HTTPException(status_code=401, detail="UNAUTHENTICATED")
    if isinstance(exc, PermissionDenied):
        raise HTTPException(status_code=403, detail="PERMISSION_DENIED")
    if isinstance(exc, NotFound):
        raise HTTPException(status_code=404, detail="NOT_FOUND")
    if isinstance(exc, TagMismatch):
        raise HTTPException(status_code=400, detail="TAG_MISMATCH")
    raise HTTPException(status_code=500, detail="INTERNAL_SERVER_ERROR")

class KVWriteRequest(BaseModel):
    path: str
    data: dict[str, Any]

@app.post("/kv/write", status_code=status.HTTP_201_CREATED)
def kv_write(req: KVWriteRequest, token: str = Depends(get_token)):
    try:
        res = kv_engine.write(req.path, req.data, token)
        return {"status": "success", "metadata": res}
    except Exception as e:
        handle_common_exceptions(e)

@app.get("/kv/read")
def kv_read(path: str, token: str = Depends(get_token)):
    try:
        data = kv_engine.read(path, token)
        return {"status": "success", "data": data}
    except Exception as e:
        handle_common_exceptions(e)

from src.kv import versioning as kv_versioning

@app.get("/kv/version/{version}")
def kv_read_version(path: str, version: int, token: str = Depends(get_token)):
    try:
        data = kv_versioning.read_version(path, version, token)
        return {"status": "success", "version": version, "data": data}
    except Exception as e:
        handle_common_exceptions(e)

@app.delete("/kv/delete")
def kv_delete(path: str, token: str = Depends(get_token)):
    try:
        kv_engine.delete(path, token)
        return {"status": "success"}
    except Exception as e:
        handle_common_exceptions(e)

# --- TRANSIT ENGINE ROUTES ---

from src.transit import keys as transit_keys
from src.transit import crypto as transit_crypto
from src.transit import signing as transit_signing
from src.transit.keys import InvalidKeyUsage, KeyNotFound, KeyAlreadyExists
from src.transit.signing import MessageType, SigningAlgorithm

def handle_transit_exceptions(exc: Exception):
    if isinstance(exc, InvalidKeyUsage):
        raise HTTPException(status_code=400, detail="INVALID_KEY_USAGE")
    if isinstance(exc, KeyNotFound):
        raise HTTPException(status_code=404, detail="KEY_NOT_FOUND")
    if isinstance(exc, KeyAlreadyExists):
        raise HTTPException(status_code=409, detail="KEY_ALREADY_EXISTS")
    if isinstance(exc, ValueError):
        raise HTTPException(status_code=400, detail=str(exc))
    handle_common_exceptions(exc)

class CreateKeyRequest(BaseModel):
    key_name: str

@app.post("/transit/keys", status_code=status.HTTP_201_CREATED)
def transit_create_key(req: CreateKeyRequest, token: str = Depends(get_token)):
    try:
        res = transit_keys.create_key(req.key_name, token)
        return {"status": "success", "data": res}
    except Exception as e:
        handle_transit_exceptions(e)

@app.get("/transit/keys")
def transit_list_keys(token: str = Depends(get_token)):
    try:
        keys = transit_keys.list_keys(token)
        return {"status": "success", "data": keys}
    except Exception as e:
        handle_transit_exceptions(e)

from src.transit import rotation as transit_rotation

@app.post("/transit/keys/{key_name}/rotate", status_code=status.HTTP_200_OK)
def transit_rotate_key(key_name: str, token: str = Depends(get_token)):
    try:
        res = transit_rotation.rotate_key(key_name, token)
        return {"status": "success", "data": res}
    except Exception as e:
        handle_transit_exceptions(e)

@app.delete("/transit/keys/{key_name}")
def transit_revoke_key(key_name: str, token: str = Depends(get_token)):
    try:
        transit_keys.revoke_key(key_name, token)
        return {"status": "success"}
    except Exception as e:
        handle_transit_exceptions(e)

class EncryptRequest(BaseModel):
    key_name: str
    plaintext_b64: str

@app.post("/transit/encrypt")
def transit_encrypt(req: EncryptRequest, token: str = Depends(get_token)):
    try:
        ct = transit_crypto.encrypt(req.key_name, req.plaintext_b64, token)
        return {"status": "success", "ciphertext": ct}
    except Exception as e:
        handle_transit_exceptions(e)

class DecryptRequest(BaseModel):
    ciphertext: str

@app.post("/transit/decrypt")
def transit_decrypt(req: DecryptRequest, token: str = Depends(get_token)):
    try:
        pt = transit_crypto.decrypt(req.ciphertext, token)
        return {"status": "success", "plaintext_b64": pt}
    except Exception as e:
        handle_transit_exceptions(e)

from src.transit import acl as vault_acl

class GrantRequest(BaseModel):
    resource_type: str
    resource_id: str
    grantee_email: str
    permissions: str

@app.post("/acl/grant", status_code=status.HTTP_200_OK)
def acl_grant(req: GrantRequest, token: str = Depends(get_token)):
    try:
        res = vault_acl.grant_access(
            req.resource_type, req.resource_id, req.grantee_email, req.permissions, token
        )
        return res
    except Exception as e:
        handle_transit_exceptions(e)

class CreateSigningKeyRequest(BaseModel):
    key_name: str
    signing_algorithm: SigningAlgorithm

@app.post("/transit/signing-keys", status_code=status.HTTP_201_CREATED)
def transit_create_signing_key(req: CreateSigningKeyRequest, token: str = Depends(get_token)):
    try:
        res = transit_signing.create_signing_key(req.key_name, req.signing_algorithm, token)
        return {"status": "success", "data": res}
    except Exception as e:
        handle_transit_exceptions(e)

class SignRequest(BaseModel):
    key_name: str
    message_b64: str
    message_type: MessageType

@app.post("/transit/sign")
def transit_sign(req: SignRequest, token: str = Depends(get_token)):
    try:
        res = transit_signing.sign(req.key_name, req.message_b64, req.message_type, token)
        return {"status": "success", "data": res}
    except Exception as e:
        handle_transit_exceptions(e)

class VerifyRequest(BaseModel):
    key_name: str
    message_b64: str
    message_type: MessageType
    signature_b64: str

@app.post("/transit/verify")
def transit_verify(req: VerifyRequest, token: str = Depends(get_token)):
    try:
        res = transit_signing.verify(req.key_name, req.message_b64, req.message_type, req.signature_b64, token)
        return {"status": "success", "data": res}
    except Exception as e:
        handle_transit_exceptions(e)
