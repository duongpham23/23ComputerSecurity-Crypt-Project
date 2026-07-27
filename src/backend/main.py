"""
MiniVault — FastAPI entry point.

Run with:
    uvicorn main:app --reload
"""

import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

from src.auth.session import (
    AccountLocked,
    RegistrationError,
    Unauthenticated,
)
from src.auth.session import (
    login as auth_login,
)
from src.auth.session import (
    logout as auth_logout,
)
from src.auth.session import (
    register as auth_register,
)
from src.core.vault import VaultLocked, init_vault, is_initialized, is_unlocked, unlock_vault
from src.kv import engine as kv_engine
from src.kv import versioning as kv_versioning
from src.kv.engine import NotFound, PermissionDenied, TagMismatch
from src.storage.db import init_db
from src.transit import acl as vault_acl
from src.transit import crypto as transit_crypto
from src.transit import keys as transit_keys
from src.transit import rotation as transit_rotation
from src.transit import signing as transit_signing
from src.transit.keys import InvalidKeyUsage, KeyAlreadyExists, KeyNotFound
from src.transit.signing import MessageType, SigningAlgorithm


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise the database on startup."""
    init_db()
    yield


app = FastAPI(title="MiniVault", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login", auto_error=False)


def get_token(token: str = Depends(oauth2_scheme)) -> str:
    """Extract Bearer token from Authorization header. Returns empty string if missing."""
    return token or ""


def handle_common_exceptions(exc: Exception):
    if isinstance(exc, VaultLocked):
        raise HTTPException(status_code=423, detail="VAULT_LOCKED")
    if isinstance(exc, Unauthenticated):
        raise HTTPException(status_code=401, detail="UNAUTHENTICATED")
    if isinstance(exc, AccountLocked):
        raise HTTPException(
            status_code=429,
            detail={"code": "ACCOUNT_LOCKED", "lock_expires_at": exc.lock_until},
        )
    if isinstance(exc, PermissionDenied):
        raise HTTPException(status_code=403, detail="PERMISSION_DENIED")
    if isinstance(exc, NotFound):
        raise HTTPException(status_code=404, detail="NOT_FOUND")
    if isinstance(exc, TagMismatch):
        raise HTTPException(status_code=400, detail="TAG_MISMATCH")
    raise HTTPException(status_code=500, detail=str(exc))


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


# --- HEALTH ---


@router.get("/")
@router.get("/health")
def health() -> dict:
    """Health check."""
    return {"service": "MiniVault", "status": "ok"}


# --- VAULT LIFECYCLE ---


@router.get("/vault")
def vault_status():
    return {"initialized": is_initialized(), "locked": not is_unlocked()}


class VaultPassphraseRequest(BaseModel):
    passphrase: str


@router.post("/vault/init")
def post_vault_init(req: VaultPassphraseRequest):
    init_vault(req.passphrase)
    return {"status": "success"}


@router.post("/vault/unlock")
def post_vault_unlock(req: VaultPassphraseRequest):
    try:
        unlock_vault(req.passphrase)
        return {"status": "success"}
    except Exception as e:
        handle_common_exceptions(e)


# --- USER & SESSION ---


class UserRegisterRequest(BaseModel):
    email: str
    passphrase: str


@router.post("/users", status_code=status.HTTP_201_CREATED)
def register_user(req: UserRegisterRequest):
    """Register a new user. Passphrase is hashed with bcrypt server-side."""
    try:
        user = auth_register(req.email, req.passphrase)
        return {
            "user": {
                "email": user["email"],
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(user["created_at"])),
            }
        }
    except RegistrationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class SessionLoginRequest(BaseModel):
    email: str
    passphrase: str


@router.post("/auth/sessions", status_code=status.HTTP_201_CREATED)
def login_session(req: SessionLoginRequest):
    """Authenticate credentials and issue a 30-minute session token."""
    try:
        session = auth_login(req.email, req.passphrase)
        return {
            "token": session["token"],
            "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(session["expires_at"])),
            "user": {"email": session["email"]},
        }
    except AccountLocked as e:
        raise HTTPException(
            status_code=429,
            detail={"code": "ACCOUNT_LOCKED", "lock_expires_at": e.lock_until},
        )
    except Unauthenticated:
        raise HTTPException(status_code=401, detail="UNAUTHENTICATED")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/auth/sessions/current", status_code=status.HTTP_204_NO_CONTENT)
def logout_session(token: str = Depends(get_token)):
    """Invalidate the current session token."""
    auth_logout(token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- AUDIT LOGS ---


@router.get("/audit/events")
def list_audit_events():
    return {"events": [], "total": 0, "page": 1, "page_size": 50}


# --- KV ENGINE ROUTES ---


class KVWriteRequest(BaseModel):
    path: str
    data: dict[str, Any]


@router.post("/kv/write", status_code=status.HTTP_201_CREATED)
def kv_write(req: KVWriteRequest, token: str = Depends(get_token)):
    try:
        res = kv_engine.write(req.path, req.data, token)
        return {"status": "success", "metadata": res}
    except Exception as e:
        handle_common_exceptions(e)


@router.get("/kv/list")
def kv_list(token: str = Depends(get_token)):
    try:
        secrets = kv_engine.list_secrets(token)
        return {"secrets": secrets}
    except Exception as e:
        handle_common_exceptions(e)


@router.get("/kv/read")
def kv_read(path: str, token: str = Depends(get_token)):
    try:
        data = kv_engine.read(path, token)
        return {"status": "success", "data": data}
    except Exception as e:
        handle_common_exceptions(e)


@router.get("/kv/version/{version}")
def kv_read_version(path: str, version: int, token: str = Depends(get_token)):
    try:
        data = kv_versioning.read_version(path, version, token)
        return {"status": "success", "version": version, "data": data}
    except Exception as e:
        handle_common_exceptions(e)


@router.delete("/kv/delete")
def kv_delete(path: str, token: str = Depends(get_token)):
    try:
        kv_engine.delete(path, token)
        return {"status": "success"}
    except Exception as e:
        handle_common_exceptions(e)


# --- TRANSIT ENGINE ROUTES ---


class CreateKeyRequest(BaseModel):
    key_name: str


@router.post("/transit/keys", status_code=status.HTTP_201_CREATED)
def transit_create_key(req: CreateKeyRequest, token: str = Depends(get_token)):
    try:
        res = transit_keys.create_key(req.key_name, token)
        return {"status": "success", "data": res}
    except Exception as e:
        handle_transit_exceptions(e)


@router.get("/transit/keys")
def transit_list_keys(token: str = Depends(get_token)):
    try:
        keys = transit_keys.list_keys(token, usage="ENCRYPT_DECRYPT")
        return {"keys": keys}
    except Exception as e:
        handle_transit_exceptions(e)


@router.post("/transit/keys/{key_name}/rotate", status_code=status.HTTP_200_OK)
def transit_rotate_key(key_name: str, token: str = Depends(get_token)):
    try:
        res = transit_rotation.rotate_key(key_name, token)
        return {"status": "success", "data": res}
    except Exception as e:
        handle_transit_exceptions(e)


@router.delete("/transit/keys/{key_name}")
def transit_revoke_key(key_name: str, token: str = Depends(get_token)):
    try:
        transit_keys.revoke_key(key_name, token)
        return {"status": "success"}
    except Exception as e:
        handle_transit_exceptions(e)


class EncryptRequest(BaseModel):
    key_name: str
    plaintext_b64: str


@router.post("/transit/encrypt")
def transit_encrypt(req: EncryptRequest, token: str = Depends(get_token)):
    try:
        ct = transit_crypto.encrypt(req.key_name, req.plaintext_b64, token)
        return {"status": "success", "ciphertext": ct}
    except Exception as e:
        handle_transit_exceptions(e)


class DecryptRequest(BaseModel):
    ciphertext: str


@router.post("/transit/decrypt")
def transit_decrypt(req: DecryptRequest, token: str = Depends(get_token)):
    try:
        pt = transit_crypto.decrypt(req.ciphertext, token)
        return {"status": "success", "plaintext_b64": pt}
    except Exception as e:
        handle_transit_exceptions(e)


class GrantRequest(BaseModel):
    resource_type: str
    resource_id: str
    grantee_email: str
    permissions: str


@router.post("/acl/grant", status_code=status.HTTP_200_OK)
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


@router.post("/transit/signing-keys", status_code=status.HTTP_201_CREATED)
def transit_create_signing_key(req: CreateSigningKeyRequest, token: str = Depends(get_token)):
    try:
        res = transit_signing.create_signing_key(req.key_name, req.signing_algorithm, token)
        return {"status": "success", "data": res}
    except Exception as e:
        handle_transit_exceptions(e)


@router.get("/transit/signing-keys")
def transit_list_signing_keys(token: str = Depends(get_token)):
    try:
        keys = transit_keys.list_keys(token, usage="SIGN_VERIFY")
        return {"keys": keys}
    except Exception as e:
        handle_transit_exceptions(e)


class SignRequest(BaseModel):
    key_name: str
    message_b64: str
    message_type: MessageType


@router.post("/transit/sign")
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


@router.post("/transit/verify")
def transit_verify(req: VerifyRequest, token: str = Depends(get_token)):
    try:
        res = transit_signing.verify(
            req.key_name, req.message_b64, req.message_type, req.signature_b64, token
        )
        return {"status": "success", "data": res}
    except Exception as e:
        handle_transit_exceptions(e)


# Include router on app root, /api, and /api/v1
app.include_router(router)
app.include_router(router, prefix="/api")
app.include_router(router, prefix="/api/v1")
