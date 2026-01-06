# backend/app/api/v1/auth_routes.py

import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Dict

import srp
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.db.session import get_db
from app.db.models.user import User
from app.db.models.role import Role
from app.core.srp_utils import create_srp_verifier
from app.core.crypto_utils import generate_dek, derive_kek, wrap_dek

router = APIRouter()

# ======================================================
# Security / SRP configuration
# ======================================================
SRP_HASH = srp.SHA1
SRP_GROUP = srp.NG_2048

SRP_SESSION_TTL_SEC = 300
MFA_SESSION_TTL_SEC = 300
MAX_SESSIONS = 5000


# ======================================================
# In-memory session stores
# ======================================================
@dataclass
class SrpSession:
    verifier: srp.Verifier
    username: str
    created_at: float


@dataclass
class MfaSession:
    username: str
    K: bytes
    challenge: bytes
    created_at: float


_srpsessions: Dict[str, SrpSession] = {}
_mfasessions: Dict[str, MfaSession] = {}


# ======================================================
# Helpers
# ======================================================
def _b64decode_strict(b64_str: str, field: str) -> bytes:
    if not isinstance(b64_str, str) or not b64_str.strip():
        raise HTTPException(status_code=400, detail=f"Missing {field}")
    try:
        return base64.b64decode(b64_str, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail=f"Invalid Base64 for {field}")


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def _cleanup_expired_sessions() -> None:
    now = time.time()

    for sid, sess in list(_srpsessions.items()):
        if now - sess.created_at > SRP_SESSION_TTL_SEC:
            _srpsessions.pop(sid, None)

    for sid, sess in list(_mfasessions.items()):
        if now - sess.created_at > MFA_SESSION_TTL_SEC:
            _mfasessions.pop(sid, None)

    if len(_srpsessions) > MAX_SESSIONS:
        for sid, _ in sorted(_srpsessions.items(), key=lambda x: x[1].created_at)[: len(_srpsessions) - MAX_SESSIONS]:
            _srpsessions.pop(sid, None)

    if len(_mfasessions) > MAX_SESSIONS:
        for sid, _ in sorted(_mfasessions.items(), key=lambda x: x[1].created_at)[: len(_mfasessions) - MAX_SESSIONS]:
            _mfasessions.pop(sid, None)


def _get_or_create_default_role(db: Session, name: str = "user") -> Role:
    role = db.query(Role).filter(Role.name == name).first()
    if role:
        return role
    role = Role(name=name)
    db.add(role)
    db.commit()
    db.refresh(role)
    return role


def _uniform_invalid_credentials() -> HTTPException:
    return HTTPException(status_code=400, detail="Invalid credentials")


# ======================================================
# Schemas
# ======================================================
class ChangePasswordBody(BaseModel):
    old_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8)


# ======================================================
# Register
# ======================================================
@router.post("/register")
def register_user(username: str, email: str, password: str, db: Session = Depends(get_db)):
    _cleanup_expired_sessions()

    if not username or not email or not password:
        raise HTTPException(status_code=400, detail="Missing fields")

    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail="Username already exists")

    srp_data = create_srp_verifier(username, password)
    salt_b64 = srp_data["salt"]
    verifier_b64 = srp_data["verifier"]

    salt_bytes = _b64decode_strict(salt_b64, "salt")
    argon2_salt = hashlib.sha256(salt_bytes).digest()

    dek = generate_dek()
    kek = derive_kek(password, argon2_salt)
    dek_wrapped = wrap_dek(kek, dek)

    role = _get_or_create_default_role(db, "user")

    user = User(
        username=username,
        email=email,
        salt=salt_b64,
        verifier=verifier_b64,
        dek_wrapped=dek_wrapped,
        is_active=True,
        is_locked=False,
        role=role,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return {"message": "User registered successfully"}


# ======================================================
# SRP Login Step 1
# ======================================================
@router.post("/login_start")
def login_start(username: str, A_b64: str, db: Session = Depends(get_db)):
    _cleanup_expired_sessions()

    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active or user.is_locked:
        raise _uniform_invalid_credentials()

    A = _b64decode_strict(A_b64, "A_b64")
    salt = _b64decode_strict(user.salt, "salt")
    verifier = _b64decode_strict(user.verifier, "verifier")

    svr = srp.Verifier(username, salt, verifier, A, hash_alg=SRP_HASH, ng_type=SRP_GROUP)
    _, B = svr.get_challenge()
    if B is None:
        raise _uniform_invalid_credentials()

    session_id = secrets.token_urlsafe(32)
    _srpsessions[session_id] = SrpSession(svr, username, time.time())

    return {"salt": user.salt, "B": _b64encode(B), "session_id": session_id}


# ======================================================
# SRP Login Step 2 → MFA
# ======================================================
@router.post("/login_verify")
def login_verify(username: str, session_id: str, M_b64: str):
    _cleanup_expired_sessions()

    sess = _srpsessions.get(session_id)
    if not sess or sess.username != username:
        raise HTTPException(status_code=400, detail="Invalid SRP session")

    M = _b64decode_strict(M_b64, "M_b64")
    HAMK = sess.verifier.verify_session(M)
    if HAMK is None:
        raise HTTPException(status_code=401, detail="SRP authentication failed")

    K = sess.verifier.get_session_key()
    challenge = secrets.token_bytes(32)
    mfa_session_id = secrets.token_urlsafe(32)

    _mfasessions[mfa_session_id] = MfaSession(username, K, challenge, time.time())
    _srpsessions.pop(session_id, None)

    return {
        "mfa_required": True,
        "mfa_session_id": mfa_session_id,
        "challenge_b64": _b64encode(challenge),
        "server_proof_b64": _b64encode(HAMK),
    }


# ======================================================
# MFA Complete
# ======================================================
@router.post("/mfa_complete")
def mfa_complete(username: str, mfa_session_id: str, proof_b64: str):
    _cleanup_expired_sessions()

    sess = _mfasessions.get(mfa_session_id)
    if not sess or sess.username != username:
        raise HTTPException(status_code=400, detail="Invalid MFA session")

    proof = _b64decode_strict(proof_b64, "proof_b64")
    expected = hmac.new(sess.K, sess.challenge, hashlib.sha1).digest()

    if not hmac.compare_digest(proof, expected):
        raise HTTPException(status_code=401, detail="Invalid MFA proof")

    _mfasessions.pop(mfa_session_id, None)
    return {"authenticated": True}


# ======================================================
# DEK Bundle
# ======================================================
@router.get("/dek_bundle")
def dek_bundle(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"salt_b64": user.salt, "dek_wrapped_b64": user.dek_wrapped}


# ======================================================
# ✅ Change Password (FINAL – WORKING)
# ======================================================
@router.post("/change-password")
def change_password(username: str, body: ChangePasswordBody, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active or user.is_locked:
        raise HTTPException(status_code=400, detail="Invalid user")

    # --- verify old password by decrypting DEK ---
    old_salt = base64.b64decode(user.salt)
    argon2_old = hashlib.sha256(old_salt).digest()
    kek_old = derive_kek(body.old_password, argon2_old)

    wrapped = base64.b64decode(user.dek_wrapped)
    nonce, ct = wrapped[:12], wrapped[12:]

    try:
        dek = AESGCM(kek_old).decrypt(nonce, ct, None)
    except Exception:
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    # --- generate NEW SRP salt + verifier ---
    new_salt, new_verifier = srp.create_salted_verification_key(
        username=user.username,
        password=body.new_password,
        hash_alg=SRP_HASH,
        ng_type=SRP_GROUP,
    )

    # --- rewrap SAME DEK ---
    argon2_new = hashlib.sha256(new_salt).digest()
    kek_new = derive_kek(body.new_password, argon2_new)
    user.dek_wrapped = wrap_dek(kek_new, dek)

    user.salt = _b64encode(new_salt)
    user.verifier = _b64encode(new_verifier)

    db.commit()

    return {"message": "Password changed successfully", "force_relogin": True}
