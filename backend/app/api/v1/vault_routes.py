from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import List
import base64

from app.db.session import get_db
from app.db.models.user import User
from app.db.models.vault_item import VaultItem

router = APIRouter(prefix="/vault", tags=["Vault"])


def _looks_like_aesgcm_b64(s: str) -> bool:
    """
    نتأكد أن secret_enc = Base64(iv12 + ciphertext>=1)
    - لازم Base64 صالح
    - لازم طول البايتات >= 13
    """
    try:
        raw = base64.b64decode(s, validate=True)
        return len(raw) >= 13
    except Exception:
        return False


class VaultAddRequest(BaseModel):
    site: str = Field(..., min_length=1, max_length=255)
    site_username: str = Field(..., min_length=1, max_length=255)
    secret_enc: str = Field(..., min_length=10)


class VaultUpdateRequest(BaseModel):
    site: str = Field(..., min_length=1, max_length=255)
    site_username: str = Field(..., min_length=1, max_length=255)


# ✅ جديد: لتحديث كلمة السر المشفرة فقط
class VaultPasswordUpdateRequest(BaseModel):
    secret_enc: str = Field(..., min_length=10)


class VaultItemResponse(BaseModel):
    id: int
    site: str
    site_username: str
    secret_enc: str


@router.get("/list", response_model=List[VaultItemResponse])
def list_vault(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active or user.is_locked:
        raise HTTPException(status_code=400, detail="Invalid user")

    items = (
        db.query(VaultItem)
        .filter(VaultItem.user_id == user.id)
        .order_by(VaultItem.id.desc())
        .all()
    )

    return [
        VaultItemResponse(
            id=i.id,
            site=i.site,
            site_username=i.site_username,
            secret_enc=i.secret_enc,
        )
        for i in items
    ]


@router.post("/add")
def add_vault_item(username: str, payload: VaultAddRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active or user.is_locked:
        raise HTTPException(status_code=400, detail="Invalid user")

    # ✅ منع نهائي للـ plaintext
    if not _looks_like_aesgcm_b64(payload.secret_enc):
        raise HTTPException(
            status_code=400,
            detail="secret_enc must be AES-GCM base64 (iv+ciphertext). Client-side encryption failed."
        )

    item = VaultItem(
        user_id=user.id,
        site=payload.site.strip(),
        site_username=payload.site_username.strip(),
        secret_enc=payload.secret_enc,
    )
    db.add(item)
    db.commit()
    db.refresh(item)

    return {"message": "Vault item added", "id": item.id}


@router.put("/{item_id}")
def update_vault_item(username: str, item_id: int, payload: VaultUpdateRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active or user.is_locked:
        raise HTTPException(status_code=400, detail="Invalid user")

    item = (
        db.query(VaultItem)
        .filter(VaultItem.id == item_id, VaultItem.user_id == user.id)
        .first()
    )
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    item.site = payload.site.strip()
    item.site_username = payload.site_username.strip()
    db.add(item)
    db.commit()

    return {"message": "Vault item updated"}


# ✅ جديد: تحديث كلمة السر داخل البطاقة (مشفر بالـ DEK على الـ client)
@router.put("/{item_id}/password")
def update_vault_password(username: str, item_id: int, payload: VaultPasswordUpdateRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active or user.is_locked:
        raise HTTPException(status_code=400, detail="Invalid user")

    item = (
        db.query(VaultItem)
        .filter(VaultItem.id == item_id, VaultItem.user_id == user.id)
        .first()
    )
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    # ✅ منع plaintext: لازم يكون AES-GCM base64
    if not _looks_like_aesgcm_b64(payload.secret_enc):
        raise HTTPException(
            status_code=400,
            detail="secret_enc must be AES-GCM base64 (iv+ciphertext). Client-side encryption failed."
        )

    item.secret_enc = payload.secret_enc
    db.add(item)
    db.commit()

    return {"message": "Password updated"}


@router.delete("/{item_id}")
def delete_vault_item(username: str, item_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active or user.is_locked:
        raise HTTPException(status_code=400, detail="Invalid user")

    item = (
        db.query(VaultItem)
        .filter(VaultItem.id == item_id, VaultItem.user_id == user.id)
        .first()
    )
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    db.delete(item)
    db.commit()
    return {"message": "Vault item deleted"}
