from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from app.db.session import get_db
from app.db.models.user import User

router = APIRouter(
    prefix="/mfa/face",
    tags=["MFA - Face"]
)

class FaceTemplateRegisterRequest(BaseModel):
    username: str = Field(..., min_length=1)
    face_template_enc_b64: str = Field(..., min_length=20)

class FaceTemplateVerifyRequest(BaseModel):
    username: str = Field(..., min_length=1)
    similarity: float | None = None

@router.get("/template")
def get_face_template(username: str, db: Session = Depends(get_db)):
    if not username:
        raise HTTPException(status_code=400, detail="Missing username")

    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active or user.is_locked:
        raise HTTPException(status_code=400, detail="Invalid user")

    if not user.face_template or len(user.face_template) < 20:
        raise HTTPException(status_code=404, detail="Face template not registered")

    return {
        "username": user.username,
        "face_template_enc_b64": user.face_template
    }

@router.post("/register")
def register_face(payload: FaceTemplateRegisterRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not user.is_active or user.is_locked:
        raise HTTPException(status_code=400, detail="Invalid user")

    if not payload.face_template_enc_b64 or len(payload.face_template_enc_b64) < 20:
        raise HTTPException(status_code=400, detail="Invalid face template payload")

    user.face_template = payload.face_template_enc_b64
    db.add(user)
    db.commit()
    return {"message": "Face template stored successfully"}

@router.post("/verify")
def verify_face(payload: FaceTemplateVerifyRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not user.face_template:
        raise HTTPException(status_code=400, detail="Face not registered")
    return {"message": "Face verify endpoint reachable"}
