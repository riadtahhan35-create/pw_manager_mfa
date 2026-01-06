from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import List

from app.db.session import get_db
from app.db.models.user import User
from app.db.models.role import Role
from app.db.models.audit_log import AuditLog

router = APIRouter(prefix="/admin", tags=["Admin"])

# =====================================================
# RBAC Helper
# =====================================================

def require_admin(username: str, db: Session) -> User:
    user = (
        db.query(User)
        .join(Role)
        .filter(User.username == username)
        .first()
    )

    if not user or user.role.name != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    return user


# =====================================================
# Admin Self Check
# =====================================================

@router.get("/me")
def admin_me(username: str, db: Session = Depends(get_db)):
    user = (
        db.query(User)
        .join(Role)
        .filter(User.username == username)
        .first()
    )

    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")

    return {"is_admin": user.role.name == "admin"}


# =====================================================
# Users Management
# =====================================================

@router.get("/users")
def list_users(username: str, db: Session = Depends(get_db)):
    require_admin(username, db)

    users = db.query(User).join(Role).all()

    return [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "is_active": u.is_active,
            "is_locked": u.is_locked,
            "role": u.role.name,
        }
        for u in users
    ]


@router.post("/users/{user_id}/lock")
def lock_user(
    user_id: int,
    payload: dict,
    username: str,
    request: Request,
    db: Session = Depends(get_db),
):
    admin = require_admin(username, db)

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_locked = payload["locked"]

    db.add(
        AuditLog(
            action="LOCK" if payload["locked"] else "UNLOCK",
            admin_username=admin.username,
            target_username=user.username,
            details="Account locked" if payload["locked"] else "Account unlocked",
            ip_address=request.client.host if request.client else None,
        )
    )

    db.commit()

    return {"message": "User updated"}


@router.post("/users/{user_id}/role")
def change_role(
    user_id: int,
    payload: dict,
    username: str,
    request: Request,
    db: Session = Depends(get_db),
):
    admin = require_admin(username, db)

    role = db.query(Role).filter(Role.name == payload["role"]).first()
    if not role:
        raise HTTPException(status_code=400, detail="Invalid role")

    user = db.query(User).filter(User.id == user_id).first()
    old_role = user.role.name

    user.role_id = role.id

    db.add(
        AuditLog(
            action="CHANGE_ROLE",
            admin_username=admin.username,
            target_username=user.username,
            details=f"{old_role} → {payload['role']}",
            ip_address=request.client.host if request.client else None,
        )
    )

    db.commit()

    return {"message": "Role updated"}


# =====================================================
# System Stats
# =====================================================

@router.get("/stats")
def system_stats(username: str, db: Session = Depends(get_db)):
    require_admin(username, db)

    return {
        "total_users": db.query(User).count(),
        "active_users": db.query(User).filter(User.is_active == True).count(),
        "locked_users": db.query(User).filter(User.is_locked == True).count(),
    }


# =====================================================
# Audit Log
# =====================================================

@router.get("/audit")
def get_audit_log(username: str, db: Session = Depends(get_db)):
    require_admin(username, db)

    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .limit(100)
        .all()
    )

    return [
        {
            "time": log.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "action": log.action,
            "admin": log.admin_username,
            "target": log.target_username,
            "details": log.details,
            "ip": log.ip_address,
        }
        for log in logs
    ]
