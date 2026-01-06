from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models.user import User


def get_current_user(username: str, db: Session = Depends(get_db)) -> User:
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active or user.is_locked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive user"
        )
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.role or user.role.name != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return user
