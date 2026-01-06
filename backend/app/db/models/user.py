from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.mysql import MEDIUMTEXT
from app.db.base import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(200), unique=True, nullable=False)

    salt = Column(String(256))
    verifier = Column(String(512))
    dek_wrapped = Column(String(1024))
    face_template = Column(MEDIUMTEXT)

    is_active = Column(Boolean, default=True)
    is_locked = Column(Boolean, default=False)

    role_id = Column(Integer, ForeignKey("roles.id"))
    role = relationship("Role", back_populates="users")

    # ✅ العلاقة الصحيحة
    vault_items = relationship(
        "VaultItem",
        back_populates="user",
        cascade="all, delete-orphan",
    )
