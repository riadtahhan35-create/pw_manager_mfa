from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func

from app.db.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    created_at = Column(
        DateTime,
        nullable=False,
        server_default=func.now()
    )

    action = Column(String(50), nullable=False)

    admin_username = Column(String(100), nullable=False)
    target_username = Column(String(100), nullable=False)

    details = Column(String(255))
    ip_address = Column(String(45))
