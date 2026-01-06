from sqlalchemy.orm import Session
from app.db.models.audit_log import AuditLog
from app.db.models.user import User


def log_audit(
    db: Session,
    action: str,
    actor: User,
    target: User | None = None,
    details: str | None = None,
    ip: str | None = None,
):
    log = AuditLog(
        action=action,
        actor_user_id=actor.id,
        actor_username=actor.username,
        target_user_id=target.id if target else None,
        target_username=target.username if target else None,
        details=details,
        ip_address=ip,
    )

    db.add(log)
    db.commit()
