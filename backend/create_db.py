from app.db.session import engine
from app.db.base import Base


from app.db.models.user import User
from app.db.models.role import Role
from app.db.models.vault_item import VaultItem
from app.db.models.audit_log import AuditLog


print("Creating database tables...")
Base.metadata.create_all(bind=engine)
print("Done.")
