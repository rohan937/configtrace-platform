"""Import all models so Alembic's autogenerate can detect the full schema.

The import order follows the FK dependency chain:
  users → integrations → resources → sync_runs → snapshots → changes → alerts
"""

from app.models.base import Base  # noqa: F401  (re-exported for Alembic env.py)
from app.models.user import User  # noqa: F401
from app.models.integration import Integration  # noqa: F401
from app.models.resource import Resource  # noqa: F401
from app.models.sync_run import SyncRun  # noqa: F401
from app.models.snapshot import Snapshot  # noqa: F401
from app.models.change import Change  # noqa: F401
from app.models.alert import Alert  # noqa: F401
from app.models.user_settings import UserSettings  # noqa: F401
from app.models.workspace import Workspace, WorkspaceMember, WorkspaceInvite, WorkspaceAuditLog  # noqa: F401
from app.models.billing import WorkspaceBilling  # noqa: F401
from app.models.notification_settings import WorkspaceNotificationSettings  # noqa: F401
from app.models.change_review import ChangeReview  # noqa: F401  (after Change + Workspace)

__all__ = [
    "Base",
    "User",
    "Integration",
    "Resource",
    "SyncRun",
    "Snapshot",
    "Change",
    "Alert",
    "UserSettings",
    "Workspace",
    "WorkspaceMember",
    "WorkspaceInvite",
    "WorkspaceAuditLog",
    "WorkspaceBilling",
    "WorkspaceNotificationSettings",
    "ChangeReview",
]
