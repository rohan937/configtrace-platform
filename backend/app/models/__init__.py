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
from app.models.change_snooze_rule import ChangeSnoozeRule  # noqa: F401  (M57.3)
from app.models.workspace_policy import WorkspacePolicy  # noqa: F401  (M58.14)
from app.models.expected_change_window import ExpectedChangeWindow  # noqa: F401  (M58.16)
from app.models.security_finding import SecurityFinding  # noqa: F401  (M60.3)
from app.models.security_finding_note import SecurityFindingNote  # noqa: F401  (M61.3)
from app.models.security_rule_setting import SecurityRuleSetting  # noqa: F401  (M61.7)
from app.models.security_beta_event import SecurityBetaEvent  # noqa: F401  (M63.1)
from app.models.security_beta_feedback import SecurityBetaFeedback  # noqa: F401  (M63.6)

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
    "ChangeSnoozeRule",
    "WorkspacePolicy",
    "ExpectedChangeWindow",
    "SecurityFinding",
    "SecurityFindingNote",
    "SecurityRuleSetting",
    "SecurityBetaEvent",
    "SecurityBetaFeedback",
]
