"""
Alembic model import hook.

Importing this module ensures all SQLAlchemy models are registered on Base.metadata.
"""

from __future__ import annotations

# Import User first - other models have relationships to User
from serendipity_spend.modules.identity.models import User  # noqa: F401

from serendipity_spend.modules.audit.models import AuditEvent  # noqa: F401
from serendipity_spend.modules.claims.models import Claim  # noqa: F401
from serendipity_spend.modules.documents.models import EvidenceDocument, SourceFile  # noqa: F401
from serendipity_spend.modules.expenses.models import ExpenseItem, ExpenseItemEvidence  # noqa: F401
from serendipity_spend.modules.exports.models import ExportRun  # noqa: F401
from serendipity_spend.modules.fx.models import FxRate  # noqa: F401
from serendipity_spend.modules.policy.models import PolicyException, PolicyViolation  # noqa: F401
from serendipity_spend.modules.workflow.models import Approval, Task  # noqa: F401
