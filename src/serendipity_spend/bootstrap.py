from __future__ import annotations

import secrets

from sqlalchemy import select

from serendipity_spend.core.config import settings
from serendipity_spend.core.db import SessionLocal, engine
from serendipity_spend.core.models import Base
from serendipity_spend.core.security import hash_password
from serendipity_spend.modules.identity.google_oauth import google_oauth_enabled
from serendipity_spend.modules.identity.models import User, UserRole


def bootstrap() -> None:
    if settings.environment == "dev" and str(settings.database_url).startswith("sqlite"):
        Base.metadata.create_all(engine)

    if not settings.init_admin_email:
        return
    if not settings.init_admin_password and not google_oauth_enabled():
        return

    password = settings.init_admin_password or secrets.token_urlsafe(32)

    with SessionLocal() as session:
        existing = session.scalar(select(User).where(User.email == settings.init_admin_email))
        if existing:
            return
        admin = User(
            email=settings.init_admin_email,
            full_name="Admin",
            password_hash=hash_password(password),
            role=UserRole.ADMIN,
            is_active=True,
        )
        session.add(admin)
        session.commit()
