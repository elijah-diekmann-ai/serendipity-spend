from __future__ import annotations

import enum

from sqlalchemy import Boolean, Enum, String
from sqlalchemy.orm import Mapped, mapped_column

from serendipity_spend.core.models import Base, Timestamped, UUIDPrimaryKey


class UserRole(str, enum.Enum):
    EMPLOYEE = "EMPLOYEE"
    APPROVER = "APPROVER"
    ADMIN = "ADMIN"


class User(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "identity_user"

    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(200))
    role: Mapped[UserRole] = mapped_column(Enum(UserRole, native_enum=False), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
