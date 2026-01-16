from __future__ import annotations

import uuid

from pydantic import BaseModel, EmailStr

from serendipity_spend.modules.identity.models import UserRole


class UserOut(BaseModel):
    id: uuid.UUID
    email: EmailStr
    full_name: str | None
    role: UserRole
    is_active: bool


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str | None = None
    password: str
    role: UserRole = UserRole.EMPLOYEE


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
