from __future__ import annotations

import secrets

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from serendipity_spend.core.security import hash_password, verify_password
from serendipity_spend.modules.identity.models import User, UserRole


def get_user_by_email(session: Session, *, email: str) -> User | None:
    return session.scalar(select(User).where(User.email == email))


def create_user(
    session: Session,
    *,
    email: str,
    password: str,
    role: UserRole,
    full_name: str | None = None,
) -> User:
    existing = get_user_by_email(session, email=email)
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")

    user = User(
        email=email,
        full_name=full_name,
        password_hash=hash_password(password),
        role=role,
        is_active=True,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def authenticate_user(session: Session, *, email: str, password: str) -> User:
    user = get_user_by_email(session, email=email)
    if not user or not user.is_active or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return user


def get_or_create_google_user(
    session: Session,
    *,
    email: str,
    full_name: str | None = None,
) -> User:
    user = get_user_by_email(session, email=email)
    if user:
        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is inactive")
        if full_name and not user.full_name:
            user.full_name = full_name
            session.add(user)
            session.commit()
            session.refresh(user)
        return user

    random_password = secrets.token_urlsafe(32)
    user = User(
        email=email,
        full_name=full_name,
        password_hash=hash_password(random_password),
        role=UserRole.EMPLOYEE,
        is_active=True,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user
