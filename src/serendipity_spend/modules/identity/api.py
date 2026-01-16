from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from serendipity_spend.api.deps import get_current_user, require_role
from serendipity_spend.core.db import db_session
from serendipity_spend.core.security import create_access_token
from serendipity_spend.modules.identity.models import User, UserRole
from serendipity_spend.modules.identity.schemas import TokenOut, UserCreate, UserOut
from serendipity_spend.modules.identity.service import authenticate_user, create_user

router = APIRouter(tags=["identity"])


@router.post("/auth/token", response_model=TokenOut)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(db_session),
) -> TokenOut:
    user = authenticate_user(session, email=form_data.username, password=form_data.password)
    token = create_access_token(subject=str(user.id))
    return TokenOut(access_token=token)


@router.get("/auth/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(user, from_attributes=True)


@router.post("/users", response_model=UserOut)
def create_user_endpoint(
    payload: UserCreate,
    session: Session = Depends(db_session),
    _: User = Depends(require_role(UserRole.ADMIN)),
) -> UserOut:
    user = create_user(
        session,
        email=str(payload.email),
        password=payload.password,
        role=payload.role,
        full_name=payload.full_name,
    )
    return UserOut.model_validate(user, from_attributes=True)
