from __future__ import annotations


def test_google_oauth_enabled_disables_password_token_endpoint(monkeypatch):
    from fastapi.testclient import TestClient

    from serendipity_spend.core.config import settings
    from serendipity_spend.main import app

    monkeypatch.setattr(settings, "google_oauth_client_id", "client")
    monkeypatch.setattr(settings, "google_oauth_client_secret", "secret")

    client = TestClient(app)
    resp = client.post("/api/auth/token", data={"username": "x", "password": "y"})
    assert resp.status_code == 400
    assert "Password auth is disabled" in resp.text


def test_google_oauth_domain_restriction_applies_to_api_tokens(monkeypatch):
    from fastapi.testclient import TestClient

    from serendipity_spend.core.config import settings
    from serendipity_spend.core.db import SessionLocal
    from serendipity_spend.core.security import create_access_token
    from serendipity_spend.main import app
    from serendipity_spend.modules.identity.models import UserRole
    from serendipity_spend.modules.identity.service import create_user

    monkeypatch.setattr(settings, "google_oauth_client_id", "client")
    monkeypatch.setattr(settings, "google_oauth_client_secret", "secret")
    monkeypatch.setattr(settings, "google_oauth_allowed_domain", "serendipitycapital.com")

    with SessionLocal() as session:
        good_user = create_user(
            session,
            email="alice@serendipitycapital.com",
            password="pw",
            role=UserRole.EMPLOYEE,
            full_name="Alice",
        )
        bad_user = create_user(
            session,
            email="mallory@example.com",
            password="pw",
            role=UserRole.EMPLOYEE,
            full_name="Mallory",
        )

        good_token = create_access_token(subject=str(good_user.id))
        bad_token = create_access_token(subject=str(bad_user.id))

    client = TestClient(app)
    ok = client.get("/api/auth/me", headers={"Authorization": f"Bearer {good_token}"})
    assert ok.status_code == 200
    forbidden = client.get("/api/auth/me", headers={"Authorization": f"Bearer {bad_token}"})
    assert forbidden.status_code == 401

