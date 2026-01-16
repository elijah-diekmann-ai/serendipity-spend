from __future__ import annotations

from fastapi.testclient import TestClient


def test_claim_detail_renders_policy_summary() -> None:
    from serendipity_spend.core.db import SessionLocal
    from serendipity_spend.core.security import create_access_token, hash_password
    from serendipity_spend.main import create_app
    from serendipity_spend.modules.claims.service import create_claim
    from serendipity_spend.modules.identity.models import User, UserRole
    from serendipity_spend.modules.policy.service import evaluate_claim

    with SessionLocal() as session:
        user = User(
            email="employee@example.com",
            full_name="Employee",
            password_hash=hash_password("password"),
            role=UserRole.EMPLOYEE,
            is_active=True,
        )
        session.add(user)
        session.commit()
        session.refresh(user)

        claim = create_claim(session, employee_id=user.id, home_currency="SGD")
        evaluate_claim(session, claim_id=claim.id)

        user_id = user.id
        claim_id = claim.id

    app = create_app()
    with TestClient(app) as client:
        token = create_access_token(subject=str(user_id))
        client.cookies.set("access_token", token)

        resp = client.get(f"/app/claims/{claim_id}")
        assert resp.status_code == 200
        assert "Policy checks" in resp.text
        assert "R001" in resp.text
        assert "Mark done" in resp.text

