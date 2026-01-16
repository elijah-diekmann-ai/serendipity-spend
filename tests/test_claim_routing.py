from __future__ import annotations

from datetime import date

import pytest
from fastapi import HTTPException

from serendipity_spend.core.db import SessionLocal
from serendipity_spend.modules.claims.models import ClaimStatus
from serendipity_spend.modules.claims.service import (
    create_claim,
    route_claim,
    submit_claim,
    update_claim,
)
from serendipity_spend.modules.identity.models import UserRole
from serendipity_spend.modules.identity.service import create_user


def test_submit_claim_autoroutes_to_single_approver():
    with SessionLocal() as session:
        employee = create_user(
            session,
            email="employee@example.com",
            password="pw",
            role=UserRole.EMPLOYEE,
            full_name="Employee",
        )
        approver = create_user(
            session,
            email="approver@example.com",
            password="pw",
            role=UserRole.APPROVER,
            full_name="Approver",
        )

        claim = create_claim(session, employee_id=employee.id, home_currency="SGD")
        update_claim(
            session,
            claim=claim,
            user=employee,
            travel_start_date=date(2026, 1, 1),
            travel_end_date=date(2026, 1, 2),
            purpose="Test trip",
        )

        submitted = submit_claim(session, claim=claim, user=employee)
        assert submitted.status == ClaimStatus.NEEDS_APPROVER_REVIEW
        assert submitted.approver_id == approver.id


def test_submit_claim_autoroutes_to_single_admin_when_no_approvers():
    with SessionLocal() as session:
        employee = create_user(
            session,
            email="employee@example.com",
            password="pw",
            role=UserRole.EMPLOYEE,
            full_name="Employee",
        )
        admin = create_user(
            session,
            email="admin@example.com",
            password="pw",
            role=UserRole.ADMIN,
            full_name="Admin",
        )

        claim = create_claim(session, employee_id=employee.id, home_currency="SGD")
        update_claim(
            session,
            claim=claim,
            user=employee,
            travel_start_date=date(2026, 1, 1),
            travel_end_date=date(2026, 1, 2),
            purpose="Test trip",
        )

        submitted = submit_claim(session, claim=claim, user=employee)
        assert submitted.status == ClaimStatus.NEEDS_APPROVER_REVIEW
        assert submitted.approver_id == admin.id


def test_submit_claim_does_not_autoroute_when_multiple_approvers():
    with SessionLocal() as session:
        employee = create_user(
            session,
            email="employee@example.com",
            password="pw",
            role=UserRole.EMPLOYEE,
            full_name="Employee",
        )
        _admin = create_user(
            session,
            email="admin@example.com",
            password="pw",
            role=UserRole.ADMIN,
            full_name="Admin",
        )
        _approver_a = create_user(
            session,
            email="approver-a@example.com",
            password="pw",
            role=UserRole.APPROVER,
            full_name="Approver A",
        )
        _approver_b = create_user(
            session,
            email="approver-b@example.com",
            password="pw",
            role=UserRole.APPROVER,
            full_name="Approver B",
        )

        claim = create_claim(session, employee_id=employee.id, home_currency="SGD")
        update_claim(
            session,
            claim=claim,
            user=employee,
            travel_start_date=date(2026, 1, 1),
            travel_end_date=date(2026, 1, 2),
            purpose="Test trip",
        )

        submitted = submit_claim(session, claim=claim, user=employee)
        assert submitted.status == ClaimStatus.SUBMITTED
        assert submitted.approver_id is None


def test_route_claim_rejects_non_approver_user():
    with SessionLocal() as session:
        employee = create_user(
            session,
            email="employee@example.com",
            password="pw",
            role=UserRole.EMPLOYEE,
            full_name="Employee",
        )
        claim = create_claim(session, employee_id=employee.id, home_currency="SGD")

        with pytest.raises(HTTPException) as exc:
            route_claim(session, claim=claim, approver_id=employee.id)

        assert exc.value.status_code == 400
