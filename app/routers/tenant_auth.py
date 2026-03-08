from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException

from ..database import get_connection
from ..schemas.auth import LoginRequest, SignupOtpVerifyRequest, TenantMemberSignupRequest
from ..services.authz import get_effective_organization_id, get_effective_role
from ..services.email_templates import build_workspace_signup_verification_email
from ..services.security import create_access_token, verify_password
from ..services.tenant import TenantContext, get_tenant_context
from .auth import _create_email_otp_challenge, _deliver_mail_or_debug, _mark_email_otp_used, _normalize_text, _now_iso, _upsert_membership
from .auth import generate_otp, hash_password, hash_token

router = APIRouter(prefix="/api/tenant-auth", tags=["tenant-auth"])


@router.get("/context")
def tenant_context_summary(tenant: TenantContext = Depends(get_tenant_context)) -> dict:
    if tenant.scope != "organization" or not tenant.organization_id:
        return {
            "scope": "platform",
            "organization_id": None,
            "organization_name": None,
            "organization_slug": "",
            "is_active": False,
        }

    with get_connection("strategy") as conn:
        organization = conn.execute(
            "SELECT id, name, slug, approval_status, status FROM organizations WHERE id = ? LIMIT 1",
            (tenant.organization_id,),
        ).fetchone()

    if not organization:
        return {
            "scope": "platform",
            "organization_id": None,
            "organization_name": None,
            "organization_slug": "",
            "is_active": False,
        }

    return {
        "scope": "organization",
        "organization_id": int(organization["id"]),
        "organization_name": str(organization["name"] or "").strip(),
        "organization_slug": str(organization["slug"] or "").strip().lower(),
        "is_active": organization["approval_status"] == "approved" and organization["status"] == "active",
    }


@router.post("/signup-request")
@router.post("/member-access/request")
def tenant_signup_request(payload: TenantMemberSignupRequest, tenant: TenantContext = Depends(get_tenant_context)) -> dict:
    if tenant.scope != "organization" or not tenant.organization_id:
        raise HTTPException(status_code=400, detail="Organization tenant context is required")

    with get_connection("strategy") as conn:
        organization = conn.execute(
            "SELECT id, name, slug, approval_status, status, status_note FROM organizations WHERE id = ?",
            (tenant.organization_id,),
        ).fetchone()
        if not organization:
            raise HTTPException(status_code=404, detail="Organization not found")
        if organization["approval_status"] != "approved" or organization["status"] != "active":
            raise HTTPException(status_code=403, detail=(organization["status_note"] or "Organization is not active"))

        email_value = payload.email.strip().lower()
        existing_user = conn.execute(
            "SELECT id FROM users WHERE lower(email) = ?",
            (email_value,),
        ).fetchone()
        if existing_user:
            raise HTTPException(status_code=409, detail="Email already registered")

        existing_invitation = conn.execute(
            """
            SELECT id
            FROM organization_invitations
            WHERE organization_id = ?
              AND lower(email) = ?
              AND status = 'pending'
            LIMIT 1
            """,
            (tenant.organization_id, email_value),
        ).fetchone()
        if existing_invitation:
            raise HTTPException(status_code=409, detail="A pending invitation already exists for this email")

        conn.execute(
            """
            UPDATE organization_member_signup_requests
            SET status = 'superseded', updated_at = CURRENT_TIMESTAMP
            WHERE organization_id = ?
              AND lower(email) = ?
              AND status IN ('otp_pending', 'pending_org_admin_review')
            """,
            (tenant.organization_id, email_value),
        )

        otp_code = generate_otp()
        otp_expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
        cursor = conn.execute(
            """
            INSERT INTO organization_member_signup_requests
            (organization_id, full_name, email, password_hash, requested_role, otp_code_hash, otp_expires_at, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'org_user', ?, ?, 'otp_pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (
                tenant.organization_id,
                _normalize_text(payload.full_name),
                email_value,
                hash_password(payload.password),
                hash_token(otp_code),
                otp_expires_at,
            ),
        )
        signup_request_id = int(cursor.lastrowid)
        _create_email_otp_challenge(
            conn,
            email=email_value,
            purpose="tenant_member_signup_verify",
            otp_code=otp_code,
            expires_at=otp_expires_at,
            reference_type="organization_member_signup_request",
            reference_id=str(signup_request_id),
        )

    email_content = build_workspace_signup_verification_email(
        full_name=_normalize_text(payload.full_name),
        organization_name=str(organization["name"] or "").strip(),
        otp_code=otp_code,
    )
    delivery = _deliver_mail_or_debug(
        to_email=payload.email.lower(),
        subject=email_content.subject,
        body=email_content.text_body,
        html_body=email_content.html_body,
        debug_payload={"otp_code": otp_code},
    )
    return {
        "status": "otp_sent",
        "signup_request_id": signup_request_id,
        "organization_id": tenant.organization_id,
        "organization_name": organization["name"],
        "expires_at": otp_expires_at,
        **delivery,
    }


@router.post("/signup/verify-otp")
@router.post("/member-access/verify-code")
def verify_tenant_signup_otp(payload: SignupOtpVerifyRequest, tenant: TenantContext = Depends(get_tenant_context)) -> dict:
    if tenant.scope != "organization" or not tenant.organization_id:
        raise HTTPException(status_code=400, detail="Organization tenant context is required")

    with get_connection("strategy") as conn:
        signup_request = conn.execute(
            """
            SELECT id, organization_id, full_name, email, otp_code_hash, otp_expires_at, status
            FROM organization_member_signup_requests
            WHERE id = ?
            LIMIT 1
            """,
            (payload.signup_request_id,),
        ).fetchone()
        if not signup_request:
            raise HTTPException(status_code=404, detail="Signup request not found")
        if int(signup_request["organization_id"]) != tenant.organization_id:
            raise HTTPException(status_code=403, detail="Signup request does not belong to this organization")
        if signup_request["status"] != "otp_pending":
            raise HTTPException(status_code=400, detail="Signup request already processed")
        if signup_request["otp_expires_at"] < _now_iso():
            raise HTTPException(status_code=400, detail="Invalid or expired code")

        challenge_ok = _mark_email_otp_used(
            conn,
            email=str(signup_request["email"]),
            purpose="tenant_member_signup_verify",
            code=payload.code,
        )
        if not challenge_ok and hash_token(payload.code) != signup_request["otp_code_hash"]:
            raise HTTPException(status_code=400, detail="Invalid or expired code")

        conn.execute(
            """
            UPDATE organization_member_signup_requests
            SET status = 'pending_org_admin_review', otp_verified_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (payload.signup_request_id,),
        )

    return {
        "status": "pending_org_admin_review",
        "signup_request_id": payload.signup_request_id,
        "message": "Email verified. Your workspace access request is pending organization admin review.",
    }


@router.post("/login")
def tenant_login(payload: LoginRequest, tenant: TenantContext = Depends(get_tenant_context)) -> dict:
    if tenant.scope != "organization" or not tenant.organization_id:
        raise HTTPException(status_code=400, detail="Organization tenant context is required")
    with get_connection("strategy") as conn:
        user = conn.execute(
            """
            SELECT
                u.id,
                COALESCE(u.organization_id, om.organization_id) AS organization_id,
                u.full_name,
                u.email,
                u.role,
                u.password_hash,
                u.is_active,
                u.is_approved,
                om.membership_role,
                om.status AS membership_status
                        FROM users u
            LEFT JOIN organization_memberships om
              ON om.user_id = u.id
             AND om.organization_id = ?
            WHERE lower(u.email) = ?
              AND (u.organization_id = ? OR om.organization_id = ?)
            LIMIT 1
            """,
            (tenant.organization_id, payload.email.lower(), tenant.organization_id, tenant.organization_id),
        ).fetchone()
        organization = conn.execute(
            "SELECT id, approval_status, status, status_note FROM organizations WHERE id = ?",
            (tenant.organization_id,),
        ).fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not organization or organization["approval_status"] != "approved" or organization["status"] != "active":
        raise HTTPException(status_code=403, detail=(organization["status_note"] if organization else "Organization is not active"))
    if not user["is_active"] or not user["is_approved"]:
        raise HTTPException(status_code=403, detail="User is not active/approved")
    membership_role = str(user["membership_role"] or "").strip().lower()
    effective_role = get_effective_role(dict(user))
    effective_organization_id = get_effective_organization_id(
        {
            "organization_id": user["organization_id"],
            "membership_organization_id": tenant.organization_id,
            "membership_role": user["membership_role"],
            "membership_status": user["membership_status"],
            "role": user["role"],
        }
    )
    if user["membership_status"] and str(user["membership_status"]).strip().lower() != "active":
        raise HTTPException(status_code=403, detail="Organization membership is not active")
    if membership_role and membership_role not in {"org_admin", "org_user"}:
        raise HTTPException(status_code=403, detail="Invalid organization membership")
    if effective_role not in {"org_admin", "org_user"}:
        raise HTTPException(status_code=403, detail="Platform-only user cannot use tenant login")
    token = create_access_token(
        subject=user["email"],
        role=effective_role,
        organization_id=effective_organization_id,
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "organization_id": effective_organization_id,
            "full_name": user["full_name"],
            "email": user["email"],
            "role": effective_role,
            "tenant_slug": tenant.organization_slug,
        },
    }