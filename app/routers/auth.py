import sqlite3
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException

from ..database import get_connection, rows_to_dicts
from ..schemas.auth import (
    AcceptInvitationRequest,
    AdminOtpRequest,
    AdminOtpVerifyRequest,
    ApproveOrgUserRequest,
    ApproveRegistrationRequest,
    CreateOrgUserRequest,
    ForgotPasswordRequest,
    LoginRequest,
    RegisterRequest,
    ResetPasswordRequest,
    SignupNormalUserRequest,
    SignupOrganizationRequest,
    SignupOtpVerifyRequest,
)
from ..services.authz import get_current_user, get_effective_organization_id, get_effective_role, has_role, require_role
from ..services.acl import get_permission_snapshot
from ..services.acl import ensure_user_default_permissions
from ..services.audit import log_audit_event
from ..services.email_templates import (
    build_account_verification_email,
    build_admin_login_request_email,
    build_organization_signup_verification_email,
    build_password_reset_email,
)
from ..services.mail_service import send_mail
from ..services.security import (
    create_access_token,
    generate_otp,
    generate_token,
    hash_password,
    hash_token,
    verify_password,
)
from ..settings import APP_BASE_URL, OWNER_ALERT_EMAIL, SMTP_PASSWORD, SMTP_USER

router = APIRouter(prefix="/api/auth", tags=["auth"])

LOCAL_TENANT_APP_PORT = "8080"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_text(value: str) -> str:
    return " ".join(str(value or "").strip().split())


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", _normalize_text(value).lower()).strip("-")
    return slug or "organization"


def _build_tenant_workspace_url(subdomain: str) -> str:
    parsed = urlparse(APP_BASE_URL)
    scheme = parsed.scheme or "http"
    hostname = (parsed.hostname or "localhost").strip().lower()

    if hostname in {"localhost", "127.0.0.1"}:
        port = f":{LOCAL_TENANT_APP_PORT}"
        return f"{scheme}://{subdomain}.localhost{port}"

    port = f":{parsed.port}" if parsed.port else ""

    host_parts = [part for part in hostname.split(".") if part]
    if len(host_parts) >= 2:
        base_host = ".".join(host_parts[-2:])
    else:
        base_host = hostname
    return f"{scheme}://{subdomain}.{base_host}{port}"


def _organization_workspace_hint(conn, *, organization_id: int, organization_name: str) -> str | None:
    row = conn.execute(
        """
        SELECT subdomain
        FROM organization_domains
        WHERE organization_id = ?
        ORDER BY CASE WHEN is_primary = 1 THEN 0 ELSE 1 END, id ASC
        LIMIT 1
        """,
        (organization_id,),
    ).fetchone()
    subdomain = str(row["subdomain"] if row else "").strip().lower()
    if not subdomain:
        subdomain = _slugify(organization_name)
    if not subdomain:
        return None
    workspace_url = _build_tenant_workspace_url(subdomain)
    return f"Looks like you belong to the {organization_name} workspace. Please use {workspace_url} to sign in."


def _serialize_user(user) -> dict:
    return {
        "id": user["id"],
        "organization_id": user["organization_id"],
        "full_name": user["full_name"],
        "email": user["email"],
        "role": user["role"],
    }


def _ensure_organization_domain(conn, *, organization_id: int, slug: str) -> None:
    if not slug.strip():
        return
    conn.execute(
        """
        INSERT OR IGNORE INTO organization_domains (organization_id, subdomain, is_primary, created_at, updated_at)
        VALUES (?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """,
        (organization_id, slug.strip().lower()),
    )


def _upsert_membership(
    conn,
    *,
    organization_id: int,
    user_id: int,
    membership_role: str,
    status: str,
    invited_by_user_id: int | None = None,
    approved_by_user_id: int | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO organization_memberships
        (organization_id, user_id, membership_role, status, invited_by_user_id, approved_by_user_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT(organization_id, user_id) DO UPDATE SET
            membership_role = excluded.membership_role,
            status = excluded.status,
            invited_by_user_id = COALESCE(excluded.invited_by_user_id, organization_memberships.invited_by_user_id),
            approved_by_user_id = COALESCE(excluded.approved_by_user_id, organization_memberships.approved_by_user_id),
            updated_at = CURRENT_TIMESTAMP
        """,
        (
            organization_id,
            user_id,
            membership_role,
            status,
            invited_by_user_id,
            approved_by_user_id,
        ),
    )


def _create_email_otp_challenge(
    conn,
    *,
    email: str,
    purpose: str,
    otp_code: str,
    expires_at: str,
    user_id: int | None = None,
    reference_type: str = "",
    reference_id: str = "",
) -> None:
    conn.execute(
        "DELETE FROM email_otp_challenges WHERE lower(email) = ? AND purpose = ? AND is_used = 0",
        (email.strip().lower(), purpose.strip().lower()),
    )
    conn.execute(
        """
        INSERT INTO email_otp_challenges
        (user_id, email, purpose, reference_type, reference_id, otp_hash, expires_at, is_used, attempt_count, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, CURRENT_TIMESTAMP)
        """,
        (
            user_id,
            email.strip().lower(),
            purpose.strip().lower(),
            reference_type.strip().lower() or None,
            reference_id.strip() or None,
            hash_token(otp_code),
            expires_at,
        ),
    )


def _mark_email_otp_used(conn, *, email: str, purpose: str, code: str) -> bool:
    row = conn.execute(
        """
        SELECT id, otp_hash, expires_at, is_used
        FROM email_otp_challenges
        WHERE lower(email) = ? AND purpose = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (email.strip().lower(), purpose.strip().lower()),
    ).fetchone()
    if not row or row["is_used"]:
        return False
    if row["expires_at"] < _now_iso():
        return False
    if row["otp_hash"] != hash_token(code):
        conn.execute(
            "UPDATE email_otp_challenges SET attempt_count = attempt_count + 1 WHERE id = ?",
            (row["id"],),
        )
        return False
    conn.execute(
        "UPDATE email_otp_challenges SET is_used = 1, used_at = CURRENT_TIMESTAMP WHERE id = ?",
        (row["id"],),
    )
    return True


def _deliver_mail_or_debug(*, to_email: str, subject: str, body: str, debug_payload: dict, html_body: str | None = None) -> dict:
    if send_mail(to_email, subject, body, html_body):
        return {"delivery": "email"}
    if not SMTP_USER or not SMTP_PASSWORD:
        return {"delivery": "debug", **debug_payload}
    raise HTTPException(status_code=503, detail="Unable to send email. Check SMTP settings.")


def _create_signup_request(
    conn,
    *,
    signup_type: str,
    full_name: str,
    email: str,
    password: str,
    organization_name: str = "",
    purchase_reference: str = "",
    requested_role: str = "org_user",
) -> tuple[int, str, str]:
    email_value = email.strip().lower()
    full_name_value = _normalize_text(full_name)
    organization_value = _normalize_text(organization_name)
    organization_slug = _slugify(organization_value) if organization_value else None
    otp_code = generate_otp()
    otp_expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()

    existing_user = conn.execute(
        "SELECT id FROM users WHERE lower(email) = ?",
        (email_value,),
    ).fetchone()
    if existing_user:
        raise HTTPException(status_code=409, detail="Email already registered")

    if signup_type == "organization":
        org_conflict = conn.execute(
            """
            SELECT id
            FROM organizations
            WHERE lower(trim(name)) = lower(trim(?)) OR lower(trim(slug)) = lower(trim(?))
            LIMIT 1
            """,
            (organization_value, organization_slug),
        ).fetchone()
        if org_conflict:
            raise HTTPException(status_code=409, detail="Organization already exists")

    conn.execute(
        "DELETE FROM signup_requests WHERE lower(email) = ? AND status IN ('otp_pending', 'otp_verified')",
        (email_value,),
    )
    cursor = conn.execute(
        """
        INSERT INTO signup_requests
        (signup_type, organization_name, organization_slug, full_name, email, password_hash, purchase_reference, requested_role, otp_code_hash, otp_expires_at, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'otp_pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """,
        (
            signup_type,
            organization_value or None,
            organization_slug,
            full_name_value,
            email_value,
            hash_password(password),
            _normalize_text(purchase_reference),
            requested_role,
            hash_token(otp_code),
            otp_expires_at,
        ),
    )
    signup_request_id = int(cursor.lastrowid)
    _create_email_otp_challenge(
        conn,
        email=email_value,
        purpose="org_signup_verify" if signup_type == "organization" else "signup_verify",
        otp_code=otp_code,
        expires_at=otp_expires_at,
        reference_type="signup_request",
        reference_id=str(signup_request_id),
    )
    return signup_request_id, otp_code, otp_expires_at


def _start_normal_user_signup(payload: SignupNormalUserRequest) -> dict:
    with get_connection("strategy") as conn:
        signup_request_id, otp_code, otp_expires_at = _create_signup_request(
            conn,
            signup_type="normal_user",
            full_name=payload.full_name,
            email=payload.email,
            password=payload.password,
            requested_role="org_user",
        )

    email_content = build_account_verification_email(
        full_name=_normalize_text(payload.full_name),
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
        "signup_type": "normal_user",
        "expires_at": otp_expires_at,
        **delivery,
    }


def _start_organization_signup(payload: SignupOrganizationRequest) -> dict:
    with get_connection("strategy") as conn:
        signup_request_id, otp_code, otp_expires_at = _create_signup_request(
            conn,
            signup_type="organization",
            full_name=payload.full_name,
            email=payload.email,
            password=payload.password,
            organization_name=payload.organization_name,
            purchase_reference=payload.purchase_reference,
            requested_role="buyer_admin",
        )

    email_content = build_organization_signup_verification_email(
        full_name=_normalize_text(payload.full_name),
        organization_name=_normalize_text(payload.organization_name),
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
        "signup_type": "organization",
        "organization_name": _normalize_text(payload.organization_name),
        "expires_at": otp_expires_at,
        **delivery,
    }


def _finalize_signup_request(conn, signup_request) -> dict:
    signup_type = str(signup_request["signup_type"]).strip().lower()
    email_value = str(signup_request["email"]).strip().lower()

    existing_user = conn.execute(
        "SELECT id FROM users WHERE lower(email) = ?",
        (email_value,),
    ).fetchone()
    if existing_user:
        raise HTTPException(status_code=409, detail="Email already registered")

    if signup_type == "normal_user":
        cursor = conn.execute(
            """
            INSERT INTO users
            (organization_id, full_name, email, password_hash, role, is_active, is_approved, signup_type, updated_at)
            VALUES (NULL, ?, ?, ?, 'org_user', 1, 0, 'normal_user', CURRENT_TIMESTAMP)
            """,
            (
                signup_request["full_name"],
                email_value,
                signup_request["password_hash"],
            ),
        )
        user_id = int(cursor.lastrowid)
        conn.execute(
            """
            UPDATE signup_requests
            SET status = 'pending_owner_approval', otp_verified_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (signup_request["id"],),
        )
        conn.execute(
            """
            INSERT INTO normal_user_approvals
            (user_id, status, created_at, updated_at)
            VALUES (?, 'pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                status = 'pending',
                updated_at = CURRENT_TIMESTAMP
            """,
            (user_id,),
        )
        log_audit_event(
            actor_user_id=user_id,
            action="platform_user_signup_submitted",
            entity_type="user",
            entity_id=str(user_id),
            details={"signup_request_id": signup_request["id"], "email": email_value},
            conn=conn,
        )
        return {
            "status": "pending_owner_approval",
            "signup_type": "normal_user",
            "message": "Email verified. Your account is pending platform approval.",
        }

    organization_name = _normalize_text(signup_request["organization_name"] or "")
    organization_slug = _slugify(signup_request["organization_slug"] or organization_name)
    org_conflict = conn.execute(
        "SELECT id FROM organizations WHERE lower(trim(name)) = lower(trim(?)) OR lower(trim(slug)) = lower(trim(?)) LIMIT 1",
        (organization_name, organization_slug),
    ).fetchone()
    if org_conflict:
        raise HTTPException(status_code=409, detail="Organization already exists")

    org_cursor = conn.execute(
        """
        INSERT INTO organizations
        (name, slug, purchaser_email, is_active, status, approval_status, created_at, updated_at)
        VALUES (?, ?, ?, 0, 'pending_approval', 'pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """,
        (organization_name, organization_slug, email_value),
    )
    organization_id = int(org_cursor.lastrowid)
    _ensure_organization_domain(conn, organization_id=organization_id, slug=organization_slug)
    user_cursor = conn.execute(
        """
        INSERT INTO users
        (organization_id, full_name, email, password_hash, role, is_active, is_approved, signup_type, updated_at)
        VALUES (?, ?, ?, ?, 'buyer_admin', 1, 0, 'organization_admin', CURRENT_TIMESTAMP)
        """,
        (
            organization_id,
            signup_request["full_name"],
            email_value,
            signup_request["password_hash"],
        ),
    )
    user_id = int(user_cursor.lastrowid)
    _upsert_membership(
        conn,
        organization_id=organization_id,
        user_id=user_id,
        membership_role="org_admin",
        status="pending",
    )
    conn.execute(
        """
        UPDATE signup_requests
        SET organization_id = ?, status = 'pending_owner_approval', otp_verified_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (organization_id, signup_request["id"]),
    )
    conn.execute(
        """
        INSERT INTO organization_status_approvals
        (organization_id, status, created_at, updated_at)
        VALUES (?, 'pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """,
        (organization_id,),
    )
    log_audit_event(
        actor_user_id=user_id,
        action="organization_signup_submitted",
        entity_type="organization",
        entity_id=str(organization_id),
        details={
            "signup_request_id": signup_request["id"],
            "organization_name": organization_name,
            "purchase_reference": signup_request["purchase_reference"],
        },
        conn=conn,
    )
    workspace_url = _build_tenant_workspace_url(organization_slug)
    return {
        "status": "pending_owner_approval",
        "signup_type": "organization",
        "organization_id": organization_id,
        "organization_slug": organization_slug,
        "workspace_url": workspace_url,
        "message": "Email verified. Your organization is pending owner approval.",
    }


@router.post("/register")
def register(payload: RegisterRequest) -> dict:
    if _normalize_text(payload.organization_name) or _normalize_text(payload.purchase_reference):
        return _start_organization_signup(
            SignupOrganizationRequest(
                organization_name=_normalize_text(payload.organization_name),
                full_name=payload.full_name,
                email=payload.email,
                password=payload.password,
                purchase_reference=payload.purchase_reference,
            )
        )
    return _start_normal_user_signup(
        SignupNormalUserRequest(
            full_name=payload.full_name,
            email=payload.email,
            password=payload.password,
        )
    )


@router.post("/signup/normal-user-request")
def signup_normal_user_request(payload: SignupNormalUserRequest) -> dict:
    return _start_normal_user_signup(payload)


@router.post("/signup/organization-request")
def signup_organization_request(payload: SignupOrganizationRequest) -> dict:
    return _start_organization_signup(payload)


@router.post("/signup/verify-otp")
def verify_signup_otp(payload: SignupOtpVerifyRequest) -> dict:
    with get_connection("strategy") as conn:
        signup_request = conn.execute(
            """
            SELECT id, signup_type, organization_name, organization_slug, organization_id, full_name, email, password_hash,
                   purchase_reference, requested_role, otp_code_hash, otp_expires_at, otp_verified_at, status
            FROM signup_requests
            WHERE id = ?
            """,
            (payload.signup_request_id,),
        ).fetchone()
        if not signup_request:
            raise HTTPException(status_code=404, detail="Signup request not found")
        if signup_request["status"] not in {"otp_pending", "otp_verified"}:
            raise HTTPException(status_code=400, detail="Signup request already processed")
        if signup_request["otp_expires_at"] < _now_iso():
            raise HTTPException(status_code=400, detail="Invalid or expired code")
        challenge_purpose = "org_signup_verify" if str(signup_request["signup_type"]).strip().lower() == "organization" else "signup_verify"
        challenge_ok = _mark_email_otp_used(
            conn,
            email=str(signup_request["email"]),
            purpose=challenge_purpose,
            code=payload.code,
        )
        if not challenge_ok and hash_token(payload.code) != signup_request["otp_code_hash"]:
            raise HTTPException(status_code=400, detail="Invalid or expired code")

        result = _finalize_signup_request(conn, signup_request)
    return result


@router.get("/invitations/{token}")
def get_invitation_details(token: str) -> dict:
    token_hash = hash_token(token)
    with get_connection("strategy") as conn:
        invitation = conn.execute(
            """
            SELECT i.id, i.organization_id, i.email, i.full_name, i.role, i.expires_at, i.status, o.name AS organization_name
            FROM organization_invitations i
            JOIN organizations o ON o.id = i.organization_id
            WHERE i.token_hash = ?
            LIMIT 1
            """,
            (token_hash,),
        ).fetchone()
        if not invitation:
            raise HTTPException(status_code=404, detail="Invitation not found")
        if invitation["status"] != "pending" or invitation["expires_at"] < _now_iso():
            raise HTTPException(status_code=400, detail="Invitation is no longer valid")
    return {
        "organization_id": invitation["organization_id"],
        "organization_name": invitation["organization_name"],
        "email": invitation["email"],
        "full_name": invitation["full_name"] or "",
        "role": invitation["role"],
        "expires_at": invitation["expires_at"],
    }


@router.post("/invitations/accept")
def accept_invitation(payload: AcceptInvitationRequest) -> dict:
    token_hash = hash_token(payload.token)
    with get_connection("strategy") as conn:
        invitation = conn.execute(
            """
            SELECT id, organization_id, inviter_user_id, email, full_name, role, expires_at, status
            FROM organization_invitations
            WHERE token_hash = ?
            LIMIT 1
            """,
            (token_hash,),
        ).fetchone()
        if not invitation:
            raise HTTPException(status_code=404, detail="Invitation not found")
        if invitation["status"] != "pending" or invitation["expires_at"] < _now_iso():
            raise HTTPException(status_code=400, detail="Invitation is no longer valid")

        existing_user = conn.execute(
            "SELECT id FROM users WHERE lower(email) = ?",
            (str(invitation["email"]).lower(),),
        ).fetchone()
        if existing_user:
            raise HTTPException(status_code=409, detail="Email already registered")

        cursor = conn.execute(
            """
            INSERT INTO users
            (organization_id, full_name, email, password_hash, role, is_active, is_approved, created_by_user_id, signup_type, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, 1, ?, 'organization_user', CURRENT_TIMESTAMP)
            """,
            (
                invitation["organization_id"],
                _normalize_text(payload.full_name or invitation["full_name"] or "Invited User"),
                str(invitation["email"]).lower(),
                hash_password(payload.password),
                invitation["role"],
                invitation["inviter_user_id"],
            ),
        )
        user_id = int(cursor.lastrowid)
        _upsert_membership(
            conn,
            organization_id=int(invitation["organization_id"]),
            user_id=user_id,
            membership_role="org_admin" if str(invitation["role"]).strip().lower() == "buyer_admin" else "org_user",
            status="active",
            invited_by_user_id=int(invitation["inviter_user_id"]),
            approved_by_user_id=int(invitation["inviter_user_id"]),
        )
        ensure_user_default_permissions(
            conn,
            user_id=user_id,
            role=str(invitation["role"]),
            granted_by_user_id=int(invitation["inviter_user_id"]),
        )
        conn.execute(
            """
            UPDATE organization_invitations
            SET status = 'accepted', accepted_user_id = ?, accepted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (user_id, invitation["id"]),
        )
        user = conn.execute(
            "SELECT id, organization_id, full_name, email, role FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        log_audit_event(
            actor_user_id=user_id,
            action="organization_invitation_accepted",
            entity_type="invitation",
            entity_id=str(invitation["id"]),
            details={"organization_id": invitation["organization_id"], "email": invitation["email"]},
            conn=conn,
        )

    token = create_access_token(
        subject=user["email"],
        role=user["role"],
        organization_id=user["organization_id"],
    )
    return {
        "status": "accepted",
        "access_token": token,
        "token_type": "bearer",
        "user": _serialize_user(user),
    }


@router.post("/login")
def login(payload: LoginRequest) -> dict:
    workspace_hint = None
    with get_connection("strategy") as conn:
        user = conn.execute(
            """
            SELECT id, organization_id, full_name, email, role, password_hash, is_active, is_approved, signup_type
            FROM users WHERE lower(email) = ?
            """,
            (payload.email.lower(),),
        ).fetchone()
        organization = None
        if user and user["organization_id"]:
            organization = conn.execute(
                "SELECT id, name, status, approval_status, status_note FROM organizations WHERE id = ?",
                (user["organization_id"],),
            ).fetchone()
        membership = None
        if user and user["organization_id"]:
            membership = conn.execute(
                """
                SELECT membership_role, status
                FROM organization_memberships
                WHERE user_id = ? AND organization_id = ?
                LIMIT 1
                """,
                (user["id"], user["organization_id"]),
            ).fetchone()
        if user and organization:
            membership_role = str(membership["membership_role"] if membership and membership["membership_role"] else "").strip().lower()
            membership_status = str(membership["status"] if membership and membership["status"] else "").strip().lower()
            signup_type = str(user["signup_type"] or "").strip().lower()
            if (
                organization["approval_status"] == "approved"
                and organization["status"] == "active"
                and membership_role == "org_user"
                and membership_status == "active"
                and signup_type == "organization_user"
            ):
                workspace_hint = _organization_workspace_hint(
                    conn,
                    organization_id=int(organization["id"]),
                    organization_name=str(organization["name"] or "your organization"),
                )
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if workspace_hint:
        raise HTTPException(status_code=403, detail=workspace_hint)
    if organization and organization["approval_status"] == "rejected":
        detail = organization["status_note"] or "Organization signup was rejected"
        raise HTTPException(status_code=403, detail=detail)
    if organization and organization["approval_status"] == "pending":
        raise HTTPException(status_code=403, detail="Organization signup pending owner approval")
    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="User account is inactive")
    if not user["is_approved"]:
        if user["organization_id"]:
            raise HTTPException(status_code=403, detail="Organization user is pending approval")
        raise HTTPException(status_code=403, detail="Account pending platform approval")

    token = create_access_token(
        subject=user["email"],
        role=user["role"],
        organization_id=user["organization_id"],
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _serialize_user(user),
    }


@router.post("/forgot-password")
def forgot_password(payload: ForgotPasswordRequest) -> dict:
    with get_connection("strategy") as conn:
        user = conn.execute(
            "SELECT id, full_name, email, is_active, is_approved FROM users WHERE lower(email) = ?",
            (payload.email.lower(),),
        ).fetchone()
        if not user:
            return {"status": "ok"}
        if not user["is_active"] or not user["is_approved"]:
            return {"status": "ok"}

        raw = generate_token(24)
        token_hash = hash_token(raw)
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
        conn.execute(
            """
            INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, is_used)
            VALUES (?, ?, ?, 0)
            """,
            (user["id"], token_hash, expires_at),
        )

    reset_link = f"{APP_BASE_URL}/reset-password?token={raw}"
    email_content = build_password_reset_email(
        full_name=str(user["full_name"] or ""),
        reset_link=reset_link,
    )
    send_mail(user["email"], email_content.subject, email_content.text_body, email_content.html_body)
    return {"status": "ok"}


@router.post("/reset-password")
def reset_password(payload: ResetPasswordRequest) -> dict:
    token_hash = hash_token(payload.token)
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_connection("strategy") as conn:
        row = conn.execute(
            """
            SELECT id, user_id, expires_at, is_used
            FROM password_reset_tokens
            WHERE token_hash = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (token_hash,),
        ).fetchone()
        if not row or row["is_used"]:
            raise HTTPException(status_code=400, detail="Invalid or expired token")
        if row["expires_at"] < now_iso:
            raise HTTPException(status_code=400, detail="Invalid or expired token")

        conn.execute(
            "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (hash_password(payload.new_password), row["user_id"]),
        )
        conn.execute("UPDATE password_reset_tokens SET is_used = 1 WHERE id = ?", (row["id"],))
    return {"status": "ok"}


@router.post("/request-admin-login-code")
def request_admin_login_code(payload: AdminOtpRequest) -> dict:
    with get_connection("strategy") as conn:
        user = conn.execute(
            """
            SELECT
                u.id,
                u.organization_id,
                u.full_name,
                u.email,
                u.role,
                u.is_active,
                u.is_approved,
                (
                    SELECT om.organization_id
                    FROM organization_memberships om
                    WHERE om.user_id = u.id
                    ORDER BY CASE WHEN lower(om.status) = 'active' THEN 0 WHEN lower(om.status) = 'pending' THEN 1 ELSE 2 END,
                             om.id ASC
                    LIMIT 1
                ) AS membership_organization_id,
                (
                    SELECT om.membership_role
                    FROM organization_memberships om
                    WHERE om.user_id = u.id
                    ORDER BY CASE WHEN lower(om.status) = 'active' THEN 0 WHEN lower(om.status) = 'pending' THEN 1 ELSE 2 END,
                             om.id ASC
                    LIMIT 1
                ) AS membership_role,
                (
                    SELECT om.status
                    FROM organization_memberships om
                    WHERE om.user_id = u.id
                    ORDER BY CASE WHEN lower(om.status) = 'active' THEN 0 WHEN lower(om.status) = 'pending' THEN 1 ELSE 2 END,
                             om.id ASC
                    LIMIT 1
                ) AS membership_status
            FROM users u
            WHERE lower(u.email) = ?
            """,
            (payload.email.lower(),),
        ).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if not user["is_active"] or not user["is_approved"]:
            raise HTTPException(status_code=403, detail="User is not active/approved")
        user_context = dict(user)
        user_context["effective_role"] = get_effective_role(user_context)
        user_context["effective_organization_id"] = get_effective_organization_id(user_context)
        if user_context["effective_role"] not in {"owner", "super_admin", "org_admin"}:
            raise HTTPException(status_code=403, detail="User is not admin eligible")

        code = generate_otp()
        code_hash = hash_token(code)
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
        conn.execute(
            """
            INSERT INTO admin_otp_requests (user_id, email, code_hash, expires_at, is_used)
            VALUES (?, ?, ?, ?, 0)
            """,
            (user["id"], user["email"], code_hash, expires_at),
        )
        _create_email_otp_challenge(
            conn,
            email=str(user["email"]),
            purpose="login_verify",
            otp_code=code,
            expires_at=expires_at,
            user_id=int(user["id"]),
            reference_type="admin_login",
            reference_id=str(user["id"]),
        )

    email_content = build_admin_login_request_email(
        requested_for_name=str(user["full_name"] or ""),
        requested_for_email=str(user["email"] or ""),
        otp_code=code,
        requested_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
    sent = send_mail(
        OWNER_ALERT_EMAIL,
        email_content.subject,
        email_content.text_body,
        email_content.html_body,
    )
    if not sent:
        raise HTTPException(status_code=503, detail="Unable to send admin OTP email. Check SMTP settings.")
    return {"status": "otp_sent_to_owner"}


@router.post("/verify-admin-login-code")
def verify_admin_login_code(payload: AdminOtpVerifyRequest) -> dict:
    with get_connection("strategy") as conn:
        user = conn.execute(
            """
            SELECT
                u.id,
                u.organization_id,
                u.full_name,
                u.email,
                u.role,
                u.is_active,
                u.is_approved,
                (
                    SELECT om.organization_id
                    FROM organization_memberships om
                    WHERE om.user_id = u.id
                    ORDER BY CASE WHEN lower(om.status) = 'active' THEN 0 WHEN lower(om.status) = 'pending' THEN 1 ELSE 2 END,
                             om.id ASC
                    LIMIT 1
                ) AS membership_organization_id,
                (
                    SELECT om.membership_role
                    FROM organization_memberships om
                    WHERE om.user_id = u.id
                    ORDER BY CASE WHEN lower(om.status) = 'active' THEN 0 WHEN lower(om.status) = 'pending' THEN 1 ELSE 2 END,
                             om.id ASC
                    LIMIT 1
                ) AS membership_role,
                (
                    SELECT om.status
                    FROM organization_memberships om
                    WHERE om.user_id = u.id
                    ORDER BY CASE WHEN lower(om.status) = 'active' THEN 0 WHEN lower(om.status) = 'pending' THEN 1 ELSE 2 END,
                             om.id ASC
                    LIMIT 1
                ) AS membership_status
            FROM users u
            WHERE lower(u.email) = ?
            """,
            (payload.email.lower(),),
        ).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user_context = dict(user)
        user_context["effective_role"] = get_effective_role(user_context)
        user_context["effective_organization_id"] = get_effective_organization_id(user_context)
        if user_context["effective_role"] not in {"owner", "super_admin", "org_admin"}:
            raise HTTPException(status_code=403, detail="User is not admin eligible")

        row = conn.execute(
            """
            SELECT id, code_hash, expires_at, is_used
            FROM admin_otp_requests
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (user["id"],),
        ).fetchone()
        if not row or row["is_used"]:
            raise HTTPException(status_code=400, detail="Invalid or expired code")

        if row["expires_at"] < datetime.now(timezone.utc).isoformat():
            raise HTTPException(status_code=400, detail="Invalid or expired code")

        challenge_ok = _mark_email_otp_used(
            conn,
            email=str(user["email"]),
            purpose="login_verify",
            code=payload.code,
        )
        if not challenge_ok and hash_token(payload.code) != row["code_hash"]:
            raise HTTPException(status_code=400, detail="Invalid or expired code")

        conn.execute("UPDATE admin_otp_requests SET is_used = 1 WHERE id = ?", (row["id"],))

    token = create_access_token(
        subject=user["email"],
        role=user["role"],
        organization_id=user_context["effective_organization_id"],
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "organization_id": user_context["effective_organization_id"],
            "full_name": user["full_name"],
            "email": user["email"],
            "role": user_context["effective_role"],
        },
    }


@router.get("/me")
def me(user: dict = Depends(get_current_user)) -> dict:
    with get_connection("strategy") as conn:
        effective_organization_id = user.get("effective_organization_id") or user.get("organization_id") or user.get("membership_organization_id")
        organization = None
        if effective_organization_id:
            organization = conn.execute(
                "SELECT id, name, slug FROM organizations WHERE id = ? LIMIT 1",
                (effective_organization_id,),
            ).fetchone()
        profile = conn.execute(
            """
            SELECT font_size, color_theme, dark_mode
            FROM user_profiles
            WHERE user_id = ?
            """,
            (user["id"],),
        ).fetchone()
        if not profile:
            conn.execute(
                """
                INSERT INTO user_profiles (user_id, font_size, color_theme, dark_mode, updated_at)
                VALUES (?, 'medium', 'emerald', 0, CURRENT_TIMESTAMP)
                """,
                (user["id"],),
            )
            profile = conn.execute(
                """
                SELECT font_size, color_theme, dark_mode
                FROM user_profiles
                WHERE user_id = ?
                """,
                (user["id"],),
            ).fetchone()
        acl_snapshot = get_permission_snapshot(conn, user=user)
    enriched_user = dict(user)
    enriched_user["organization_name"] = str(organization["name"] or "").strip() if organization else ""
    enriched_user["organization_slug"] = str(organization["slug"] or "").strip().lower() if organization else ""
    return {
        "user": enriched_user,
        "profile": dict(profile) if profile else {"font_size": "medium", "color_theme": "emerald", "dark_mode": 0},
        **acl_snapshot,
    }


@router.get("/owner/registration-requests")
def list_registration_requests(_: dict = Depends(require_role("owner"))) -> list[dict]:
    with get_connection("strategy") as conn:
        rows = conn.execute(
            """
            SELECT id, organization_name, full_name, email, purchase_reference, status, review_note, created_at
            FROM registration_requests
            ORDER BY created_at DESC
            """
        ).fetchall()
    return rows_to_dicts(rows)


@router.post("/owner/review-registration")
def review_registration(
    payload: ApproveRegistrationRequest,
    owner: dict = Depends(require_role("owner")),
) -> dict:
    with get_connection("strategy") as conn:
        req = conn.execute(
            """
            SELECT id, organization_name, full_name, email, password_hash, status
            FROM registration_requests
            WHERE id = ?
            """,
            (payload.request_id,),
        ).fetchone()
        if not req:
            raise HTTPException(status_code=404, detail="Registration request not found")
        if req["status"] != "pending":
            raise HTTPException(status_code=400, detail="Request already reviewed")

        if payload.approve:
            org = conn.execute(
                "SELECT id FROM organizations WHERE name = ?",
                (req["organization_name"],),
            ).fetchone()
            if org:
                organization_id = int(org["id"])
            else:
                cursor = conn.execute(
                    "INSERT INTO organizations (name, purchaser_email, is_active) VALUES (?, ?, 1)",
                    (req["organization_name"], req["email"]),
                )
                organization_id = int(cursor.lastrowid)

            conn.execute(
                """
                INSERT OR REPLACE INTO users
                (organization_id, full_name, email, password_hash, role, is_active, is_approved, created_by_user_id, updated_at)
                VALUES (?, ?, ?, ?, 'buyer_admin', 1, 1, ?, CURRENT_TIMESTAMP)
                """,
                (
                    organization_id,
                    req["full_name"],
                    req["email"].lower(),
                    req["password_hash"],
                    owner["id"],
                ),
            )
            target = conn.execute(
                "SELECT id, role FROM users WHERE lower(email) = ?",
                (str(req["email"]).lower(),),
            ).fetchone()
            if target:
                ensure_user_default_permissions(
                    conn,
                    user_id=int(target["id"]),
                    role=str(target["role"]),
                    granted_by_user_id=int(owner["id"]),
                )
            status = "approved"
        else:
            status = "rejected"

        conn.execute(
            """
            UPDATE registration_requests
            SET status = ?, reviewed_by_user_id = ?, review_note = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (status, owner["id"], payload.note, payload.request_id),
        )
    return {"status": status}


@router.get("/buyer/users")
def list_org_users(admin: dict = Depends(require_role("buyer_admin", "owner"))) -> list[dict]:
    with get_connection("strategy") as conn:
        if has_role(admin, "owner"):
            rows = conn.execute(
                """
                SELECT id, organization_id, full_name, email, role, is_active, is_approved, created_at
                FROM users
                ORDER BY created_at DESC
                """
            ).fetchall()
        else:
            organization_id = get_effective_organization_id(admin)
            rows = conn.execute(
                """
                SELECT id, organization_id, full_name, email, role, is_active, is_approved, created_at
                FROM users
                WHERE organization_id = ?
                ORDER BY created_at DESC
                """,
                (organization_id,),
            ).fetchall()
    return rows_to_dicts(rows)


@router.post("/buyer/create-user")
def create_org_user(
    payload: CreateOrgUserRequest,
    admin: dict = Depends(require_role("buyer_admin", "owner")),
) -> dict:
    if has_role(admin, "buyer_admin") and not has_role(admin, "owner") and payload.organization_id != get_effective_organization_id(admin):
        raise HTTPException(status_code=403, detail="Cannot create users for another organization")
    with get_connection("strategy") as conn:
        org = conn.execute(
            "SELECT id FROM organizations WHERE id = ?",
            (payload.organization_id,),
        ).fetchone()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        existing = conn.execute(
            "SELECT id FROM users WHERE lower(email) = ?",
            (payload.email.lower(),),
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="Email already registered")
        conn.execute(
            """
            INSERT INTO users
            (organization_id, full_name, email, password_hash, role, is_active, is_approved, created_by_user_id, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, 0, ?, CURRENT_TIMESTAMP)
            """,
            (
                payload.organization_id,
                payload.full_name.strip(),
                payload.email.lower(),
                hash_password(payload.password),
                payload.role,
                admin["id"],
            ),
        )
    return {"status": "created_pending_approval"}


@router.post("/buyer/review-user")
def review_org_user(
    payload: ApproveOrgUserRequest,
    admin: dict = Depends(require_role("buyer_admin", "owner")),
) -> dict:
    with get_connection("strategy") as conn:
        user = conn.execute(
            """
            SELECT id, organization_id, role
            FROM users
            WHERE id = ?
            """,
            (payload.user_id,),
        ).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if not has_role(admin, "owner") and user["organization_id"] != get_effective_organization_id(admin):
            raise HTTPException(status_code=403, detail="Cannot review users from another organization")
        if user["role"] == "owner":
            raise HTTPException(status_code=403, detail="Owner account cannot be modified")
        conn.execute(
            "UPDATE users SET is_approved = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (1 if payload.approve else 0, payload.user_id),
        )
        if payload.approve:
            target = conn.execute(
                "SELECT id, role FROM users WHERE id = ?",
                (payload.user_id,),
            ).fetchone()
            if target:
                ensure_user_default_permissions(
                    conn,
                    user_id=int(target["id"]),
                    role=str(target["role"]),
                    granted_by_user_id=int(admin["id"]),
                )
    return {"status": "approved" if payload.approve else "rejected"}
