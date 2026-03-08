import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query

from ..database import get_connection, rows_to_dicts
from ..schemas.admin import (
    AccessPreviewRequest,
    ApplyRoleTemplateRequest,
    BulkUserReviewRequest,
    DeleteOrganizationRequest,
    ChangePasswordRequest,
    CreateOrganizationInvitationRequest,
    DeleteUsersRequest,
    OwnerOrganizationReviewRequest,
    OwnerPlatformUserReviewRequest,
    OrganizationBoundaryRequest,
    PermissionFlags,
    ProjectAccessAssignmentRequest,
    ReviewOrganizationMemberSignupRequest,
    RemoveProjectAccessRequest,
    SetModuleAccessRequest,
    SetSubEntityAccessRequest,
    TransferOwnershipRequest,
    UpdateProfileDetailsRequest,
    UpdateUserRoleRequest,
    UpdateUserStatusRequest,
    UserProfileSettingsRequest,
)
from ..services.acl import (
    PERMISSION_COLUMNS,
    assert_module_permission,
    assert_project_permission,
    ensure_user_default_permissions,
    get_permission_snapshot,
    list_modules,
    list_projects,
    list_sub_entities,
    preview_access,
    remove_permission,
    transfer_project_ownership,
    upsert_permission,
)
from ..services.audit import log_audit_event
from ..services.email_templates import build_invitation_email, build_project_update_reminder_email
from ..services.authz import get_current_user, get_data_scope_organization_id, get_effective_organization_id, get_effective_role, has_role, require_role
from ..services.mail_service import send_mail
from ..services.security import generate_token, hash_password, hash_token, verify_password
from ..settings import APP_BASE_URL, SMTP_PASSWORD, SMTP_USER
from .auth import _build_tenant_workspace_url, _slugify, _upsert_membership

router = APIRouter(prefix="/api/admin", tags=["admin"])

ALLOWED_ROLES = {"org_user", "org_admin", "buyer_admin", "owner", "super_admin"}


def _is_elevated(actor: dict) -> bool:
    return get_effective_role(actor) in {"owner", "super_admin"}


def _actor_organization_id(actor: dict) -> int | None:
    return get_effective_organization_id(actor)


def _actor_data_scope_organization_id(actor: dict) -> int | None:
    return get_data_scope_organization_id(actor)


def _target_visible_in_scope(actor: dict, target: dict) -> bool:
    effective_role = get_effective_role(target)
    effective_organization_id = get_effective_organization_id(target)

    if not _is_elevated(actor):
        return effective_organization_id == _actor_organization_id(actor)

    scope_organization_id = _actor_data_scope_organization_id(actor)
    if scope_organization_id is None:
        return effective_role in {"owner", "super_admin"} or effective_organization_id is None

    return effective_role in {"owner", "super_admin"} or effective_organization_id == scope_organization_id


def _hydrate_target_user_context(conn, target: dict, *, preferred_organization_id: int | None = None) -> dict:
    lookup_organization_id = preferred_organization_id or target.get("organization_id")
    membership = None
    if lookup_organization_id is not None:
        membership = conn.execute(
            """
            SELECT organization_id, membership_role, status
            FROM organization_memberships
            WHERE user_id = ? AND organization_id = ?
            LIMIT 1
            """,
            (target["id"], lookup_organization_id),
        ).fetchone()
    if not membership:
        membership = conn.execute(
            """
            SELECT organization_id, membership_role, status
            FROM organization_memberships
            WHERE user_id = ?
            ORDER BY CASE WHEN lower(status) = 'active' THEN 0 WHEN lower(status) = 'pending' THEN 1 ELSE 2 END,
                     id ASC
            LIMIT 1
            """,
            (target["id"],),
        ).fetchone()
    target_dict = dict(target)
    if membership:
        target_dict["membership_organization_id"] = membership["organization_id"]
        target_dict["membership_role"] = membership["membership_role"]
        target_dict["membership_status"] = membership["status"]
        if target_dict.get("organization_id") is None:
            target_dict["effective_organization_id"] = membership["organization_id"]
    target_dict.setdefault("effective_organization_id", target_dict.get("organization_id"))
    target_dict["effective_role"] = get_effective_role(target_dict)
    return target_dict


def _flags_to_permission_dict(flags: PermissionFlags) -> dict[str, bool]:
    return {
        "can_view": bool(flags.can_view),
        "can_create": bool(flags.can_create),
        "can_edit": bool(flags.can_edit),
        "can_delete": bool(flags.can_delete),
        "can_approve": bool(flags.can_approve),
        "can_assign": bool(flags.can_assign),
        "can_evaluate": bool(flags.can_evaluate),
    }


def _get_target_user(conn, actor: dict, user_id: int) -> dict:
    row = conn.execute(
        """
        SELECT id, organization_id, full_name, email, role, is_active, is_approved, created_at
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    target = _hydrate_target_user_context(conn, dict(row), preferred_organization_id=_actor_organization_id(actor))
    if not _target_visible_in_scope(actor, target):
        raise HTTPException(status_code=403, detail="Cannot manage users from another organization")
    if not _is_elevated(actor) and get_effective_role(target) in {"owner", "super_admin"}:
        raise HTTPException(status_code=403, detail="Cannot modify owner account")
    return target


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _send_mail_or_link(*, email: str, subject: str, body: str, link: str, html_body: str | None = None) -> dict:
    if send_mail(email, subject, body, html_body):
        return {"delivery": "email"}
    if not SMTP_USER or not SMTP_PASSWORD:
        return {"delivery": "debug", "invitation_link": link}
    raise HTTPException(status_code=503, detail="Unable to send invitation email. Check SMTP settings.")


def _get_target_invitation(conn, admin: dict, invitation_id: int) -> dict:
    row = conn.execute(
        """
        SELECT id, organization_id, inviter_user_id, email, full_name, role, expires_at, status, accepted_user_id, created_at
        FROM organization_invitations
        WHERE id = ?
        """,
        (invitation_id,),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Invitation not found")
    invitation = dict(row)
    scope_organization_id = _actor_data_scope_organization_id(admin)
    if _is_elevated(admin):
        if scope_organization_id is None:
            raise HTTPException(status_code=403, detail="Select an organization before managing invitations")
        if invitation["organization_id"] != scope_organization_id:
            raise HTTPException(status_code=403, detail="Cannot manage invitations for another organization")
    elif invitation["organization_id"] != _actor_organization_id(admin):
        raise HTTPException(status_code=403, detail="Cannot manage invitations for another organization")
    return invitation


def _get_target_member_signup_request(conn, admin: dict, request_id: int) -> dict:
    row = conn.execute(
        """
        SELECT r.id, r.organization_id, r.full_name, r.email, r.password_hash, r.requested_role,
               r.otp_expires_at, r.otp_verified_at, r.status, r.review_note, r.created_at,
               o.name AS organization_name, o.status AS organization_status, o.approval_status
        FROM organization_member_signup_requests r
        JOIN organizations o ON o.id = r.organization_id
        WHERE r.id = ?
        LIMIT 1
        """,
        (request_id,),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Member signup request not found")
    request = dict(row)
    scope_organization_id = _actor_data_scope_organization_id(admin)
    if _is_elevated(admin):
        if scope_organization_id is None:
            raise HTTPException(status_code=403, detail="Select an organization before reviewing member signup requests")
        if int(request["organization_id"]) != int(scope_organization_id):
            raise HTTPException(status_code=403, detail="Cannot manage requests for another organization")
    elif int(request["organization_id"]) != int(_actor_organization_id(admin) or 0):
        raise HTTPException(status_code=403, detail="Cannot manage requests for another organization")
    return request


def _create_invitation_record(
    conn,
    *,
    organization_id: int,
    inviter_user_id: int,
    email: str,
    full_name: str,
    role: str,
    expires_in_days: int,
) -> dict:
    organization = conn.execute(
        "SELECT id, name, slug, approval_status FROM organizations WHERE id = ?",
        (organization_id,),
    ).fetchone()
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")
    if organization["approval_status"] != "approved":
        raise HTTPException(status_code=400, detail="Organization is not approved for invitations")

    email_value = email.strip().lower()
    existing_user = conn.execute(
        "SELECT id FROM users WHERE lower(email) = ?",
        (email_value,),
    ).fetchone()
    if existing_user:
        raise HTTPException(status_code=409, detail="Email already registered")

    raw_token = generate_token(24)
    if expires_in_days == 0:
        expires_at = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc).isoformat()
        expiry_copy = "This invitation does not expire."
    else:
        expires_dt = datetime.now(timezone.utc) + timedelta(days=expires_in_days)
        expires_at = expires_dt.isoformat()
        expiry_copy = f"This invitation expires on {expires_dt.strftime('%d %b %Y at %H:%M UTC')}."
    cursor = conn.execute(
        """
        INSERT INTO organization_invitations
        (organization_id, inviter_user_id, email, full_name, role, token_hash, expires_at, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """,
        (
            organization_id,
            inviter_user_id,
            email_value,
            full_name.strip(),
            role,
            hash_token(raw_token),
            expires_at,
        ),
    )
    invitation_id = int(cursor.lastrowid)
    domain_row = conn.execute(
        """
        SELECT subdomain
        FROM organization_domains
        WHERE organization_id = ?
        ORDER BY CASE WHEN is_primary = 1 THEN 0 ELSE 1 END, id ASC
        LIMIT 1
        """,
        (organization_id,),
    ).fetchone()
    workspace_subdomain = str(domain_row["subdomain"] if domain_row else "").strip().lower()
    if not workspace_subdomain:
        workspace_subdomain = str(organization["slug"] or "").strip().lower()
    if not workspace_subdomain:
        workspace_subdomain = _slugify(str(organization["name"] or ""))
    workspace_base_url = _build_tenant_workspace_url(workspace_subdomain)
    invitation_link = f"{workspace_base_url}/login?invite={raw_token}"
    email_content = build_invitation_email(
        full_name=full_name.strip(),
        organization_name=str(organization["name"] or "").strip(),
        invitation_link=invitation_link,
        expiry_line=expiry_copy,
    )
    delivery = _send_mail_or_link(
        email=email_value,
        subject=email_content.subject,
        body=email_content.text_body,
        html_body=email_content.html_body,
        link=invitation_link,
    )
    return {
        "invitation_id": invitation_id,
        "organization_id": organization_id,
        "expires_at": expires_at,
        **delivery,
    }


def _parse_invitation_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    candidate = str(value).strip()
    if not candidate:
        return None
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = datetime.strptime(candidate, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _derive_invitation_expiry_days(invitation: dict) -> int:
    created_at = _parse_invitation_datetime(invitation.get("created_at"))
    expires_at = _parse_invitation_datetime(invitation.get("expires_at"))
    if not created_at or not expires_at:
        return 7
    if expires_at.year >= 9999:
        return 0
    delta = expires_at - created_at
    days = max(1, int(round(delta.total_seconds() / 86400)))
    return min(days, 30)


def _pick_reassignment_user_id(
    conn,
    *,
    target_user_id: int,
    preferred_user_id: int | None,
) -> int | None:
    if preferred_user_id and preferred_user_id != target_user_id:
        preferred = conn.execute(
            "SELECT id FROM users WHERE id = ?",
            (preferred_user_id,),
        ).fetchone()
        if preferred:
            return int(preferred["id"])

    elevated = conn.execute(
        """
        SELECT id
        FROM users
        WHERE id != ?
          AND is_active = 1
          AND is_approved = 1
          AND role IN ('owner', 'super_admin')
        ORDER BY CASE WHEN role = 'owner' THEN 0 ELSE 1 END, id ASC
        LIMIT 1
        """,
        (target_user_id,),
    ).fetchone()
    if elevated:
        return int(elevated["id"])

    fallback = conn.execute(
        """
        SELECT id
        FROM users
        WHERE id != ?
          AND is_active = 1
          AND is_approved = 1
        ORDER BY id ASC
        LIMIT 1
        """,
        (target_user_id,),
    ).fetchone()
    if fallback:
        return int(fallback["id"])
    return None


def _delete_user_account(conn, *, actor: dict, target: dict) -> dict:
    actor_user_id = int(actor["id"])
    target_user_id = int(target["id"])
    same_user = actor_user_id == target_user_id
    target_effective_role = get_effective_role(target)

    if target_effective_role in {"owner", "super_admin"} and not _is_elevated(actor):
        raise HTTPException(status_code=403, detail="Only elevated admins can delete elevated accounts")

    if target_effective_role in {"owner", "super_admin"}:
        other_elevated = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM users
            WHERE id != ?
              AND is_active = 1
              AND is_approved = 1
              AND role IN ('owner', 'super_admin')
            """,
            (target_user_id,),
        ).fetchone()
        if int(other_elevated["total"]) == 0:
            raise HTTPException(status_code=409, detail="Cannot delete the last elevated admin account")

    reassigned_user_id = _pick_reassignment_user_id(
        conn,
        target_user_id=target_user_id,
        preferred_user_id=None if same_user else actor_user_id,
    )

    if reassigned_user_id is None:
        owned_count = conn.execute(
            "SELECT COUNT(*) AS total FROM projects WHERE owner_user_id = ?",
            (target_user_id,),
        ).fetchone()
        created_count = conn.execute(
            "SELECT COUNT(*) AS total FROM projects WHERE created_by_user_id = ?",
            (target_user_id,),
        ).fetchone()
        if int(owned_count["total"]) > 0 or int(created_count["total"]) > 0:
            raise HTTPException(
                status_code=409,
                detail="Cannot delete account because it owns project records and no replacement user is available",
            )
    else:
        conn.execute(
            "UPDATE projects SET owner_user_id = ?, updated_at = CURRENT_TIMESTAMP WHERE owner_user_id = ?",
            (reassigned_user_id, target_user_id),
        )
        conn.execute(
            "UPDATE projects SET created_by_user_id = ?, updated_at = CURRENT_TIMESTAMP WHERE created_by_user_id = ?",
            (reassigned_user_id, target_user_id),
        )

    if reassigned_user_id is None:
        conn.execute(
            "UPDATE permissions SET granted_by_user_id = NULL, updated_at = CURRENT_TIMESTAMP WHERE granted_by_user_id = ?",
            (target_user_id,),
        )
        conn.execute("UPDATE audit_logs SET actor_user_id = NULL WHERE actor_user_id = ?", (target_user_id,))
    else:
        conn.execute(
            "UPDATE permissions SET granted_by_user_id = ?, updated_at = CURRENT_TIMESTAMP WHERE granted_by_user_id = ?",
            (reassigned_user_id, target_user_id),
        )
        conn.execute(
            "UPDATE audit_logs SET actor_user_id = ? WHERE actor_user_id = ?",
            (reassigned_user_id, target_user_id),
        )

    conn.execute("DELETE FROM user_profiles WHERE user_id = ?", (target_user_id,))
    conn.execute("DELETE FROM permissions WHERE user_id = ?", (target_user_id,))
    conn.execute("DELETE FROM user_permissions WHERE user_id = ?", (target_user_id,))
    conn.execute("DELETE FROM reminder_jobs WHERE user_id = ?", (target_user_id,))
    conn.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (target_user_id,))
    conn.execute("DELETE FROM admin_otp_requests WHERE user_id = ?", (target_user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (target_user_id,))

    actor_for_log = actor_user_id
    if same_user:
        actor_for_log = reassigned_user_id

    log_audit_event(
        actor_user_id=actor_for_log,
        action="user_deleted",
        entity_type="user",
        entity_id=str(target_user_id),
        details={
            "target_user_id": target_user_id,
            "target_email": target["email"],
            "target_role": target_effective_role,
            "self_service": same_user,
            "reassigned_user_id": reassigned_user_id,
        },
        conn=conn,
    )
    return {"deleted_user_id": target_user_id, "reassigned_user_id": reassigned_user_id}


def _normalized_organization_name(value: str | None) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _delete_organization_external_records(*, organization_name: str) -> dict[str, int]:
    normalized_name = _normalized_organization_name(organization_name)
    counts = {
        "fuel_calculations": 0,
        "co2_projects": 0,
        "macc_projects": 0,
    }
    if not normalized_name:
        return counts

    with get_connection("fuel") as fuel_conn:
        fuel_rows = fuel_conn.execute(
            "SELECT id, unique_code FROM calculations WHERE lower(trim(org_name)) = ?",
            (normalized_name,),
        ).fetchall()
        fuel_ids = [int(row["id"]) for row in fuel_rows]
        fuel_codes = [str(row["unique_code"] or "") for row in fuel_rows if row["unique_code"]]
        counts["fuel_calculations"] = len(fuel_ids)
        if fuel_ids:
            placeholders = ",".join("?" for _ in fuel_ids)
            fuel_conn.execute(f"DELETE FROM materials_baseline WHERE calculation_id IN ({placeholders})", tuple(fuel_ids))
            fuel_conn.execute(f"DELETE FROM emission_reductions WHERE calculation_id IN ({placeholders})", tuple(fuel_ids))
            fuel_conn.execute(f"DELETE FROM base_value_details WHERE calculation_id IN ({placeholders})", tuple(fuel_ids))
            fuel_conn.execute(f"DELETE FROM calculations WHERE id IN ({placeholders})", tuple(fuel_ids))
        if fuel_codes:
            placeholders = ",".join("?" for _ in fuel_codes)
            fuel_conn.execute(f"DELETE FROM fuel_yearly_data WHERE unique_code IN ({placeholders})", tuple(fuel_codes))

    with get_connection("co2") as co2_conn:
        co2_rows = co2_conn.execute(
            "SELECT project_code FROM projects WHERE lower(trim(organization)) = ?",
            (normalized_name,),
        ).fetchall()
        co2_codes = [str(row["project_code"] or "") for row in co2_rows if row["project_code"]]
        counts["co2_projects"] = len(co2_codes)
        if co2_codes:
            placeholders = ",".join("?" for _ in co2_codes)
            co2_conn.execute(f"DELETE FROM project_actuals WHERE project_code IN ({placeholders})", tuple(co2_codes))
            co2_conn.execute(f"DELETE FROM amp_actuals_tracking WHERE project_code IN ({placeholders})", tuple(co2_codes))
            co2_conn.execute(f"DELETE FROM project_status_updates WHERE project_code IN ({placeholders})", tuple(co2_codes))
            co2_conn.execute(f"DELETE FROM projects WHERE project_code IN ({placeholders})", tuple(co2_codes))

    with get_connection("npv") as npv_conn:
        deleted = npv_conn.execute(
            "DELETE FROM npv_projects WHERE lower(trim(organization)) = ?",
            (normalized_name,),
        )
        counts["macc_projects"] = int(deleted.rowcount or 0)

    return counts


def _delete_organization_strategy_records(conn, *, organization_id: int, organization_name: str, actor: dict) -> dict[str, int | str | None]:
    normalized_name = _normalized_organization_name(organization_name)
    user_rows = conn.execute(
        """
        SELECT DISTINCT u.id, u.role
        FROM users u
        LEFT JOIN organization_memberships om ON om.user_id = u.id
        WHERE u.organization_id = ? OR om.organization_id = ?
        ORDER BY u.id ASC
        """,
        (organization_id, organization_id),
    ).fetchall()
    user_ids = [int(row["id"]) for row in user_rows]

    elevated_users = [int(row["id"]) for row in user_rows if str(row["role"] or "").strip().lower() in {"owner", "super_admin"}]
    if elevated_users:
        raise HTTPException(status_code=409, detail="Remove elevated accounts from this organization before deleting the workspace")

    project_rows = conn.execute(
        "SELECT id FROM projects WHERE organization_id = ?",
        (organization_id,),
    ).fetchall()
    project_ids = [int(row["id"]) for row in project_rows]

    signup_deleted = conn.execute(
        "DELETE FROM signup_requests WHERE organization_id = ?",
        (organization_id,),
    )
    boundary_deleted = conn.execute(
        "DELETE FROM organization_boundaries WHERE organization_id = ?",
        (organization_id,),
    )
    invitation_deleted = conn.execute(
        "DELETE FROM organization_invitations WHERE organization_id = ?",
        (organization_id,),
    )
    member_request_deleted = conn.execute(
        "DELETE FROM organization_member_signup_requests WHERE organization_id = ?",
        (organization_id,),
    )
    approval_deleted = conn.execute(
        "DELETE FROM organization_status_approvals WHERE organization_id = ?",
        (organization_id,),
    )
    domain_deleted = conn.execute(
        "DELETE FROM organization_domains WHERE organization_id = ?",
        (organization_id,),
    )

    if project_ids:
        project_placeholders = ",".join("?" for _ in project_ids)
        conn.execute(
            f"DELETE FROM audit_logs WHERE project_id IN ({project_placeholders})",
            tuple(project_ids),
        )
        conn.execute(
            f"DELETE FROM permissions WHERE project_id IN ({project_placeholders})",
            tuple(project_ids),
        )
        conn.execute(
            f"DELETE FROM sub_entities WHERE project_id IN ({project_placeholders})",
            tuple(project_ids),
        )

    if user_ids:
        user_placeholders = ",".join("?" for _ in user_ids)
        conn.execute(
            f"DELETE FROM audit_logs WHERE actor_user_id IN ({user_placeholders}) OR (entity_type = 'user' AND entity_id IN ({user_placeholders}))",
            tuple(user_ids + [str(user_id) for user_id in user_ids]),
        )
        conn.execute(
            f"DELETE FROM permissions WHERE user_id IN ({user_placeholders}) OR granted_by_user_id IN ({user_placeholders})",
            tuple(user_ids + user_ids),
        )
        conn.execute(f"DELETE FROM user_permissions WHERE user_id IN ({user_placeholders})", tuple(user_ids))
        conn.execute(f"DELETE FROM reminder_jobs WHERE user_id IN ({user_placeholders})", tuple(user_ids))
        conn.execute(f"DELETE FROM password_reset_tokens WHERE user_id IN ({user_placeholders})", tuple(user_ids))
        conn.execute(f"DELETE FROM admin_otp_requests WHERE user_id IN ({user_placeholders})", tuple(user_ids))
        conn.execute(f"DELETE FROM user_profiles WHERE user_id IN ({user_placeholders})", tuple(user_ids))
        conn.execute(f"DELETE FROM normal_user_approvals WHERE user_id IN ({user_placeholders})", tuple(user_ids))

    conn.execute(
        "DELETE FROM audit_logs WHERE entity_type = 'organization' AND entity_id = ?",
        (str(organization_id),),
    )
    portfolio_deleted = conn.execute(
        "DELETE FROM strategy_portfolios WHERE lower(trim(organization)) = ?",
        (normalized_name,),
    )
    acl_project_deleted = conn.execute(
        "DELETE FROM projects WHERE organization_id = ?",
        (organization_id,),
    )
    membership_deleted = conn.execute(
        "DELETE FROM organization_memberships WHERE organization_id = ?",
        (organization_id,),
    )
    user_deleted = conn.execute(
        f"DELETE FROM users WHERE id IN ({','.join('?' for _ in user_ids)})",
        tuple(user_ids),
    ) if user_ids else None
    organization_deleted = conn.execute(
        "DELETE FROM organizations WHERE id = ?",
        (organization_id,),
    )

    log_audit_event(
        actor_user_id=actor["id"],
        action="organization_deleted",
        entity_type="organization",
        entity_id=str(organization_id),
        details={
            "organization_id": organization_id,
            "organization_name": organization_name,
            "deleted_user_count": len(user_ids),
            "deleted_project_count": len(project_ids),
            "deleted_strategy_portfolio_count": int(portfolio_deleted.rowcount or 0),
        },
        conn=conn,
    )

    return {
        "organization_id": organization_id,
        "organization_name": organization_name,
        "deleted_user_count": len(user_ids),
        "deleted_project_count": int(acl_project_deleted.rowcount or 0),
        "deleted_portfolio_count": int(portfolio_deleted.rowcount or 0),
        "deleted_membership_count": int(membership_deleted.rowcount or 0),
        "deleted_domain_count": int(domain_deleted.rowcount or 0),
        "deleted_invitation_count": int(invitation_deleted.rowcount or 0),
        "deleted_member_request_count": int(member_request_deleted.rowcount or 0),
        "deleted_signup_request_count": int(signup_deleted.rowcount or 0),
        "deleted_boundary_count": int(boundary_deleted.rowcount or 0),
        "deleted_approval_count": int(approval_deleted.rowcount or 0),
        "deleted_organization_count": int(organization_deleted.rowcount or 0),
        "deleted_user_row_count": int(user_deleted.rowcount or 0) if user_deleted else 0,
    }


def _get_module_row(conn, module_key: str) -> dict:
    row = conn.execute(
        """
        SELECT id, module_key, module_name
        FROM modules
        WHERE module_key = ?
        """,
        (module_key.strip().lower(),),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Module not found: {module_key}")
    return dict(row)


def _get_project_row(conn, module_id: int, project_id: str) -> dict:
    row = conn.execute(
        """
        SELECT id, module_id, external_project_id, project_name, owner_user_id, organization_id
        FROM projects
        WHERE module_id = ? AND external_project_id = ?
        """,
        (module_id, project_id),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Project not found")
    return dict(row)


@router.get("/users")
def list_users(
    q: str = "",
    role: str = "",
    include_inactive: bool = True,
    include_rejected: bool = True,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> list[dict]:
    with get_connection("strategy") as conn:
        params: list = []
        where = []
        if q.strip():
            where.append("(lower(full_name) LIKE ? OR lower(email) LIKE ?)")
            q_like = f"%{q.strip().lower()}%"
            params.extend([q_like, q_like])
        if not include_inactive:
            where.append("is_active = 1")
        if not include_rejected:
            where.append("is_approved = 1")
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        rows = conn.execute(
            f"""
            SELECT
                u.id,
                u.organization_id,
                u.full_name,
                u.email,
                u.role,
                u.is_active,
                u.is_approved,
                u.created_at,
                u.updated_at,
                o.name AS direct_organization_name,
                o.slug AS direct_organization_slug
            FROM users u
            LEFT JOIN organizations o ON o.id = u.organization_id
            {where_sql}
            ORDER BY u.created_at DESC
            """,
            tuple(params),
        ).fetchall()

        actor_organization_id = _actor_organization_id(admin)
        requested_role = role.strip().lower()
        records: list[dict] = []

        for row in rows:
            hydrated = _hydrate_target_user_context(
                conn,
                dict(row),
                preferred_organization_id=actor_organization_id,
            )
            effective_role = get_effective_role(hydrated)
            effective_organization_id = get_effective_organization_id(hydrated)

            if not _target_visible_in_scope(admin, hydrated):
                continue

            role_aliases = {
                str(hydrated.get("role") or "").strip().lower(),
                str(hydrated.get("membership_role") or "").strip().lower(),
                effective_role,
            }
            if effective_role == "org_admin":
                role_aliases.add("buyer_admin")
            if requested_role and requested_role not in role_aliases:
                continue

            organization_name = hydrated.get("direct_organization_name")
            organization_slug = hydrated.get("direct_organization_slug")
            if effective_organization_id and not organization_name:
                organization = conn.execute(
                    "SELECT name, slug FROM organizations WHERE id = ? LIMIT 1",
                    (effective_organization_id,),
                ).fetchone()
                if organization:
                    organization_name = organization["name"]
                    organization_slug = organization["slug"]

            hydrated["organization_id"] = effective_organization_id
            hydrated["organization_name"] = organization_name
            hydrated["organization_slug"] = organization_slug
            hydrated["effective_role"] = effective_role
            hydrated["role_scope"] = "organization" if effective_role in {"org_admin", "org_user"} else "platform"
            records.append(hydrated)

    def sort_key(user_row: dict) -> tuple:
        organization_order = 1 if user_row.get("role_scope") == "organization" else 0
        organization_name = str(user_row.get("organization_name") or "").lower()
        role_order = {
            "owner": 0,
            "super_admin": 1,
            "org_admin": 2,
            "org_user": 3,
        }.get(str(user_row.get("effective_role") or user_row.get("role") or "").strip().lower(), 9)
        created_at = str(user_row.get("created_at") or "")
        full_name = str(user_row.get("full_name") or "").lower()
        return (organization_order, organization_name, role_order, created_at, full_name)

    return sorted(records, key=sort_key)


@router.patch("/users/{user_id}/status")
def set_user_status(
    user_id: int,
    payload: UpdateUserStatusRequest,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> dict:
    with get_connection("strategy") as conn:
        target = _get_target_user(conn, admin, user_id)
        if get_effective_role(target) in {"owner", "super_admin"} and not _is_elevated(admin):
            raise HTTPException(status_code=403, detail="Owner status can only be changed by owner")
        conn.execute(
            "UPDATE users SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (1 if payload.is_active else 0, user_id),
        )
        log_audit_event(
            actor_user_id=admin["id"],
            action="user_status_updated",
            entity_type="user",
            entity_id=str(user_id),
            details={"target_user_id": user_id, "is_active": payload.is_active},
            conn=conn,
        )
    return {"status": "ok", "user_id": user_id, "is_active": payload.is_active}


@router.patch("/users/{user_id}/role")
def set_user_role(
    user_id: int,
    payload: UpdateUserRoleRequest,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> dict:
    next_role = payload.role.strip().lower()
    if next_role == "org_admin":
        next_role = "buyer_admin"
    if next_role not in ALLOWED_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role: {payload.role}")
    if not _is_elevated(admin) and next_role in {"owner", "super_admin", "buyer_admin"}:
        raise HTTPException(status_code=403, detail="Buyer admin cannot assign elevated roles")

    with get_connection("strategy") as conn:
        target = _get_target_user(conn, admin, user_id)
        if get_effective_role(target) in {"owner", "super_admin"} and not _is_elevated(admin):
            raise HTTPException(status_code=403, detail="Owner role cannot be changed by buyer admin")
        conn.execute(
            "UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (next_role, user_id),
        )
        ensure_user_default_permissions(
            conn,
            user_id=user_id,
            role=next_role,
            granted_by_user_id=int(admin["id"]),
        )
        log_audit_event(
            actor_user_id=admin["id"],
            action="user_role_updated",
            entity_type="user",
            entity_id=str(user_id),
            details={"target_user_id": user_id, "new_role": next_role},
            conn=conn,
        )
    return {"status": "ok", "user_id": user_id, "role": next_role}


@router.post("/users/{user_id}/apply-role-template")
def apply_user_role_template(
    user_id: int,
    payload: ApplyRoleTemplateRequest,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> dict:
    requested_role = payload.role.strip().lower()
    if requested_role == "org_admin":
        requested_role = "buyer_admin"

    with get_connection("strategy") as conn:
        target = _get_target_user(conn, admin, user_id)
        target_effective_role = get_effective_role(target)
        template_role = requested_role or str(target.get("role") or target_effective_role).strip().lower()
        if template_role == "org_admin":
            template_role = "buyer_admin"
        if template_role not in ALLOWED_ROLES:
            raise HTTPException(status_code=400, detail=f"Invalid role template: {payload.role or template_role}")
        if not _is_elevated(admin) and template_role in {"owner", "super_admin", "buyer_admin"}:
            raise HTTPException(status_code=403, detail="Buyer admin cannot apply elevated role templates")
        if target_effective_role in {"owner", "super_admin"} and not _is_elevated(admin):
            raise HTTPException(status_code=403, detail="Owner role template can only be applied by owner")

        if template_role != str(target.get("role") or "").strip().lower():
            conn.execute(
                "UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (template_role, user_id),
            )

        ensure_user_default_permissions(
            conn,
            user_id=user_id,
            role=template_role,
            granted_by_user_id=int(admin["id"]),
        )
        log_audit_event(
            actor_user_id=admin["id"],
            action="user_role_template_applied",
            entity_type="user",
            entity_id=str(user_id),
            details={
                "target_user_id": user_id,
                "template_role": template_role,
            },
            conn=conn,
        )
    return {"status": "ok", "user_id": user_id, "role": template_role}


@router.delete("/users/{user_id}")
def delete_user_account(
    user_id: int,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> dict:
    with get_connection("strategy") as conn:
        target = _get_target_user(conn, admin, user_id)
        if int(target["id"]) == int(admin["id"]):
            raise HTTPException(status_code=400, detail="Use profile delete option to delete your own account")
        result = _delete_user_account(conn, actor=admin, target=target)
    return {"status": "ok", **result}


@router.post("/users/bulk-review")
def bulk_review_users(
    payload: BulkUserReviewRequest,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> dict:
    user_ids = sorted(set(int(user_id) for user_id in payload.user_ids if user_id))
    if not user_ids:
        return {"status": "ok", "updated": 0}

    updated = 0
    with get_connection("strategy") as conn:
        for user_id in user_ids:
            target = _get_target_user(conn, admin, user_id)
            if get_effective_role(target) in {"owner", "super_admin"}:
                continue
            conn.execute(
                "UPDATE users SET is_approved = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (1 if payload.approve else 0, user_id),
            )
            updated += 1
            log_audit_event(
                actor_user_id=admin["id"],
                action="user_bulk_review",
                entity_type="user",
                entity_id=str(user_id),
                details={"target_user_id": user_id, "approved": payload.approve},
                conn=conn,
            )
    return {"status": "ok", "updated": updated}


@router.delete("/users/rejected")
def delete_rejected_users(
    payload: DeleteUsersRequest,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> dict:
    user_ids = sorted(set(int(user_id) for user_id in payload.user_ids if user_id))
    if not user_ids:
        return {"status": "ok", "deleted": 0}

    deleted = 0
    with get_connection("strategy") as conn:
        for user_id in user_ids:
            target = _get_target_user(conn, admin, user_id)
            if target["is_approved"] or get_effective_role(target) in {"owner", "super_admin"}:
                continue
            conn.execute("DELETE FROM user_profiles WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM permissions WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM user_permissions WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM reminder_jobs WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            deleted += 1
            log_audit_event(
                actor_user_id=admin["id"],
                action="rejected_user_deleted",
                entity_type="user",
                entity_id=str(user_id),
                details={"target_user_id": user_id},
                conn=conn,
            )
    return {"status": "ok", "deleted": deleted}


@router.get("/users/{user_id}/audit")
def user_audit_history(
    user_id: int,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> list[dict]:
    with get_connection("strategy") as conn:
        _get_target_user(conn, admin, user_id)
        rows = conn.execute(
            """
            SELECT a.id, a.action, a.entity_type, a.entity_id, a.details, a.created_at, u.email AS actor_email
            FROM audit_logs a
            LEFT JOIN users u ON u.id = a.actor_user_id
            WHERE a.actor_user_id = ? OR a.details LIKE ?
            ORDER BY a.created_at DESC
            LIMIT 500
            """,
            (user_id, f'%"target_user_id":{user_id}%'),
        ).fetchall()
    records = []
    for row in rows:
        data = dict(row)
        try:
            data["details"] = json.loads(data.get("details") or "{}")
        except json.JSONDecodeError:
            data["details"] = {}
        records.append(data)
    return records


@router.get("/modules")
def get_modules(admin: dict = Depends(require_role("owner", "buyer_admin"))) -> list[dict]:
    with get_connection("strategy") as conn:
        assert_module_permission(conn, user=admin, module_key="admin", action="view")
        return list_modules(conn)


@router.get("/access/module/{user_id}")
def get_module_access(
    user_id: int,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> list[dict]:
    with get_connection("strategy") as conn:
        _get_target_user(conn, admin, user_id)
        rows = conn.execute(
            f"""
            SELECT
                m.module_key,
                m.module_name,
                {",".join(f"COALESCE(p.{col}, 0) AS {col}" for col in PERMISSION_COLUMNS)}
            FROM modules m
            LEFT JOIN permissions p ON p.id = (
                SELECT p2.id
                FROM permissions p2
                WHERE p2.user_id = ?
                  AND p2.module_id = m.id
                  AND p2.project_id IS NULL
                  AND p2.sub_entity_id IS NULL
                ORDER BY p2.updated_at DESC, p2.id DESC
                LIMIT 1
            )
            ORDER BY m.id ASC
            """,
            (user_id,),
        ).fetchall()
    return rows_to_dicts(rows)


@router.post("/access/module")
def set_module_access(
    payload: SetModuleAccessRequest,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> dict:
    with get_connection("strategy") as conn:
        target = _get_target_user(conn, admin, payload.user_id)
        assert_module_permission(conn, user=admin, module_key=payload.module_key, action="assign")
        module = _get_module_row(conn, payload.module_key)
        permissions = _flags_to_permission_dict(payload.permissions)
        upsert_permission(
            conn,
            user_id=int(target["id"]),
            module_id=int(module["id"]),
            project_id=None,
            sub_entity_id=None,
            granted_by_user_id=int(admin["id"]),
            permissions=permissions,
        )
        log_audit_event(
            actor_user_id=admin["id"],
            action="module_permission_updated",
            entity_type="permission",
            entity_id=f"{payload.user_id}:{payload.module_key}",
            module_id=int(module["id"]),
            details={"target_user_id": payload.user_id, "permissions": permissions},
            conn=conn,
        )
    return {"status": "ok"}


@router.post("/access/preview")
def access_preview(
    payload: AccessPreviewRequest,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> dict:
    with get_connection("strategy") as conn:
        target = _get_target_user(conn, admin, payload.user_id)
        return preview_access(
            conn,
            target_user=target,
            module_key=payload.module_key,
            action=payload.action,
            external_project_id=payload.project_id.strip(),
            sub_entity_key=payload.sub_entity_key.strip().lower(),
            external_sub_entity_id=payload.sub_entity_id.strip(),
        )


@router.get("/projects/{module_key}")
def get_projects_for_module(
    module_key: str,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> list[dict]:
    with get_connection("strategy") as conn:
        assert_module_permission(conn, user=admin, module_key=module_key, action="view")
        return list_projects(conn, module_key=module_key, user=admin)


@router.post("/access/projects/assign")
def assign_project_access(
    payload: ProjectAccessAssignmentRequest,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> dict:
    if not payload.user_ids:
        return {"status": "ok", "assigned": 0}
    with get_connection("strategy") as conn:
        module = _get_module_row(conn, payload.module_key)
        project = _get_project_row(conn, int(module["id"]), payload.project_id)
        assert_project_permission(
            conn,
            user=admin,
            module_key=payload.module_key,
            external_project_id=payload.project_id,
            action="assign",
            require_exists=True,
        )
        if not _is_elevated(admin) and project["organization_id"] != _actor_organization_id(admin):
            raise HTTPException(status_code=403, detail="Cannot assign projects from another organization")

        permissions = _flags_to_permission_dict(payload.permissions)
        assigned = 0
        for target_user_id in sorted(set(payload.user_ids)):
            _get_target_user(conn, admin, int(target_user_id))
            upsert_permission(
                conn,
                user_id=int(target_user_id),
                module_id=int(module["id"]),
                project_id=int(project["id"]),
                sub_entity_id=None,
                granted_by_user_id=int(admin["id"]),
                permissions=permissions,
            )
            assigned += 1
            log_audit_event(
                actor_user_id=admin["id"],
                action="project_permission_updated",
                entity_type="permission",
                entity_id=f"{target_user_id}:{payload.module_key}:{payload.project_id}",
                module_id=int(module["id"]),
                project_id=int(project["id"]),
                details={"target_user_id": int(target_user_id), "permissions": permissions},
                conn=conn,
            )
    return {"status": "ok", "assigned": assigned}


@router.post("/access/projects/remove")
def remove_project_access(
    payload: RemoveProjectAccessRequest,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> dict:
    with get_connection("strategy") as conn:
        module = _get_module_row(conn, payload.module_key)
        project = _get_project_row(conn, int(module["id"]), payload.project_id)
        assert_project_permission(
            conn,
            user=admin,
            module_key=payload.module_key,
            external_project_id=payload.project_id,
            action="assign",
            require_exists=True,
        )
        _get_target_user(conn, admin, payload.user_id)
        conn.execute("DELETE FROM permissions WHERE user_id = ? AND project_id = ?", (payload.user_id, project["id"]))
        remove_permission(
            conn,
            user_id=payload.user_id,
            module_id=int(module["id"]),
            project_id=int(project["id"]),
            sub_entity_id=None,
        )
        log_audit_event(
            actor_user_id=admin["id"],
            action="project_permission_removed",
            entity_type="permission",
            entity_id=f"{payload.user_id}:{payload.module_key}:{payload.project_id}",
            module_id=int(module["id"]),
            project_id=int(project["id"]),
            details={"target_user_id": payload.user_id},
            conn=conn,
        )
    return {"status": "ok"}


@router.post("/access/projects/transfer-ownership")
def transfer_ownership(
    payload: TransferOwnershipRequest,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> dict:
    with get_connection("strategy") as conn:
        _get_target_user(conn, admin, payload.new_owner_user_id)
        assert_project_permission(
            conn,
            user=admin,
            module_key=payload.module_key,
            external_project_id=payload.project_id,
            action="assign",
            require_exists=True,
        )
        updated = transfer_project_ownership(
            conn,
            module_key=payload.module_key,
            external_project_id=payload.project_id,
            new_owner_user_id=payload.new_owner_user_id,
            actor_user_id=admin["id"],
        )
    return {"status": "ok", "project": updated}


@router.get("/sub-entities/{module_key}/{project_id}")
def get_sub_entities_for_project(
    module_key: str,
    project_id: str,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> list[dict]:
    with get_connection("strategy") as conn:
        assert_project_permission(
            conn,
            user=admin,
            module_key=module_key,
            external_project_id=project_id,
            action="view",
            require_exists=True,
        )
        return list_sub_entities(conn, module_key=module_key, external_project_id=project_id)


@router.get("/access/sub-entity/{user_id}/{module_key}/{project_id}")
def get_sub_entity_access(
    user_id: int,
    module_key: str,
    project_id: str,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> list[dict]:
    with get_connection("strategy") as conn:
        target = _get_target_user(conn, admin, user_id)
        assert_project_permission(
            conn,
            user=admin,
            module_key=module_key,
            external_project_id=project_id,
            action="view",
            require_exists=True,
        )
        snapshot = get_permission_snapshot(conn, user=target)
        return [
            row
            for row in snapshot.get("sub_entity_permissions", [])
            if row.get("module_key") == module_key and row.get("project_id") == project_id
        ]


@router.post("/access/sub-entity")
def set_sub_entity_access(
    payload: SetSubEntityAccessRequest,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> dict:
    with get_connection("strategy") as conn:
        _get_target_user(conn, admin, payload.user_id)
        assert_project_permission(
            conn,
            user=admin,
            module_key=payload.module_key,
            external_project_id=payload.project_id,
            action="assign",
            require_exists=True,
        )
        module = _get_module_row(conn, payload.module_key)
        project = _get_project_row(conn, int(module["id"]), payload.project_id)
        sub = conn.execute(
            """
            SELECT id
            FROM sub_entities
            WHERE project_id = ? AND sub_entity_key = ? AND external_sub_entity_id = ?
            """,
            (project["id"], payload.sub_entity_key.strip().lower(), payload.sub_entity_id.strip()),
        ).fetchone()
        if not sub:
            raise HTTPException(status_code=404, detail="Sub-entity not found")

        permissions = _flags_to_permission_dict(payload.permissions)
        if any(
            permissions[key]
            for key in ("can_create", "can_edit", "can_delete", "can_approve", "can_assign", "can_evaluate")
        ):
            permissions["can_view"] = True
        upsert_permission(
            conn,
            user_id=payload.user_id,
            module_id=int(module["id"]),
            project_id=int(project["id"]),
            sub_entity_id=int(sub["id"]),
            granted_by_user_id=admin["id"],
            permissions=permissions,
        )
        log_audit_event(
            actor_user_id=admin["id"],
            action="sub_entity_permission_updated",
            entity_type="permission",
            entity_id=f"{payload.user_id}:{payload.module_key}:{payload.project_id}:{payload.sub_entity_key}:{payload.sub_entity_id}",
            module_id=int(module["id"]),
            project_id=int(project["id"]),
            sub_entity_id=int(sub["id"]),
            details={"target_user_id": payload.user_id, "permissions": permissions},
            conn=conn,
        )
    return {"status": "ok"}


@router.get("/audit")
def list_audit_logs(
    module_key: str = "",
    project_id: str = "",
    user_id: int | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> list[dict]:
    with get_connection("strategy") as conn:
        conditions = []
        params: list = []
        if module_key.strip():
            module = _get_module_row(conn, module_key)
            conditions.append("a.module_id = ?")
            params.append(module["id"])
        if project_id.strip():
            conditions.append("p.external_project_id = ?")
            params.append(project_id.strip())
        if user_id is not None:
            conditions.append("(a.actor_user_id = ? OR a.details LIKE ?)")
            params.extend([user_id, f'%"target_user_id":{user_id}%'])
        scope_organization_id = get_data_scope_organization_id(admin)
        if _is_elevated(admin) and scope_organization_id is None:
            return []
        if scope_organization_id is not None:
            conditions.append("(p.organization_id = ? OR au.organization_id = ?)")
            params.extend([scope_organization_id, scope_organization_id])
        where_sql = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = conn.execute(
            f"""
            SELECT
                a.id,
                a.action,
                a.entity_type,
                a.entity_id,
                a.details,
                a.created_at,
                m.module_key,
                p.external_project_id AS project_id,
                au.email AS actor_email
            FROM audit_logs a
            LEFT JOIN modules m ON m.id = a.module_id
            LEFT JOIN projects p ON p.id = a.project_id
            LEFT JOIN users au ON au.id = a.actor_user_id
            {where_sql}
            ORDER BY a.created_at DESC, a.id DESC
            LIMIT ?
            """,
            (*params, limit),
        ).fetchall()
    records = []
    for row in rows:
        item = dict(row)
        try:
            item["details"] = json.loads(item.get("details") or "{}")
        except json.JSONDecodeError:
            item["details"] = {}
        records.append(item)
    return records


@router.delete("/audit")
def clear_audit_logs(
    module_key: str = "",
    project_id: str = "",
    user_id: int | None = None,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> dict:
    with get_connection("strategy") as conn:
        conditions = []
        params: list = []
        if module_key.strip():
            module = _get_module_row(conn, module_key)
            conditions.append("a.module_id = ?")
            params.append(module["id"])
        if project_id.strip():
            conditions.append("p.external_project_id = ?")
            params.append(project_id.strip())
        if user_id is not None:
            _get_target_user(conn, admin, int(user_id))
            conditions.append("(a.actor_user_id = ? OR a.details LIKE ?)")
            params.extend([int(user_id), f'%"target_user_id":{int(user_id)}%'])
        scope_organization_id = get_data_scope_organization_id(admin)
        if _is_elevated(admin) and scope_organization_id is None:
            return {"status": "ok", "deleted": 0}
        if scope_organization_id is not None:
            conditions.append("(p.organization_id = ? OR au.organization_id = ?)")
            params.extend([scope_organization_id, scope_organization_id])
        where_sql = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = conn.execute(
            f"""
            SELECT a.id
            FROM audit_logs a
            LEFT JOIN projects p ON p.id = a.project_id
            LEFT JOIN users au ON au.id = a.actor_user_id
            {where_sql}
            """,
            tuple(params),
        ).fetchall()
        ids = [int(row["id"]) for row in rows]
        if not ids:
            return {"status": "ok", "deleted": 0}
        placeholders = ",".join("?" for _ in ids)
        conn.execute(f"DELETE FROM audit_logs WHERE id IN ({placeholders})", tuple(ids))
    return {"status": "ok", "deleted": len(ids)}


@router.get("/owner/pending-organizations")
def list_pending_organizations(_: dict = Depends(require_role("owner"))) -> list[dict]:
    with get_connection("strategy") as conn:
        rows = conn.execute(
            """
            SELECT
                o.id,
                o.name,
                o.slug,
                o.purchaser_email,
                o.status,
                o.approval_status,
                o.status_note,
                o.created_at,
                sr.purchase_reference,
                osa.status AS approval_record_status,
                osa.note AS approval_note,
                u.id AS admin_user_id,
                u.full_name AS admin_full_name,
                u.email AS admin_email
            FROM organizations o
            LEFT JOIN organization_memberships om ON om.id = (
                SELECT om2.id
                FROM organization_memberships om2
                WHERE om2.organization_id = o.id
                  AND om2.membership_role = 'org_admin'
                ORDER BY CASE WHEN lower(om2.status) = 'active' THEN 0 WHEN lower(om2.status) = 'pending' THEN 1 ELSE 2 END,
                         om2.id ASC
                LIMIT 1
            )
            LEFT JOIN users u ON u.id = om.user_id
            LEFT JOIN signup_requests sr ON sr.id = (
                SELECT sr2.id
                FROM signup_requests sr2
                WHERE sr2.organization_id = o.id
                  AND sr2.signup_type = 'organization'
                ORDER BY sr2.id DESC
                LIMIT 1
            )
            LEFT JOIN organization_status_approvals osa ON osa.id = (
                SELECT osa2.id
                FROM organization_status_approvals osa2
                WHERE osa2.organization_id = o.id
                ORDER BY osa2.id DESC
                LIMIT 1
            )
            WHERE COALESCE(osa.status, o.approval_status) = 'pending'
            ORDER BY o.created_at DESC, sr.id DESC
            """
        ).fetchall()
    return rows_to_dicts(rows)


@router.get("/owner/pending-platform-users")
def list_pending_platform_users(_: dict = Depends(require_role("owner"))) -> list[dict]:
    with get_connection("strategy") as conn:
        rows = conn.execute(
            """
                        SELECT u.id, u.full_name, u.email, u.role, u.signup_type, u.created_at, u.updated_at,
                                     nua.status AS approval_status,
                                     nua.note AS approval_note
                        FROM users u
                        JOIN normal_user_approvals nua ON nua.user_id = u.id
                        WHERE u.organization_id IS NULL
                            AND u.is_active = 1
                            AND nua.status = 'pending'
            ORDER BY created_at DESC
            """
        ).fetchall()
    return rows_to_dicts(rows)


@router.get("/owner/hierarchy")
def get_owner_hierarchy(_: dict = Depends(require_role("owner"))) -> dict:
    with get_connection("strategy") as conn:
        counts = conn.execute(
            """
            SELECT
                SUM(CASE WHEN approval_status = 'pending' THEN 1 ELSE 0 END) AS pending_organizations,
                SUM(CASE WHEN approval_status = 'approved' THEN 1 ELSE 0 END) AS approved_organizations,
                SUM(CASE WHEN approval_status = 'rejected' THEN 1 ELSE 0 END) AS rejected_organizations
            FROM organizations
            """
        ).fetchone()
        platform_counts = conn.execute(
            """
            SELECT
                SUM(CASE WHEN nua.status = 'pending' THEN 1 ELSE 0 END) AS pending_platform_users,
                SUM(CASE WHEN nua.status = 'approved' THEN 1 ELSE 0 END) AS approved_platform_users
            FROM normal_user_approvals nua
            """
        ).fetchone()
        organizations = conn.execute(
            """
            SELECT
                o.id,
                o.name,
                o.slug,
                o.status,
                o.approval_status,
                o.created_at,
                COUNT(CASE WHEN om.membership_role = 'org_admin' THEN 1 END) AS admin_count,
                COUNT(CASE WHEN om.membership_role = 'org_user' THEN 1 END) AS user_count
            FROM organizations o
            LEFT JOIN organization_memberships om ON om.organization_id = o.id AND om.status IN ('active', 'pending')
            GROUP BY o.id, o.name, o.slug, o.status, o.approval_status, o.created_at
            ORDER BY o.created_at DESC
            """
        ).fetchall()
    return {
        "summary": {
            "pending_organizations": int(counts["pending_organizations"] or 0),
            "approved_organizations": int(counts["approved_organizations"] or 0),
            "rejected_organizations": int(counts["rejected_organizations"] or 0),
            "pending_platform_users": int(platform_counts["pending_platform_users"] or 0),
            "approved_platform_users": int(platform_counts["approved_platform_users"] or 0),
        },
        "organizations": rows_to_dicts(organizations),
    }


@router.post("/owner/review-organization")
def review_organization(
    payload: OwnerOrganizationReviewRequest,
    owner: dict = Depends(require_role("owner")),
) -> dict:
    with get_connection("strategy") as conn:
        organization = conn.execute(
            "SELECT id, name, approval_status FROM organizations WHERE id = ?",
            (payload.organization_id,),
        ).fetchone()
        if not organization:
            raise HTTPException(status_code=404, detail="Organization not found")

        approval_status = "approved" if payload.approve else "rejected"
        lifecycle_status = "active" if payload.approve else "rejected"
        conn.execute(
            """
            UPDATE organizations
            SET is_active = ?,
                status = ?,
                approval_status = ?,
                status_note = ?,
                approved_by_user_id = ?,
                approved_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                1 if payload.approve else 0,
                lifecycle_status,
                approval_status,
                payload.note.strip(),
                owner["id"],
                payload.organization_id,
            ),
        )
        conn.execute(
            """
            UPDATE users
            SET is_approved = ?, updated_at = CURRENT_TIMESTAMP
            WHERE organization_id = ?
            """,
            (1 if payload.approve else 0, payload.organization_id),
        )
        conn.execute(
            """
            UPDATE organization_memberships
            SET status = ?,
                approved_by_user_id = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE organization_id = ?
            """,
            (
                "active" if payload.approve else "rejected",
                owner["id"],
                payload.organization_id,
            ),
        )
        conn.execute(
            """
            INSERT INTO organization_status_approvals
            (organization_id, status, reviewed_by_user_id, reviewed_at, note, created_at, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (
                payload.organization_id,
                approval_status,
                owner["id"],
                payload.note.strip(),
            ),
        )
        if payload.approve:
            org_users = conn.execute(
                "SELECT id, role FROM users WHERE organization_id = ?",
                (payload.organization_id,),
            ).fetchall()
            for row in org_users:
                ensure_user_default_permissions(
                    conn,
                    user_id=int(row["id"]),
                    role=str(row["role"]),
                    granted_by_user_id=int(owner["id"]),
                )
        conn.execute(
            """
            UPDATE signup_requests
            SET status = ?, review_note = ?, updated_at = CURRENT_TIMESTAMP
            WHERE organization_id = ?
              AND status IN ('pending_owner_approval', 'otp_verified')
            """,
            (
                approval_status,
                payload.note.strip(),
                payload.organization_id,
            ),
        )
        log_audit_event(
            actor_user_id=owner["id"],
            action="organization_reviewed",
            entity_type="organization",
            entity_id=str(payload.organization_id),
            details={"approved": payload.approve, "note": payload.note.strip()},
            conn=conn,
        )
    return {"status": approval_status, "organization_id": payload.organization_id}


@router.post("/owner/review-platform-user")
def review_platform_user(
    payload: OwnerPlatformUserReviewRequest,
    owner: dict = Depends(require_role("owner")),
) -> dict:
    with get_connection("strategy") as conn:
        user = conn.execute(
            "SELECT id, email, organization_id, role FROM users WHERE id = ?",
            (payload.user_id,),
        ).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if user["organization_id"] is not None:
            raise HTTPException(status_code=400, detail="User belongs to an organization")
        conn.execute(
            "UPDATE users SET is_approved = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (1 if payload.approve else 0, payload.user_id),
        )
        conn.execute(
            """
            INSERT INTO normal_user_approvals
            (user_id, status, reviewed_by_user_id, reviewed_at, note, created_at, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                status = excluded.status,
                reviewed_by_user_id = excluded.reviewed_by_user_id,
                reviewed_at = CURRENT_TIMESTAMP,
                note = excluded.note,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                payload.user_id,
                "approved" if payload.approve else "rejected",
                owner["id"],
                payload.note.strip(),
            ),
        )
        conn.execute(
            """
            UPDATE signup_requests
            SET status = ?, review_note = ?, updated_at = CURRENT_TIMESTAMP
            WHERE lower(email) = ?
              AND signup_type = 'normal_user'
              AND status IN ('pending_owner_approval', 'otp_verified')
            """,
            (
                "approved" if payload.approve else "rejected",
                payload.note.strip(),
                str(user["email"]).lower(),
            ),
        )
        if payload.approve:
            ensure_user_default_permissions(
                conn,
                user_id=int(user["id"]),
                role=str(user["role"]),
                granted_by_user_id=int(owner["id"]),
            )
        log_audit_event(
            actor_user_id=owner["id"],
            action="platform_user_reviewed",
            entity_type="user",
            entity_id=str(payload.user_id),
            details={"approved": payload.approve, "note": payload.note.strip()},
            conn=conn,
        )
    return {"status": "approved" if payload.approve else "rejected", "user_id": payload.user_id}


@router.get("/organizations/invitations")
def list_organization_invitations(
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> list[dict]:
    with get_connection("strategy") as conn:
        scope_organization_id = _actor_data_scope_organization_id(admin)
        if _is_elevated(admin) and scope_organization_id is None:
            return []
        if _is_elevated(admin):
            rows = conn.execute(
                """
                SELECT i.id, i.organization_id, o.name AS organization_name, i.email, i.full_name, i.role,
                       i.expires_at, i.status, i.created_at
                FROM organization_invitations i
                JOIN organizations o ON o.id = i.organization_id
                WHERE i.organization_id = ?
                ORDER BY i.created_at DESC
                """,
                (scope_organization_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT i.id, i.organization_id, o.name AS organization_name, i.email, i.full_name, i.role,
                       i.expires_at, i.status, i.created_at
                FROM organization_invitations i
                JOIN organizations o ON o.id = i.organization_id
                WHERE i.organization_id = ?
                ORDER BY i.created_at DESC
                """,
                (_actor_organization_id(admin),),
            ).fetchall()
    return rows_to_dicts(rows)


@router.get("/organizations/member-signup-requests")
def list_organization_member_signup_requests(
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> list[dict]:
    with get_connection("strategy") as conn:
        scope_organization_id = _actor_data_scope_organization_id(admin)
        if _is_elevated(admin) and scope_organization_id is None:
            return []
        if _is_elevated(admin):
            rows = conn.execute(
                """
                SELECT r.id, r.organization_id, o.name AS organization_name, o.slug AS organization_slug,
                       r.full_name, r.email, r.requested_role, r.status, r.review_note, r.created_at, r.updated_at
                FROM organization_member_signup_requests r
                JOIN organizations o ON o.id = r.organization_id
                WHERE r.organization_id = ?
                  AND r.status = 'pending_org_admin_review'
                ORDER BY r.created_at DESC, r.id DESC
                """,
                (scope_organization_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT r.id, r.organization_id, o.name AS organization_name, o.slug AS organization_slug,
                       r.full_name, r.email, r.requested_role, r.status, r.review_note, r.created_at, r.updated_at
                FROM organization_member_signup_requests r
                JOIN organizations o ON o.id = r.organization_id
                WHERE r.organization_id = ?
                  AND r.status = 'pending_org_admin_review'
                ORDER BY r.created_at DESC, r.id DESC
                """,
                (_actor_organization_id(admin),),
            ).fetchall()
    return rows_to_dicts(rows)


@router.post("/organizations/member-signup-requests/{request_id}/review")
def review_organization_member_signup_request(
    request_id: int,
    payload: ReviewOrganizationMemberSignupRequest,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> dict:
    with get_connection("strategy") as conn:
        request = _get_target_member_signup_request(conn, admin, request_id)
        if request["status"] != "pending_org_admin_review":
            raise HTTPException(status_code=400, detail="Signup request is not pending review")

        final_status = "approved" if payload.approve else "rejected"
        approved_user_id = None

        if payload.approve:
            if request["approval_status"] != "approved" or request["organization_status"] != "active":
                raise HTTPException(status_code=400, detail="Organization is not active for member onboarding")
            existing_user = conn.execute(
                "SELECT id FROM users WHERE lower(email) = ?",
                (str(request["email"]).lower(),),
            ).fetchone()
            if existing_user:
                raise HTTPException(status_code=409, detail="Email already registered")

            cursor = conn.execute(
                """
                INSERT INTO users
                (organization_id, full_name, email, password_hash, role, is_active, is_approved, created_by_user_id, signup_type, updated_at)
                VALUES (?, ?, ?, ?, 'org_user', 1, 1, ?, 'organization_user', CURRENT_TIMESTAMP)
                """,
                (
                    request["organization_id"],
                    request["full_name"],
                    str(request["email"]).lower(),
                    request["password_hash"],
                    admin["id"],
                ),
            )
            approved_user_id = int(cursor.lastrowid)
            _upsert_membership(
                conn,
                organization_id=int(request["organization_id"]),
                user_id=approved_user_id,
                membership_role="org_user",
                status="active",
                approved_by_user_id=int(admin["id"]),
            )
            ensure_user_default_permissions(
                conn,
                user_id=approved_user_id,
                role="org_user",
                granted_by_user_id=int(admin["id"]),
            )
            conn.execute(
                """
                UPDATE organization_invitations
                SET status = 'revoked', updated_at = CURRENT_TIMESTAMP
                WHERE organization_id = ?
                  AND lower(email) = ?
                  AND status = 'pending'
                """,
                (request["organization_id"], str(request["email"]).lower()),
            )

        conn.execute(
            """
            UPDATE organization_member_signup_requests
            SET status = ?,
                review_note = ?,
                reviewed_by_user_id = ?,
                reviewed_at = CURRENT_TIMESTAMP,
                approved_user_id = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                final_status,
                payload.note.strip(),
                admin["id"],
                approved_user_id,
                request_id,
            ),
        )
        log_audit_event(
            actor_user_id=admin["id"],
            action="organization_member_signup_reviewed",
            entity_type="organization_member_signup_request",
            entity_id=str(request_id),
            details={
                "organization_id": request["organization_id"],
                "email": request["email"],
                "approved": payload.approve,
                "approved_user_id": approved_user_id,
                "note": payload.note.strip(),
            },
            conn=conn,
        )
    return {
        "status": final_status,
        "request_id": request_id,
        "approved_user_id": approved_user_id,
    }


@router.post("/organizations/invitations")
def create_organization_invitation(
    payload: CreateOrganizationInvitationRequest,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> dict:
    role = payload.role.strip().lower()
    if role == "org_admin":
        role = "buyer_admin"
    if role not in {"org_user", "buyer_admin"}:
        raise HTTPException(status_code=400, detail="Invalid invitation role")

    organization_id = payload.organization_id if _is_elevated(admin) else _actor_organization_id(admin)
    if _is_elevated(admin):
        scope_organization_id = _actor_data_scope_organization_id(admin)
        if scope_organization_id is None:
            raise HTTPException(status_code=400, detail="Select an organization before sending invitations")
        if organization_id != scope_organization_id:
            raise HTTPException(status_code=403, detail="Invitation organization does not match the selected scope")
    if organization_id is None:
        raise HTTPException(status_code=400, detail="Organization is required")

    with get_connection("strategy") as conn:
        conn.execute(
            "UPDATE organization_invitations SET status = 'revoked', updated_at = CURRENT_TIMESTAMP WHERE lower(email) = ? AND organization_id = ? AND status = 'pending'",
            (payload.email.strip().lower(), organization_id),
        )
        inviter_membership = None
        if _actor_organization_id(admin):
            inviter_membership = conn.execute(
                """
                SELECT id
                FROM organization_memberships
                WHERE organization_id = ? AND user_id = ?
                LIMIT 1
                """,
                (organization_id, admin["id"]),
            ).fetchone()
        created = _create_invitation_record(
            conn,
            organization_id=int(organization_id),
            inviter_user_id=int(admin["id"]),
            email=payload.email,
            full_name=payload.full_name,
            role=role,
            expires_in_days=int(payload.expires_in_days),
        )
        log_audit_event(
            actor_user_id=admin["id"],
            action="organization_invitation_created",
            entity_type="invitation",
            entity_id=str(created["invitation_id"]),
            details={"organization_id": organization_id, "email": payload.email.strip().lower(), "role": role},
            conn=conn,
        )
    return {"status": "invited", **created}


@router.post("/organizations/invitations/{invitation_id}/resend")
def resend_organization_invitation(
    invitation_id: int,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> dict:
    with get_connection("strategy") as conn:
        invitation = _get_target_invitation(conn, admin, invitation_id)
        if invitation["status"] == "accepted":
            raise HTTPException(status_code=400, detail="Accepted invitations cannot be resent")
        if invitation["status"] == "revoked":
            raise HTTPException(status_code=400, detail="Revoked invitations cannot be resent")

        conn.execute(
            "UPDATE organization_invitations SET status = 'revoked', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (invitation_id,),
        )
        created = _create_invitation_record(
            conn,
            organization_id=int(invitation["organization_id"]),
            inviter_user_id=int(admin["id"]),
            email=str(invitation["email"]),
            full_name=str(invitation["full_name"] or ""),
            role=str(invitation["role"]),
            expires_in_days=_derive_invitation_expiry_days(invitation),
        )
        log_audit_event(
            actor_user_id=admin["id"],
            action="organization_invitation_resent",
            entity_type="invitation",
            entity_id=str(created["invitation_id"]),
            details={"previous_invitation_id": invitation_id, "organization_id": invitation["organization_id"], "email": invitation["email"]},
            conn=conn,
        )
    return {"status": "resent", **created}


@router.post("/organizations/invitations/{invitation_id}/revoke")
def revoke_organization_invitation(
    invitation_id: int,
    admin: dict = Depends(require_role("owner", "buyer_admin")),
) -> dict:
    with get_connection("strategy") as conn:
        invitation = _get_target_invitation(conn, admin, invitation_id)
        if invitation["status"] == "accepted":
            raise HTTPException(status_code=400, detail="Accepted invitations cannot be revoked")
        if invitation["status"] == "revoked":
            return {"status": "revoked", "invitation_id": invitation_id}

        conn.execute(
            "UPDATE organization_invitations SET status = 'revoked', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (invitation_id,),
        )
        log_audit_event(
            actor_user_id=admin["id"],
            action="organization_invitation_revoked",
            entity_type="invitation",
            entity_id=str(invitation_id),
            details={"organization_id": invitation["organization_id"], "email": invitation["email"]},
            conn=conn,
        )
    return {"status": "revoked", "invitation_id": invitation_id}


@router.get("/profile/me")
def get_profile(user: dict = Depends(get_current_user)) -> dict:
    with get_connection("strategy") as conn:
        row = conn.execute(
            """
            SELECT font_size, color_theme, dark_mode, updated_at
            FROM user_profiles
            WHERE user_id = ?
            """,
            (user["id"],),
        ).fetchone()
        if not row:
            conn.execute(
                """
                INSERT INTO user_profiles (user_id, font_size, color_theme, dark_mode, updated_at)
                VALUES (?, 'medium', 'emerald', 0, CURRENT_TIMESTAMP)
                """,
                (user["id"],),
            )
            row = conn.execute(
                """
                SELECT font_size, color_theme, dark_mode, updated_at
                FROM user_profiles
                WHERE user_id = ?
                """,
                (user["id"],),
            ).fetchone()
        organization_row = None
        organization_id = get_effective_organization_id(user)
        if organization_id is not None:
            organization_row = conn.execute(
                "SELECT id, name, slug FROM organizations WHERE id = ?",
                (organization_id,),
            ).fetchone()
    profile_data = dict(row) if row else {"font_size": "medium", "color_theme": "emerald", "dark_mode": 0, "updated_at": None}
    return {
        **profile_data,
        "account": {
            "id": int(user["id"]),
            "full_name": str(user.get("full_name") or ""),
            "email": str(user.get("email") or ""),
            "role": str(user.get("role") or ""),
            "effective_role": get_effective_role(user),
            "organization_id": organization_id,
            "organization_name": str(organization_row["name"]) if organization_row else "",
            "organization_slug": str(organization_row["slug"] or "") if organization_row else "",
            "membership_status": str(user.get("membership_status") or ""),
        },
    }


@router.put("/profile/me")
def update_profile(
    payload: UserProfileSettingsRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    with get_connection("strategy") as conn:
        conn.execute(
            """
            INSERT INTO user_profiles (user_id, font_size, color_theme, dark_mode, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                font_size = excluded.font_size,
                color_theme = excluded.color_theme,
                dark_mode = excluded.dark_mode,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                user["id"],
                payload.font_size.strip().lower(),
                payload.color_theme.strip().lower(),
                1 if payload.dark_mode else 0,
            ),
        )
    return {"status": "ok"}


@router.put("/profile/me/details")
def update_profile_details(
    payload: UpdateProfileDetailsRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    full_name = " ".join(payload.full_name.strip().split())
    if len(full_name) < 2:
        raise HTTPException(status_code=400, detail="Full name is too short")

    with get_connection("strategy") as conn:
        conn.execute(
            "UPDATE users SET full_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (full_name, user["id"]),
        )
        log_audit_event(
            actor_user_id=int(user["id"]),
            action="profile_details_updated",
            entity_type="user",
            entity_id=str(user["id"]),
            details={"full_name": full_name},
            conn=conn,
        )
    return {"status": "ok", "full_name": full_name}


@router.post("/profile/me/change-password")
def change_my_password(
    payload: ChangePasswordRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    if payload.current_password == payload.new_password:
        raise HTTPException(status_code=400, detail="New password must be different from the current password")

    with get_connection("strategy") as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE id = ?",
            (user["id"],),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        if not verify_password(payload.current_password, str(row["password_hash"] or "")):
            raise HTTPException(status_code=400, detail="Current password is incorrect")

        conn.execute(
            "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (hash_password(payload.new_password), user["id"]),
        )
        log_audit_event(
            actor_user_id=int(user["id"]),
            action="profile_password_changed",
            entity_type="user",
            entity_id=str(user["id"]),
            details={},
            conn=conn,
        )
    return {"status": "ok"}


@router.delete("/profile/me")
def delete_my_account(user: dict = Depends(get_current_user)) -> dict:
    with get_connection("strategy") as conn:
        target = conn.execute(
            """
            SELECT id, organization_id, full_name, email, role, is_active, is_approved, created_at
            FROM users
            WHERE id = ?
            """,
            (user["id"],),
        ).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="User not found")
        result = _delete_user_account(conn, actor=user, target=dict(target))
    return {"status": "ok", **result}


@router.get("/organizations")
def list_organizations(_: dict = Depends(require_role("owner", "buyer_admin"))) -> list[dict]:
    with get_connection("strategy") as conn:
        rows = conn.execute(
            "SELECT id, name, purchaser_email, is_active, created_at FROM organizations ORDER BY created_at DESC"
        ).fetchall()
    return rows_to_dicts(rows)


@router.delete("/organizations/{organization_id}")
def delete_organization(
    organization_id: int,
    admin: dict = Depends(require_role("owner", "super_admin")),
) -> dict:
    with get_connection("strategy") as conn:
        organization = conn.execute(
            "SELECT id, name, slug FROM organizations WHERE id = ? LIMIT 1",
            (organization_id,),
        ).fetchone()
        if not organization:
            raise HTTPException(status_code=404, detail="Organization not found")
        organization_name = str(organization["name"] or "").strip()

    external_counts = _delete_organization_external_records(organization_name=organization_name)

    with get_connection("strategy") as conn:
        result = _delete_organization_strategy_records(
            conn,
            organization_id=organization_id,
            organization_name=organization_name,
            actor=admin,
        )

    return {
        "status": "ok",
        **result,
        **external_counts,
    }


@router.post("/organization-boundary")
def upsert_org_boundary(
    payload: OrganizationBoundaryRequest,
    user: dict = Depends(require_role("owner", "buyer_admin")),
) -> dict:
    if _is_elevated(user):
        scope_organization_id = _actor_data_scope_organization_id(user)
        if scope_organization_id is None:
            raise HTTPException(status_code=403, detail="Select an organization before updating organization boundaries")
        if payload.organization_id != scope_organization_id:
            raise HTTPException(status_code=403, detail="Organization boundary scope mismatch")
    if has_role(user, "buyer_admin") and not _is_elevated(user) and payload.organization_id != _actor_organization_id(user):
        raise HTTPException(status_code=403, detail="Cannot update another organization boundary")
    with get_connection("strategy") as conn:
        org = conn.execute("SELECT id FROM organizations WHERE id = ?", (payload.organization_id,)).fetchone()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        existing = conn.execute(
            "SELECT id FROM organization_boundaries WHERE organization_id = ?",
            (payload.organization_id,),
        ).fetchone()
        if existing:
            conn.execute(
                """
                UPDATE organization_boundaries
                SET organization_name = ?, subsidiary_name = ?, associate_name = ?,
                    manufacturing_unit = ?, updated_at = CURRENT_TIMESTAMP
                WHERE organization_id = ?
                """,
                (
                    payload.organization_name.strip(),
                    payload.subsidiary_name.strip(),
                    payload.associate_name.strip(),
                    payload.manufacturing_unit.strip(),
                    payload.organization_id,
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO organization_boundaries
                (organization_id, organization_name, subsidiary_name, associate_name, manufacturing_unit, updated_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (
                    payload.organization_id,
                    payload.organization_name.strip(),
                    payload.subsidiary_name.strip(),
                    payload.associate_name.strip(),
                    payload.manufacturing_unit.strip(),
                ),
            )
        log_audit_event(
            actor_user_id=user["id"],
            action="organization_boundary_updated",
            entity_type="organization",
            entity_id=str(payload.organization_id),
            details={"organization_name": payload.organization_name.strip()},
            conn=conn,
        )
    return {"status": "ok"}


@router.get("/organization-boundary/{organization_id}")
def get_org_boundary(
    organization_id: int,
    user: dict = Depends(require_role("owner", "buyer_admin", "org_user")),
) -> dict:
    if _is_elevated(user):
        scope_organization_id = _actor_data_scope_organization_id(user)
        if scope_organization_id is None:
            raise HTTPException(status_code=403, detail="Select an organization before viewing organization boundaries")
        if organization_id != scope_organization_id:
            raise HTTPException(status_code=403, detail="Cannot access another organization boundary")
    elif organization_id != _actor_organization_id(user):
        raise HTTPException(status_code=403, detail="Cannot access another organization boundary")
    with get_connection("strategy") as conn:
        row = conn.execute(
            """
            SELECT organization_id, organization_name, subsidiary_name, associate_name, manufacturing_unit, updated_at
            FROM organization_boundaries WHERE organization_id = ?
            """,
            (organization_id,),
        ).fetchone()
        if row:
            return dict(row)
        org = conn.execute("SELECT name FROM organizations WHERE id = ?", (organization_id,)).fetchone()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        return {
            "organization_id": organization_id,
            "organization_name": org["name"],
            "subsidiary_name": "",
            "associate_name": "",
            "manufacturing_unit": "",
            "updated_at": None,
        }


@router.post("/project-status/{project_code}")
def update_project_status(
    project_code: str,
    status: str,
    comment: str = "",
    user: dict = Depends(get_current_user),
) -> dict:
    with get_connection("strategy") as conn_acl:
        assert_project_permission(
            conn_acl,
            user=user,
            module_key="co2",
            external_project_id=project_code,
            action="approve",
            require_exists=False,
        )
    with get_connection("co2") as conn:
        proj = conn.execute("SELECT project_code FROM projects WHERE project_code = ?", (project_code,)).fetchone()
        if not proj:
            raise HTTPException(status_code=404, detail="Project not found")
        conn.execute(
            "UPDATE projects SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE project_code = ?",
            (status.strip(), project_code),
        )

    with get_connection("strategy") as conn:
        conn.execute(
            """
            INSERT INTO project_status_updates
            (project_code, status, comment, updated_by_email, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (project_code, status.strip(), comment.strip(), user["email"]),
        )
        log_audit_event(
            actor_user_id=user["id"],
            action="project_status_updated",
            entity_type="project",
            entity_id=project_code,
            details={"status": status.strip(), "comment": comment.strip()},
            conn=conn,
        )
    return {"status": "ok", "project_code": project_code}


@router.get("/project-status/{project_code}")
def list_project_status(
    project_code: str,
    user: dict = Depends(get_current_user),
) -> list[dict]:
    with get_connection("strategy") as conn_acl:
        assert_project_permission(
            conn_acl,
            user=user,
            module_key="co2",
            external_project_id=project_code,
            action="view",
            require_exists=False,
        )
    with get_connection("strategy") as conn:
        rows = conn.execute(
            """
            SELECT project_code, status, comment, updated_by_email, updated_at
            FROM project_status_updates
            WHERE project_code = ?
            ORDER BY updated_at DESC
            """,
            (project_code,),
        ).fetchall()
    return rows_to_dicts(rows)


@router.post("/reminders/send-pending")
def send_pending_reminders(user: dict = Depends(require_role("owner", "buyer_admin"))) -> dict:
    sent = 0
    now = datetime.now().date().isoformat()
    with get_connection("strategy") as conn:
        scope_organization_id = _actor_data_scope_organization_id(user)
        if _is_elevated(user) and scope_organization_id is None:
            return {"status": "ok", "sent": 0}
        if _is_elevated(user):
            jobs = conn.execute(
                """
                SELECT r.id, r.user_id, r.project_code, r.reminder_type, u.email, u.full_name
                FROM reminder_jobs r
                JOIN users u ON u.id = r.user_id
                WHERE r.status = 'pending' AND r.due_date <= ?
                  AND u.organization_id = ?
                ORDER BY r.id ASC
                LIMIT 100
                """,
                (now, scope_organization_id),
            ).fetchall()
        else:
            organization_id = _actor_organization_id(user)
            jobs = conn.execute(
                """
                SELECT r.id, r.user_id, r.project_code, r.reminder_type, u.email, u.full_name
                FROM reminder_jobs r
                JOIN users u ON u.id = r.user_id
                WHERE r.status = 'pending'
                  AND r.due_date <= ?
                  AND u.organization_id = ?
                ORDER BY r.id ASC
                LIMIT 100
                """,
                (now, organization_id),
            ).fetchall()
        for job in jobs:
            email_content = build_project_update_reminder_email(
                full_name=str(job["full_name"] or ""),
                project_code=str(job["project_code"] or ""),
                reminder_type=str(job["reminder_type"] or ""),
                dashboard_url=APP_BASE_URL,
            )
            if send_mail(job["email"], email_content.subject, email_content.text_body, email_content.html_body):
                conn.execute(
                    "UPDATE reminder_jobs SET status = 'sent', sent_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (job["id"],),
                )
                sent += 1
    return {"status": "ok", "sent": sent}


@router.get("/saved-projects-overview")
def saved_projects_overview(user: dict = Depends(require_role("owner", "buyer_admin", "org_user"))) -> dict:
    org_filter = get_data_scope_organization_id(user)
    org_name_filter = str(user.get("selected_organization_name") or user.get("effective_organization_name") or "").strip() or None
    if _is_elevated(user) and org_filter is None:
        return {
            "co2_projects": [],
            "fuel_calculations": [],
            "macc_projects": [],
            "strategy_portfolios": [],
        }

    scoped_registry_ids: dict[str, list[str]] = {"co2": [], "fuel": [], "macc": [], "strategy": []}
    if org_filter is not None:
        with get_connection("strategy") as strategy_conn:
            registry_rows = strategy_conn.execute(
                """
                SELECT m.module_key, p.external_project_id
                FROM projects p
                JOIN modules m ON m.id = p.module_id
                WHERE p.organization_id = ?
                ORDER BY p.updated_at DESC, p.id DESC
                """,
                (org_filter,),
            ).fetchall()
        for row in registry_rows:
            module_key = str(row["module_key"])
            if module_key in scoped_registry_ids:
                scoped_registry_ids[module_key].append(str(row["external_project_id"]))

    with get_connection("co2") as conn:
        scoped_co2_ids = scoped_registry_ids["co2"] if org_filter is not None else None
        if scoped_co2_ids is not None:
            if not scoped_co2_ids:
                co2_projects = []
            else:
                placeholders = ",".join("?" for _ in scoped_co2_ids)
                co2_projects = conn.execute(
                    f"""
                    SELECT project_code, organization, project_name, target_year, status, updated_at
                    FROM projects
                    WHERE project_code IN ({placeholders})
                    ORDER BY updated_at DESC
                    """,
                    tuple(scoped_co2_ids),
                ).fetchall()
        elif org_name_filter is None:
            co2_projects = conn.execute(
                "SELECT project_code, organization, project_name, target_year, status, updated_at FROM projects ORDER BY updated_at DESC"
            ).fetchall()
        else:
            co2_projects = conn.execute(
                """
                SELECT project_code, organization, project_name, target_year, status, updated_at
                FROM projects
                WHERE lower(trim(organization)) = lower(trim(?))
                ORDER BY updated_at DESC
                """,
                (org_name_filter,),
            ).fetchall()

    with get_connection("fuel") as conn:
        scoped_fuel_ids = scoped_registry_ids["fuel"] if org_filter is not None else None
        if scoped_fuel_ids is not None:
            if not scoped_fuel_ids:
                fuel_calcs = []
            else:
                placeholders = ",".join("?" for _ in scoped_fuel_ids)
                fuel_calcs = conn.execute(
                    f"""
                    SELECT unique_code, org_name, sector, target_year, updated_at
                    FROM calculations
                    WHERE unique_code IN ({placeholders})
                    ORDER BY updated_at DESC
                    """,
                    tuple(scoped_fuel_ids),
                ).fetchall()
        elif org_name_filter is None:
            fuel_calcs = conn.execute(
                "SELECT unique_code, org_name, sector, target_year, updated_at FROM calculations ORDER BY updated_at DESC"
            ).fetchall()
        else:
            fuel_calcs = conn.execute(
                """
                SELECT unique_code, org_name, sector, target_year, updated_at
                FROM calculations
                WHERE lower(trim(org_name)) = lower(trim(?))
                ORDER BY updated_at DESC
                """,
                (org_name_filter,),
            ).fetchall()

    with get_connection("npv") as conn:
        scoped_macc_project_ids = scoped_registry_ids["macc"] if org_filter is not None else None
        if scoped_macc_project_ids is not None:
            if not scoped_macc_project_ids:
                macc_projects = []
            else:
                placeholders = ",".join("?" for _ in scoped_macc_project_ids)
                macc_projects = conn.execute(
                    f"""
                    SELECT id, organization, project_name, target_year, mac, total_co2_diff, created_at
                    FROM npv_projects
                    WHERE id IN ({placeholders})
                    ORDER BY created_at DESC
                    """,
                    tuple(scoped_macc_project_ids),
                ).fetchall()
        elif org_name_filter is None:
            macc_projects = conn.execute(
                """
                SELECT id, organization, project_name, target_year, mac, total_co2_diff, created_at
                FROM npv_projects
                ORDER BY created_at DESC
                """
            ).fetchall()
        else:
            macc_projects = conn.execute(
                """
                SELECT id, organization, project_name, target_year, mac, total_co2_diff, created_at
                FROM npv_projects
                WHERE lower(trim(organization)) = lower(trim(?))
                ORDER BY created_at DESC
                """,
                (org_name_filter,),
            ).fetchall()

    with get_connection("strategy") as conn:
        scoped_strategy_ids = scoped_registry_ids["strategy"] if org_filter is not None else None
        if scoped_strategy_ids is not None:
            if not scoped_strategy_ids:
                strategy_rows = []
            else:
                placeholders = ",".join("?" for _ in scoped_strategy_ids)
                strategy_rows = conn.execute(
                    f"""
                    SELECT id, name, organization, sector, baseline_calc_id, selected_macc_projects, updated_at
                    FROM strategy_portfolios
                    WHERE id IN ({placeholders})
                    ORDER BY updated_at DESC
                    """,
                    tuple(scoped_strategy_ids),
                ).fetchall()
        elif org_name_filter is None:
            strategy_rows = conn.execute(
                """
                SELECT id, name, organization, sector, baseline_calc_id, selected_macc_projects, updated_at
                FROM strategy_portfolios
                ORDER BY updated_at DESC
                """
            ).fetchall()
        else:
            strategy_rows = conn.execute(
                """
                SELECT id, name, organization, sector, baseline_calc_id, selected_macc_projects, updated_at
                FROM strategy_portfolios
                WHERE lower(trim(organization)) = lower(trim(?))
                ORDER BY updated_at DESC
                """,
                (org_name_filter,),
            ).fetchall()

    return {
        "fuel_calculations": rows_to_dicts(fuel_calcs),
        "co2_projects": rows_to_dicts(co2_projects),
        "macc_projects": rows_to_dicts(macc_projects),
        "strategy_portfolios": rows_to_dicts(strategy_rows),
    }
