from fastapi import Depends, Header, HTTPException, Request

from ..database import get_connection
from .security import decode_access_token
from .tenant import TenantContext, assert_user_matches_tenant, get_tenant_context


def _normalize_role(value: str | None) -> str:
    return str(value or "").strip().lower()


def get_effective_role(user: dict) -> str:
    legacy_role = _normalize_role(user.get("role"))
    if legacy_role in {"owner", "super_admin"}:
        return legacy_role
    membership_role = _normalize_role(user.get("membership_role"))
    membership_status = _normalize_role(user.get("membership_status"))
    if membership_role and membership_status in {"", "active"}:
        if membership_role == "org_admin":
            return "org_admin"
        if membership_role == "org_user":
            return "org_user"
    if legacy_role == "buyer_admin":
        return "org_admin"
    return legacy_role


def get_effective_organization_id(user: dict) -> int | None:
    organization_id = user.get("effective_organization_id")
    if organization_id is not None:
        return int(organization_id)
    organization_id = user.get("organization_id")
    if organization_id is not None:
        return int(organization_id)
    membership_organization_id = user.get("membership_organization_id")
    if membership_organization_id is not None:
        return int(membership_organization_id)
    return None


def get_selected_organization_id(user: dict) -> int | None:
    organization_id = user.get("selected_organization_id")
    if organization_id is not None:
        return int(organization_id)
    tenant = user.get("tenant_context") or {}
    if get_effective_role(user) in {"owner", "super_admin"} and tenant.get("scope") == "organization":
        tenant_organization_id = tenant.get("organization_id")
        if tenant_organization_id is not None:
            return int(tenant_organization_id)
    return None


def get_data_scope_organization_id(user: dict) -> int | None:
    if get_effective_role(user) in {"owner", "super_admin"}:
        return get_selected_organization_id(user)
    return get_effective_organization_id(user)


def has_role(user: dict, *roles: str) -> bool:
    requested = {_normalize_role(role) for role in roles}
    effective_role = get_effective_role(user)
    if effective_role in {"owner", "super_admin"}:
        return True
    aliases = {effective_role, _normalize_role(user.get("role"))}
    if "org_admin" in aliases:
        aliases.add("buyer_admin")
    if "buyer_admin" in aliases:
        aliases.add("org_admin")
    return bool(aliases & requested)


def get_current_user(
    request: Request,
    authorization: str | None = Header(default=None),
    x_selected_organization_id: str | None = Header(default=None),
) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = decode_access_token(token)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc

    email = str(payload.get("sub", "")).lower()
    tenant = get_tenant_context(request)
    with get_connection("strategy") as conn:
        user = conn.execute(
            """
            SELECT id, organization_id, full_name, email, role, is_active, is_approved
            FROM users
            WHERE lower(email) = ?
            """,
            (email,),
        ).fetchone()
        membership = None
        if user and tenant.scope == "organization" and tenant.organization_id:
            membership = conn.execute(
                """
                SELECT organization_id, membership_role, status
                FROM organization_memberships
                WHERE user_id = ? AND organization_id = ?
                LIMIT 1
                """,
                (user["id"], tenant.organization_id),
            ).fetchone()
        elif user and user["organization_id"]:
            membership = conn.execute(
                """
                SELECT organization_id, membership_role, status
                FROM organization_memberships
                WHERE user_id = ? AND organization_id = ?
                LIMIT 1
                """,
                (user["id"], user["organization_id"]),
            ).fetchone()
        elif user:
            membership = conn.execute(
                """
                SELECT organization_id, membership_role, status
                FROM organization_memberships
                WHERE user_id = ?
                ORDER BY CASE WHEN lower(status) = 'active' THEN 0 WHEN lower(status) = 'pending' THEN 1 ELSE 2 END,
                         id ASC
                LIMIT 1
                """,
                (user["id"],),
            ).fetchone()
        effective_org_row = None
        selected_org_row = None
        selected_organization_id = None
        requested_selected_org_id = str(x_selected_organization_id or "").strip()
        if tenant.scope == "organization" and tenant.organization_id:
            selected_organization_id = int(tenant.organization_id)
        elif user:
            role_probe = get_effective_role({
                **dict(user),
                **({
                    "membership_organization_id": membership["organization_id"],
                    "membership_role": membership["membership_role"],
                    "membership_status": membership["status"],
                } if membership else {}),
            })
            if role_probe in {"owner", "super_admin"} and requested_selected_org_id:
                try:
                    parsed_selected_org_id = int(requested_selected_org_id)
                except ValueError:
                    parsed_selected_org_id = None
                if parsed_selected_org_id is not None and parsed_selected_org_id > 0:
                    selected_organization_id = parsed_selected_org_id
        if user:
            effective_organization_id = user["organization_id"]
            if tenant.scope == "organization" and tenant.organization_id and membership:
                effective_organization_id = tenant.organization_id
            elif effective_organization_id is None and membership:
                effective_organization_id = membership["organization_id"]
            if effective_organization_id is not None:
                effective_org_row = conn.execute(
                    "SELECT id, name, slug FROM organizations WHERE id = ? LIMIT 1",
                    (effective_organization_id,),
                ).fetchone()
            if selected_organization_id is not None:
                selected_org_row = conn.execute(
                    "SELECT id, name, slug FROM organizations WHERE id = ? LIMIT 1",
                    (selected_organization_id,),
                ).fetchone()
                if not selected_org_row:
                    raise HTTPException(status_code=404, detail="Selected organization not found")
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if not user["is_active"] or not user["is_approved"]:
        raise HTTPException(status_code=403, detail="User is not active/approved")
    user_dict = dict(user)
    if membership:
        user_dict["membership_organization_id"] = membership["organization_id"]
        user_dict["membership_role"] = membership["membership_role"]
        user_dict["membership_status"] = membership["status"]
    effective_organization_id = user_dict.get("organization_id")
    if tenant.scope == "organization" and tenant.organization_id and membership:
        effective_organization_id = tenant.organization_id
    elif effective_organization_id is None and membership:
        effective_organization_id = membership["organization_id"]
    user_dict["effective_organization_id"] = effective_organization_id
    user_dict["effective_role"] = get_effective_role(user_dict)
    user_dict["effective_organization_name"] = str(effective_org_row["name"] or "").strip() if effective_org_row else ""
    user_dict["effective_organization_slug"] = str(effective_org_row["slug"] or "").strip().lower() if effective_org_row else ""
    assert_user_matches_tenant(user=user_dict, tenant=tenant)
    user_dict["tenant_context"] = tenant.as_dict()
    if selected_org_row:
        user_dict["selected_organization_id"] = int(selected_org_row["id"])
        user_dict["selected_organization_name"] = str(selected_org_row["name"] or "").strip()
        user_dict["selected_organization_slug"] = str(selected_org_row["slug"] or "").strip().lower()
    return user_dict


def require_role(*roles: str):
    def dependency(user: dict = Depends(get_current_user)) -> dict:
        if not has_role(user, *roles):
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user

    return dependency


def require_permission(page_key: str, button_key: str):
    def dependency(user: dict = Depends(get_current_user)) -> dict:
        from .acl import assert_module_permission

        button = button_key.strip().lower()
        action = "view"
        if button in {"save", "create", "yearly_save", "tracking_save"}:
            action = "edit"
        elif button == "delete":
            action = "delete"
        elif button in {"approve", "status"}:
            action = "approve"
        elif button in {"assign", "permissions"}:
            action = "assign"
        elif button in {"evaluate", "compute", "analyze"}:
            action = "evaluate"

        with get_connection("strategy") as conn:
            assert_module_permission(
                conn,
                user=user,
                module_key=page_key,
                action=action,
            )
        return user

    return dependency
