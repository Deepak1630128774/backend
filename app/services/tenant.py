from dataclasses import asdict, dataclass
from urllib.parse import urlparse

from fastapi import Depends, Header, HTTPException, Request

from ..database import get_connection
from ..settings import APP_BASE_URL


PLATFORM_HOST_SUFFIXES = (".onrender.com",)


@dataclass
class TenantContext:
    scope: str
    host: str
    organization_id: int | None = None
    organization_slug: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def _platform_hosts() -> set[str]:
    configured_host = urlparse(APP_BASE_URL).hostname or ""
    hosts = {
        configured_host.lower(),
        "localhost",
        "127.0.0.1",
    }
    return {host for host in hosts if host}


def _is_platform_host(host: str) -> bool:
    normalized = host.strip().lower()
    if not normalized:
        return True
    if normalized in _platform_hosts():
        return True
    return any(normalized.endswith(suffix) for suffix in PLATFORM_HOST_SUFFIXES)


def _extract_host(request: Request) -> str:
    workspace_host = request.headers.get("x-workspace-host", "").strip().lower()
    origin = request.headers.get("origin", "").strip()
    referer = request.headers.get("referer", "").strip()
    forwarded_host = request.headers.get("x-forwarded-host", "").strip().lower()
    host = workspace_host or forwarded_host

    if not host and origin:
        host = urlparse(origin).netloc.strip().lower()
    if not host and referer:
        host = urlparse(referer).netloc.strip().lower()
    if not host:
        host = request.headers.get("host", "").strip().lower()

    return host.split(":", 1)[0].lower()


def get_tenant_context(request: Request) -> TenantContext:
    host = _extract_host(request)
    if _is_platform_host(host):
        return TenantContext(scope="platform", host=host)

    host_parts = [part for part in host.split(".") if part]
    if len(host_parts) < 2:
        return TenantContext(scope="platform", host=host)

    subdomain = host_parts[0]
    if subdomain in {"www", "platform", "api"}:
        return TenantContext(scope="platform", host=host)

    with get_connection("strategy") as conn:
        organization = conn.execute(
            """
            SELECT o.id, o.slug
            FROM organization_domains d
            JOIN organizations o ON o.id = d.organization_id
            WHERE lower(d.subdomain) = ?
            LIMIT 1
            """,
            (subdomain,),
        ).fetchone()
        if not organization:
            organization = conn.execute(
                "SELECT id, slug FROM organizations WHERE lower(slug) = ? LIMIT 1",
                (subdomain,),
            ).fetchone()
    if not organization:
        return TenantContext(scope="platform", host=host)
    return TenantContext(
        scope="organization",
        host=host,
        organization_id=int(organization["id"]),
        organization_slug=str(organization["slug"] or ""),
    )


def assert_user_matches_tenant(*, user: dict, tenant: TenantContext) -> None:
    from .authz import get_effective_organization_id, get_effective_role

    role = get_effective_role(user)
    if role in {"owner", "super_admin"}:
        return
    if tenant.scope != "organization":
        return
    if get_effective_organization_id(user) == tenant.organization_id:
        return
    membership_ok = False
    with get_connection("strategy") as conn:
        membership = conn.execute(
            """
            SELECT status
            FROM organization_memberships
            WHERE user_id = ? AND organization_id = ?
            LIMIT 1
            """,
            (user.get("id"), tenant.organization_id),
        ).fetchone()
        membership_ok = bool(membership and membership["status"] == "active")
    if not membership_ok:
        raise HTTPException(status_code=403, detail="Tenant mismatch")


def require_platform_session(
    request: Request,
    authorization: str | None = Header(default=None),
    tenant: TenantContext = Depends(get_tenant_context),
) -> dict:
    from .authz import get_current_user
    from .authz import get_effective_role

    user = get_current_user(request=request, authorization=authorization)
    role = get_effective_role(user)
    if tenant.scope == "organization" and role not in {"owner", "super_admin"}:
        raise HTTPException(status_code=403, detail="Platform session required")
    return user


def require_org_member_or_owner(
    request: Request,
    authorization: str | None = Header(default=None),
    tenant: TenantContext = Depends(get_tenant_context),
):
    from .authz import get_current_user
    from .authz import get_effective_organization_id, get_effective_role

    user = get_current_user(request=request, authorization=authorization)
    role = get_effective_role(user)
    if role in {"owner", "super_admin"}:
        return user
    if not get_effective_organization_id(user):
        raise HTTPException(status_code=403, detail="Organization membership required")
    assert_user_matches_tenant(user=user, tenant=tenant)
    return user


def require_org_admin(
    request: Request,
    authorization: str | None = Header(default=None),
    tenant: TenantContext = Depends(get_tenant_context),
):
    from .authz import get_effective_role

    user = require_org_member_or_owner(request=request, authorization=authorization, tenant=tenant)
    role = get_effective_role(user)
    if role in {"owner", "super_admin", "org_admin"}:
        return user
    raise HTTPException(status_code=403, detail="Organization admin required")


def require_org_member(
    request: Request,
    authorization: str | None = Header(default=None),
    tenant: TenantContext = Depends(get_tenant_context),
):
    return require_org_member_or_owner(request=request, authorization=authorization, tenant=tenant)


def assert_payload_organization_access(conn, *, user: dict, organization_name: str) -> None:
    from .authz import get_data_scope_organization_id, get_effective_role

    normalized = " ".join(str(organization_name or "").strip().lower().split())
    if not normalized:
        return
    role = get_effective_role(user)
    organization_id = get_data_scope_organization_id(user)
    if role in {"owner", "super_admin"} and organization_id is None:
        raise HTTPException(status_code=403, detail="Select an organization before working with organization data")
    if not organization_id:
        raise HTTPException(status_code=403, detail="Organization context required")
    row = conn.execute(
        "SELECT name FROM organizations WHERE id = ?",
        (organization_id,),
    ).fetchone()
    current_name = " ".join(str(row["name"] if row else "").strip().lower().split())
    if current_name and normalized != current_name:
        raise HTTPException(status_code=403, detail="Organization payload does not match tenant")