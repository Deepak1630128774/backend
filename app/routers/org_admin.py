from fastapi import APIRouter, Depends

from ..schemas.admin import CreateOrganizationInvitationRequest
from ..services.tenant import require_org_admin
from . import admin as legacy_admin

router = APIRouter(prefix="/api/org-admin", tags=["org-admin"])


@router.get("/users")
def list_org_users(
    q: str = "",
    role: str = "",
    include_inactive: bool = True,
    include_rejected: bool = True,
    admin_user: dict = Depends(require_org_admin),
) -> list[dict]:
    return legacy_admin.list_users(q=q, role=role, include_inactive=include_inactive, include_rejected=include_rejected, admin=admin_user)


@router.get("/invitations")
def list_invitations(admin_user: dict = Depends(require_org_admin)) -> list[dict]:
    return legacy_admin.list_organization_invitations(admin_user)


@router.post("/invitations")
def create_invitation(payload: CreateOrganizationInvitationRequest, admin_user: dict = Depends(require_org_admin)) -> dict:
    return legacy_admin.create_organization_invitation(payload, admin_user)


@router.post("/invitations/{invitation_id}/resend")
def resend_invitation(invitation_id: int, admin_user: dict = Depends(require_org_admin)) -> dict:
    return legacy_admin.resend_organization_invitation(invitation_id, admin_user)


@router.post("/invitations/{invitation_id}/revoke")
def revoke_invitation(invitation_id: int, admin_user: dict = Depends(require_org_admin)) -> dict:
    return legacy_admin.revoke_organization_invitation(invitation_id, admin_user)