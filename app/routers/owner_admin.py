from fastapi import APIRouter, Body, Depends

from ..services.authz import require_role
from . import admin as legacy_admin

router = APIRouter(prefix="/api/owner", tags=["owner-admin"])


@router.get("/hierarchy")
def hierarchy(_: dict = Depends(require_role("owner"))) -> dict:
    return legacy_admin.get_owner_hierarchy(_)


@router.get("/organizations/pending-approval")
def pending_organizations(_: dict = Depends(require_role("owner"))) -> list[dict]:
    return legacy_admin.list_pending_organizations(_)


@router.get("/normal-users/pending-approval")
def pending_platform_users(_: dict = Depends(require_role("owner"))) -> list[dict]:
    return legacy_admin.list_pending_platform_users(_)


@router.post("/organizations/{organization_id}/approve")
def approve_organization(organization_id: int, note: str = Body(default="", embed=True), owner: dict = Depends(require_role("owner"))) -> dict:
    from ..schemas.admin import OwnerOrganizationReviewRequest

    payload = OwnerOrganizationReviewRequest(organization_id=organization_id, approve=True, note=note)
    return legacy_admin.review_organization(payload, owner)


@router.post("/organizations/{organization_id}/reject")
def reject_organization(organization_id: int, note: str = Body(default="", embed=True), owner: dict = Depends(require_role("owner"))) -> dict:
    from ..schemas.admin import OwnerOrganizationReviewRequest

    payload = OwnerOrganizationReviewRequest(organization_id=organization_id, approve=False, note=note)
    return legacy_admin.review_organization(payload, owner)


@router.post("/normal-users/{user_id}/approve")
def approve_platform_user(user_id: int, note: str = Body(default="", embed=True), owner: dict = Depends(require_role("owner"))) -> dict:
    from ..schemas.admin import OwnerPlatformUserReviewRequest

    payload = OwnerPlatformUserReviewRequest(user_id=user_id, approve=True, note=note)
    return legacy_admin.review_platform_user(payload, owner)


@router.post("/normal-users/{user_id}/reject")
def reject_platform_user(user_id: int, note: str = Body(default="", embed=True), owner: dict = Depends(require_role("owner"))) -> dict:
    from ..schemas.admin import OwnerPlatformUserReviewRequest

    payload = OwnerPlatformUserReviewRequest(user_id=user_id, approve=False, note=note)
    return legacy_admin.review_platform_user(payload, owner)