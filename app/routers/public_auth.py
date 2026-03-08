from fastapi import APIRouter, HTTPException

from ..schemas.auth import AcceptInvitationRequest, LoginRequest, SignupNormalUserRequest, SignupOrganizationRequest, SignupOtpVerifyRequest
from . import auth as legacy_auth

router = APIRouter(prefix="/api/public", tags=["public-auth"])


@router.post("/signup/normal-user")
def signup_normal_user(payload: SignupNormalUserRequest) -> dict:
    return legacy_auth.signup_normal_user_request(payload)


@router.post("/signup/organization")
def signup_organization(payload: SignupOrganizationRequest) -> dict:
    return legacy_auth.signup_organization_request(payload)


@router.post("/otp/verify")
def verify_otp(payload: SignupOtpVerifyRequest) -> dict:
    return legacy_auth.verify_signup_otp(payload)


@router.post("/login/platform")
def platform_login(payload: LoginRequest) -> dict:
    result = legacy_auth.login(payload)
    user = result.get("user") or {}
    role = str(user.get("role", "")).strip().lower()
    if user.get("organization_id") is not None and role not in {"owner", "super_admin"}:
        raise HTTPException(status_code=403, detail="Organization members must use organization login")
    return result


@router.get("/invitations/{token}")
def get_invitation(token: str) -> dict:
    return legacy_auth.get_invitation_details(token)


@router.post("/invitations/accept")
def accept_invitation(payload: AcceptInvitationRequest) -> dict:
    return legacy_auth.accept_invitation(payload)