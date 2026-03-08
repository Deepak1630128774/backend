from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    organization_name: str = ""
    full_name: str = Field(min_length=2)
    email: EmailStr
    password: str = Field(min_length=8)
    purchase_reference: str = ""


class ApproveRegistrationRequest(BaseModel):
    request_id: int
    approve: bool
    note: str = ""


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8)


class AdminOtpRequest(BaseModel):
    email: EmailStr


class AdminOtpVerifyRequest(BaseModel):
    email: EmailStr
    code: str = Field(min_length=6, max_length=6)


class CreateOrgUserRequest(BaseModel):
    organization_id: int
    full_name: str = Field(min_length=2)
    email: EmailStr
    password: str = Field(min_length=8)
    role: str = "org_user"


class ApproveOrgUserRequest(BaseModel):
    user_id: int
    approve: bool


class SignupNormalUserRequest(BaseModel):
    full_name: str = Field(min_length=2)
    email: EmailStr
    password: str = Field(min_length=8)


class SignupOrganizationRequest(BaseModel):
    organization_name: str = Field(min_length=2)
    full_name: str = Field(min_length=2)
    email: EmailStr
    password: str = Field(min_length=8)
    purchase_reference: str = ""


class TenantMemberSignupRequest(BaseModel):
    full_name: str = Field(min_length=2)
    email: EmailStr
    password: str = Field(min_length=8)


class SignupOtpVerifyRequest(BaseModel):
    signup_request_id: int
    code: str = Field(min_length=6, max_length=6)


class AcceptInvitationRequest(BaseModel):
    token: str = Field(min_length=16)
    full_name: str = Field(min_length=2)
    password: str = Field(min_length=8)
