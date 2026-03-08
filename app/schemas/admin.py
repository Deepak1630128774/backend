from pydantic import BaseModel, Field


class OwnerOrganizationReviewRequest(BaseModel):
    organization_id: int
    approve: bool
    note: str = ""


class OwnerPlatformUserReviewRequest(BaseModel):
    user_id: int
    approve: bool
    note: str = ""


class CreateOrganizationInvitationRequest(BaseModel):
    organization_id: int | None = None
    email: str = Field(min_length=5)
    full_name: str = ""
    role: str = Field(default="org_user", min_length=4)
    expires_in_days: int = Field(default=7, ge=0, le=30)


class ReviewOrganizationMemberSignupRequest(BaseModel):
    approve: bool
    note: str = ""


class SetPermissionRequest(BaseModel):
    user_id: int
    page_key: str = Field(min_length=2)
    button_key: str = Field(min_length=2)
    is_allowed: bool


class OrganizationBoundaryRequest(BaseModel):
    organization_id: int
    organization_name: str
    subsidiary_name: str = ""
    associate_name: str = ""
    manufacturing_unit: str = ""


class PermissionFlags(BaseModel):
    can_view: bool = False
    can_create: bool = False
    can_edit: bool = False
    can_delete: bool = False
    can_approve: bool = False
    can_assign: bool = False
    can_evaluate: bool = False


class UpdateUserStatusRequest(BaseModel):
    is_active: bool


class UpdateUserRoleRequest(BaseModel):
    role: str = Field(min_length=4)


class ApplyRoleTemplateRequest(BaseModel):
    role: str = Field(default="", min_length=0)


class BulkUserReviewRequest(BaseModel):
    user_ids: list[int] = Field(default_factory=list)
    approve: bool


class DeleteUsersRequest(BaseModel):
    user_ids: list[int] = Field(default_factory=list)


class DeleteOrganizationRequest(BaseModel):
    organization_id: int


class SetModuleAccessRequest(BaseModel):
    user_id: int
    module_key: str = Field(min_length=2)
    permissions: PermissionFlags


class ProjectAccessAssignmentRequest(BaseModel):
    module_key: str = Field(min_length=2)
    project_id: str = Field(min_length=1)
    user_ids: list[int] = Field(default_factory=list)
    permissions: PermissionFlags


class RemoveProjectAccessRequest(BaseModel):
    module_key: str = Field(min_length=2)
    project_id: str = Field(min_length=1)
    user_id: int


class TransferOwnershipRequest(BaseModel):
    module_key: str = Field(min_length=2)
    project_id: str = Field(min_length=1)
    new_owner_user_id: int


class SetSubEntityAccessRequest(BaseModel):
    user_id: int
    module_key: str = Field(min_length=2)
    project_id: str = Field(min_length=1)
    sub_entity_key: str = Field(min_length=2)
    sub_entity_id: str = Field(min_length=1)
    permissions: PermissionFlags


class AccessPreviewRequest(BaseModel):
    user_id: int
    module_key: str = Field(min_length=2)
    action: str = Field(min_length=3)
    project_id: str = ""
    sub_entity_key: str = ""
    sub_entity_id: str = ""


class UserProfileSettingsRequest(BaseModel):
    font_size: str = Field(default="medium", min_length=3)
    color_theme: str = Field(default="emerald", min_length=3)
    dark_mode: bool = False


class UpdateProfileDetailsRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=6, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)
