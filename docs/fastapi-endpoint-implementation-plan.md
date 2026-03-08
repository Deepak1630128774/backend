# FastAPI Endpoint Implementation Plan

## Objective

Provide a concrete backend implementation plan for the multi-tenant user, organization, OTP, and access system using the existing FastAPI project structure under `backend/app`.

## Implementation Scope

This plan covers:

- public signup and login flows
- OTP verification
- organization status approval
- invitation flow
- audit log architecture
- owner administration APIs
- organization admin APIs
- tenant resolution and tenant-guard dependencies
- migration of current auth and admin routers

## Target Router Layout

Recommended route groups:

- `app/routers/public_auth.py`
- `app/routers/owner_admin.py`
- `app/routers/org_admin.py`
- `app/routers/tenant_auth.py`
- keep business routers such as `fuel`, `co2`, `macc`, `strategy`

Current routers to refactor:

- `backend/app/routers/auth.py`
- `backend/app/routers/admin.py`

## New Supporting Services

Recommended service modules:

- `app/services/tenant.py`
- `app/services/otp.py`
- `app/services/identity.py`
- `app/services/membership.py`
- `app/services/invitations.py`
- `app/services/audit_log.py`
- `app/services/owner_admin.py`
- `app/services/org_admin.py`

These should keep router code thin and testable.

## Cross-Cutting Dependencies

### 1. Tenant Resolver

File suggestion: `app/services/tenant.py`

Responsibilities:

- parse request host header
- determine platform or organization scope
- resolve `organization_id` for subdomains
- return a tenant context object

Suggested dependency:

- `get_tenant_context()`

### 2. Current Principal Resolver

Current authz service should be extended so `get_current_user` returns:

- user identity
- platform role
- organization membership role if any
- authenticated tenant context

### 3. Tenant Guard

Suggested dependencies:

- `require_platform_session()`
- `require_owner()`
- `require_org_admin()`
- `require_org_member()`
- `require_same_tenant()`

## Public Authentication Endpoints

### POST `/api/public/signup/normal-user`

Request:

- full_name
- email
- password

Behavior:

- create user with `account_type=normal_user`
- create pending approval record
- create signup OTP challenge
- send OTP email

Response:

- user id or challenge id
- status `otp_pending`

### POST `/api/public/signup/organization`

Request:

- organization_name
- organization_slug
- admin_full_name
- admin_email
- password

Behavior:

- create user as org-member identity
- create organization in pending state
- create org-admin membership in pending state
- reserve subdomain
- create OTP challenge
- send OTP email

Response:

- organization id
- reserved subdomain
- status `otp_pending`

Post-verification state:

- organization should move to `pending_owner_review`
- owner must approve organization before first tenant activation if owner-gated onboarding is enabled

### POST `/api/public/otp/send`

Request:

- email
- purpose

Behavior:

- generate new OTP challenge
- invalidate older active challenge for same purpose if needed
- send OTP email

### POST `/api/public/otp/verify`

Request:

- email
- purpose
- code

Behavior:

- validate OTP
- mark challenge used
- activate related user or signup state depending on purpose

Cases:

- normal-user signup: email verified, approval still pending
- organization signup: email verified, org and org-admin membership activated
- password reset: authorize password reset completion
- invite accept: activate org user membership

### POST `/api/public/login/platform`

Allowed principals:

- owner
- approved normal user

Behavior:

- reject org-only users
- require email verified
- require active approval state
- issue platform-scoped JWT

### POST `/api/public/login/organization`

Allowed principals:

- org_admin
- org_user

Behavior:

- resolve tenant from subdomain
- ensure user has active membership in that tenant
- issue tenant-scoped JWT

## Owner Administration Endpoints

### GET `/api/owner/hierarchy`

Returns:

- owners
- normal users
- organizations with nested org admins and org users

### GET `/api/owner/organizations`

Returns paginated organization list with counts.

### GET `/api/owner/organizations/{organization_id}`

Returns organization metadata and members.

### POST `/api/owner/organizations/{organization_id}/status`

Actions:

- activate
- suspend
- reject

Implementation notes:

- approving after OTP verification should transition `pending_owner_review -> active`
- suspension should block tenant login for org-admin and org-user accounts under that organization
- reactivation should restore tenant login without recreating memberships

### GET `/api/owner/normal-users`

Lists all platform normal users and approval state.

### POST `/api/owner/normal-users/{user_id}/approve`

Approve or reject normal user platform access.

### POST `/api/owner/owners`

Creates additional owner account.

### POST `/api/owner/users/{user_id}/status`

Suspend or activate any account.

### GET `/api/owner/audit`

Query audit trail across tenants.

### GET `/api/owner/organizations/pending-approval`

Returns organizations waiting for owner review.

### POST `/api/owner/organizations/{organization_id}/approve`

Approves organization activation after OTP verification.

### POST `/api/owner/organizations/{organization_id}/reject`

Rejects organization onboarding with note.

## Organization Admin Endpoints

### GET `/api/org-admin/users`

Returns only users inside the authenticated organization.

### POST `/api/org-admin/users`

Creates org user or sends invitation.

Request:

- full_name
- email
- role default `org_user`

Behavior:

- organization inferred from tenant context, never client input
- membership created in pending or active state depending on invite model

Recommended implementation:

- default to invitation-based onboarding
- create invitation record
- send invitation email and OTP challenge
- activate membership only after invite acceptance

### PATCH `/api/org-admin/users/{user_id}`

Updates org user metadata inside tenant.

### POST `/api/org-admin/users/{user_id}/status`

Suspend or activate org user inside tenant.

### POST `/api/org-admin/access/module`

Assign module-level access to org user.

### POST `/api/org-admin/access/project`

Assign project-level access within the same organization.

### POST `/api/org-admin/access/sub-entity`

Assign sub-entity permissions within same organization.

### GET `/api/org-admin/audit`

Returns audit rows only for the current tenant.

### GET `/api/org-admin/invitations`

List current tenant invitations with status.

### POST `/api/org-admin/invitations`

Create invitation for organization user.

### POST `/api/org-admin/invitations/{invitation_id}/resend`

Resend invitation or OTP.

### POST `/api/org-admin/invitations/{invitation_id}/revoke`

Revoke pending invitation.

### POST `/api/public/invitations/accept`

Accept invitation and complete OTP verification.

## Existing Endpoint Refactor Mapping

### Replace in `auth.py`

Current endpoints to split:

- `/api/auth/register`
- `/api/auth/login`
- `/api/auth/request-admin-login-code`
- `/api/auth/verify-admin-login-code`

New direction:

- public signup endpoints
- platform login endpoint
- tenant login endpoint
- universal OTP service

### Replace in `admin.py`

Current mixed admin router contains both owner-like and buyer-admin-like behavior. That should be split into:

- owner-only router
- org-admin-only router

The existing ACL internals can still be reused.

## DTO And Schema Plan

Recommended new schema files:

- `app/schemas/public_auth.py`
- `app/schemas/owner_admin.py`
- `app/schemas/org_admin.py`
- `app/schemas/tenant.py`

Suggested request models:

- `NormalUserSignupRequest`
- `OrganizationSignupRequest`
- `OtpSendRequest`
- `OtpVerifyRequest`
- `PlatformLoginRequest`
- `TenantLoginRequest`
- `CreateOwnerRequest`
- `ApproveNormalUserRequest`
- `CreateOrganizationUserRequest`
- `OrganizationStatusApprovalRequest`
- `CreateInvitationRequest`
- `ResendInvitationRequest`
- `RevokeInvitationRequest`
- `AcceptInvitationRequest`

## Service Responsibilities

### `tenant.py`

- resolve host to tenant
- validate subdomain ownership

### `otp.py`

- create OTP challenge
- hash and verify OTP
- expiry and retry rules
- send email integration

### `identity.py`

- create user identity
- activate user
- create JWT claims
- validate login flows

### `membership.py`

- create org membership
- activate membership
- list organization members
- enforce org boundary checks

### `invitations.py`

- create invitation
- resend invitation
- revoke invitation
- accept invitation
- expire stale invitations

### `audit_log.py`

- standardize audit event payloads
- attach tenant context and request host
- provide owner-scoped and org-scoped query helpers

### `owner_admin.py`

- hierarchy queries
- approvals
- owner creation
- org status changes

### `org_admin.py`

- org user lifecycle
- tenant-scoped permissions
- org audit access

## Dependency Injection Design

Suggested FastAPI dependencies:

- `get_tenant_context`
- `get_current_principal`
- `require_owner`
- `require_platform_user`
- `require_org_admin`
- `require_org_member`

These should replace ad hoc role checks scattered across route handlers.

## Testing Plan

### Unit Tests

- OTP generation and verification
- tenant resolver host parsing
- JWT claim generation
- membership validation

### Integration Tests

- normal user signup -> OTP verify -> owner approval -> login
- organization signup -> OTP verify -> owner approve -> org admin login on subdomain
- org admin creates org user -> org user can access tenant-only data
- org admin creates invitation -> user accepts invite -> membership activates
- org admin blocked from reading another tenant
- owner hierarchy shows all tenants and all normal users
- owner audit endpoint returns cross-tenant actions
- org audit endpoint returns only tenant-local actions

### Security Tests

- wrong subdomain with valid token returns `403`
- expired OTP rejected
- reused OTP rejected
- org admin cannot elevate to owner
- org admin cannot query users from another organization

## Recommended Delivery Sequence

### Workstream 1. Foundations

- add schema support for users, memberships, OTP, and domains
- add tenant resolver and principal model

### Workstream 2. Public Flows

- normal user signup
- organization signup
- OTP verify
- platform login
- tenant login

### Workstream 3. Owner Admin

- hierarchy endpoints
- normal user approval
- organization status management
- owner creation
- owner review queue for pending organizations

### Workstream 4. Org Admin

- org user CRUD
- invitation lifecycle
- org-scoped permission assignment
- org audit views

### Workstream 5. Business Router Hardening

- update fuel, co2, macc, strategy routers to rely on tenant boundary dependency before ACL checks

## Definition Of Done

The backend implementation is considered complete when:

- every signup is OTP verified
- normal users cannot log in before owner approval
- organization signup provisions org admin and tenant subdomain
- organization status can be approved, rejected, suspended, and reactivated by owner workflow
- org admins can manage only their own org users
- org invitations are tenant-bound, expiring, and single-use
- owners can view all organizations and all users
- tenant mismatch is rejected server-side
- business data queries are tenant-isolated
- audit trail captures all critical identity and access changes

## Final Recommendation

Do not implement this by only expanding the existing `auth.py` and `admin.py` files. The correct backend implementation is to split platform auth, tenant auth, owner admin, and org admin into separate route groups backed by tenant-aware service layers.