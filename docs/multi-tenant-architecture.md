# Multi-Tenant Access Architecture

## Purpose

This document rewrites the current admin and access model into a tenancy-first backend architecture that supports:

- normal platform users
- organization admins
- organization users
- owner accounts
- OTP-based email verification for all registrations
- organization isolation by tenant and subdomain

It is written against the current FastAPI backend under `backend/app` and assumes the existing ACL model will be retained but moved under stronger tenant boundaries.

## Current State Summary

The current backend already contains partial building blocks:

- organization-aware users in `users.organization_id`
- elevated roles such as `owner` and `super_admin`
- organization-scoped restrictions in admin flows
- module, project, and sub-entity ACLs
- password reset tokens and admin OTP flows

The current system does not yet support:

- separate signup types for normal user vs organization
- universal OTP verification during signup
- formal organization admin lifecycle
- owner approval flow for normal users
- subdomain tenancy
- explicit platform-wide hierarchy views
- a clean split between platform-level and tenant-level administration

## Architectural Principles

### 1. Tenant Before Permission

Every request must first resolve tenant context before checking resource permissions.

Authorization order:

1. authenticate caller
2. resolve tenant context from host or route
3. verify caller belongs to that tenant, unless caller is an owner
4. verify caller role within that tenant scope
5. evaluate ACL for module, project, or sub-entity access

### 2. Separate Identity From Membership

A user identity is not the same thing as a tenant membership.

- `users` represents global identity
- `organization_memberships` represents relationship to an organization
- a platform user can exist without organization membership
- organization access is granted through membership, not by overloading one role column

### 3. Platform Scope And Tenant Scope Must Be Different

There are two management domains:

- platform domain: owners and normal users
- organization domain: org admins and org users

Owners can cross boundaries. Organization admins never can.

### 4. OTP Verification Is Required For Activation

All registration flows must be OTP-verified before the account can become usable.

### 5. Resource Ownership Must Be Tenant-Aware

Every business record must either:

- carry `organization_id` directly, or
- inherit it through a parent entity such as a project

No organization-scoped query should ever rely only on frontend filtering.

## Target User Model

### Owner

- platform super admin
- created initially from backend or secure bootstrap flow
- can create additional owner accounts
- can view and manage all organizations, organization admins, organization users, and normal users
- can access all audit and governance views

### Normal User

- platform-level user, not tied to an organization by default
- signs up on the public platform
- must complete OTP verification
- remains blocked until owner approval
- after approval, can use only the platform capabilities granted to that account

### Organization Admin

- belongs to exactly one organization
- is the administrative manager for that organization
- can create and manage organization users under the same organization
- can assign module, project, and sub-entity permissions within that organization
- cannot see any other organization

### Organization User

- belongs to exactly one organization
- can access only resources granted within that organization
- cannot manage global users or tenant settings

## Tenant Model

### Public Root

Examples:

- `site.com`
- `www.site.com`
- `platform.site.com`

Used for:

- landing page
- normal user signup
- organization signup
- owner login
- normal user login

### Organization Subdomains

Examples:

- `tata.site.com`
- `deccan.site.com`

Used for:

- org admin login
- org user login
- tenant-scoped dashboards and APIs

### Request Tenant Resolution

The backend should resolve the host header into one of:

- platform scope
- organization scope with `organization_id`

This should be implemented as middleware or a dependency that attaches tenant context to the request.

## Domain Boundaries

### Platform Administration

Owner-only capability set:

- manage owner accounts
- list all organizations
- inspect tenant hierarchy
- approve or reject normal users
- suspend or activate organizations
- suspend or activate any user
- audit across all tenants

### Organization Administration

Org-admin-only capability set:

- manage users inside their own organization
- assign permissions inside their own organization
- invite new organization users into their own organization
- approve or reject pending organization-user invitations within their own organization
- inspect tenant-local audit trail
- manage org-local access boundaries

### Resource Access

ACL remains useful but is no longer the first line of defense. ACL is evaluated only after tenant scope is validated.

## Target Authentication Model

JWT claims should explicitly separate platform and tenant semantics.

Recommended claims:

- `uid`
- `sub`
- `account_type`
- `platform_role`
- `organization_id`
- `membership_role`
- `session_type`
- `tenant_subdomain`
- `iat`
- `exp`

Examples:

- owner session: `session_type=platform`, `platform_role=owner`, `organization_id=null`
- normal user session: `session_type=platform`, `platform_role=normal_user`, `organization_id=null`
- org admin session: `session_type=organization`, `membership_role=org_admin`, `organization_id=<id>`

## Registration And Activation Flows

### Normal User Registration

1. user selects `Normal User`
2. backend creates user in inactive state
3. backend creates OTP challenge for email verification
4. user verifies OTP
5. account becomes email-verified but still pending owner approval
6. owner approves account
7. user can log in to platform scope

### Organization Registration

1. user selects `Organization`
2. backend creates organization draft and org-admin identity
3. backend reserves unique subdomain slug
4. backend creates OTP challenge
5. user verifies OTP
6. organization and membership become active
7. org admin logs in through organization subdomain

### Organization Status Approval

Organization lifecycle should be explicit rather than implied.

Recommended statuses:

- `pending_otp`
- `pending_owner_review`
- `active`
- `suspended`
- `rejected`

Recommended approval model:

1. organization signup is submitted
2. org admin verifies email via OTP
3. organization moves to `pending_owner_review`
4. owner reviews organization metadata, domain slug, and contact details
5. owner either approves or rejects the organization
6. only approved organizations become `active`

Rationale:

- prevents immediate automatic tenant activation
- allows review of fraudulent or duplicate organization signups
- gives the owner a formal control point before a new tenant is admitted

Owner actions on organization status:

- approve organization
- reject organization
- suspend active organization
- reactivate suspended organization

### Invitation Flow

Organization user creation should be invitation-based rather than direct password assignment as the primary pattern.

Recommended invitation lifecycle:

1. org admin creates invitation for a user email
2. backend stores invitation with tenant context and intended role
3. invitation email or OTP is sent to the user
4. user accepts invitation and verifies email via OTP
5. backend either creates a new user identity or links an existing global identity
6. organization membership becomes `active`

Invitation rules:

- invitation is always tied to exactly one organization
- invitation cannot cross tenants
- invitation must expire automatically
- invitation can be revoked by org admin before acceptance
- accepted invitation must be single-use

Recommended future invitation statuses:

- `pending`
- `accepted`
- `expired`
- `revoked`

### Audit Logs

Audit logging must be treated as a platform capability, not a debug artifact.

There should be two visibility scopes:

- owner audit scope: all organizations and platform users
- org-admin audit scope: only events for the current tenant

Events that must always be logged:

- signup submitted
- OTP sent
- OTP verified
- login success and failure when appropriate
- organization approved, rejected, suspended, reactivated
- owner account created
- org admin created or demoted
- invitation created, resent, revoked, accepted, expired
- user approved, rejected, suspended, activated
- permission grants and removals
- ownership transfer

Recommended audit event shape:

- actor user id
- actor tenant id if applicable
- target entity type
- target entity id
- action
- tenant id of affected resource
- request host or subdomain
- metadata payload
- created at

### Organization User Provisioning

Preferred pattern:

1. org admin creates invite
2. backend creates pending user or pending invitation
3. user verifies email OTP
4. membership becomes active

## Isolation Rules

The following rules must be enforced at backend level:

- org admins can query only users with their `organization_id`
- org users can access only resources under their `organization_id`
- owners can bypass tenant boundary checks
- tenant-bound tokens cannot be reused against another tenant
- a mismatched host and JWT organization should return `403`

## Admin Hierarchy View

Owner hierarchy should be materialized as a dedicated response model, not assembled ad hoc in the frontend.

Recommended response shape:

- `owners`
- `normal_users`
- `organizations[]`
  - `organization`
  - `organization_admins[]`
  - `organization_users[]`
  - `counts`
  - `status`

This directly supports a tree like:

- Owner
  - Organization: Tata
    - Org Admin
    - User 1
    - User 2
  - Organization: Deccan
    - Org Admin
    - User 1

## Security Controls

- never persist raw OTPs
- hash OTP values before storage
- add OTP retry limits and expiration windows
- rate-limit OTP send and verify endpoints
- include tenant context in access tokens
- require tenant resolution on every tenant-bound request
- log every approval, role change, invitation, suspension, and cross-scope mutation
- prohibit organization admins from assigning owner privileges

## Recommended Runtime Stack

The current SQLite-backed approach is acceptable for local development but should not remain the target architecture for a serious multi-tenant system.

Recommended target:

- FastAPI
- PostgreSQL
- Alembic migrations
- shared-schema multi-tenancy with `organization_id` boundaries
- Redis optional for OTP throttling and short-lived challenge state

## Rollout Strategy

### Phase 1

- introduce new identity and membership model
- add OTP verification for signup
- keep existing ACL tables but tenant-bound

### Phase 2

- split owner admin and org admin APIs
- migrate `buyer_admin` semantics to `org_admin`
- add owner hierarchy endpoints

### Phase 3

- introduce subdomain tenant resolver
- enforce host-based tenant boundary checks

### Phase 4

- migrate to PostgreSQL
- backfill tenant keys and audit data
- remove legacy registration flow

## Final Recommendation

The correct end state is not a slightly expanded admin page. It is a tenancy-first identity and access architecture where:

- platform users and tenant users are modeled separately
- organizations are explicit first-class tenants
- owners operate globally
- organization admins operate only inside their tenant
- all users verify email using OTP
- subdomain context becomes part of backend authorization

That is the level of structure required to make the isolation rules defensible.