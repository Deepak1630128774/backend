# Multi-Tenant Schema And Migration Plan

## Goal

Define a target schema and migration path from the current SQLite-based user and organization model to a multi-tenant model that supports owners, normal users, organization admins, organization users, OTP verification, approval workflows, and subdomain tenancy.

## Current Relevant Tables

Based on the current backend behavior, the live model already relies on tables such as:

- `users`
- `organizations`
- `registration_requests`
- `password_reset_tokens`
- `admin_otp_requests`
- `permissions`
- `user_permissions`
- `projects`
- `modules`
- `audit_logs`

This plan assumes those tables exist and need structured evolution rather than destructive replacement.

## Target Core Schema

### 1. users

Purpose: global identity record.

Columns:

- `id` bigint primary key
- `email` citext unique not null
- `password_hash` text not null
- `full_name` text not null
- `account_type` text not null
  - allowed: `owner`, `normal_user`, `org_member`
- `platform_role` text null
  - allowed: `owner`, `normal_user`, null
- `email_verified` boolean not null default false
- `is_active` boolean not null default false
- `created_at` timestamptz not null
- `updated_at` timestamptz not null
- `last_login_at` timestamptz null

Notes:

- `organization_id` should be removed from this table in the final model.
- organization belonging should move to membership records.

### 2. organizations

Purpose: tenant registry.

Columns:

- `id` bigint primary key
- `name` text not null
- `slug` text unique not null
- `status` text not null
  - allowed: `pending_verification`, `active`, `suspended`, `rejected`
- `created_by_user_id` bigint not null references `users(id)`
- `primary_contact_email` citext null
- `created_at` timestamptz not null
- `updated_at` timestamptz not null

Indexes:

- unique index on `lower(slug)`
- index on `status`

### 3. organization_domains

Purpose: subdomain routing and tenant resolution.

Columns:

- `id` bigint primary key
- `organization_id` bigint not null references `organizations(id)`
- `subdomain` text unique not null
- `is_primary` boolean not null default true
- `created_at` timestamptz not null

Indexes:

- unique index on `lower(subdomain)`
- index on `organization_id`

### 4. organization_memberships

Purpose: user membership in an organization.

Columns:

- `id` bigint primary key
- `organization_id` bigint not null references `organizations(id)`
- `user_id` bigint not null references `users(id)`
- `membership_role` text not null
  - allowed: `org_admin`, `org_user`
- `status` text not null
  - allowed: `pending`, `active`, `suspended`, `rejected`
- `invited_by_user_id` bigint null references `users(id)`
- `approved_by_user_id` bigint null references `users(id)`
- `created_at` timestamptz not null
- `updated_at` timestamptz not null

Constraints:

- unique `(organization_id, user_id)`

Indexes:

- index on `(organization_id, membership_role)`
- index on `(user_id, status)`

### 5. email_otp_challenges

Purpose: OTP verification for signup, login, invites, and password reset.

Columns:

- `id` bigint primary key
- `user_id` bigint not null references `users(id)`
- `purpose` text not null
  - allowed: `signup_verify`, `org_signup_verify`, `password_reset`, `invite_accept`, `login_verify`
- `otp_hash` text not null
- `expires_at` timestamptz not null
- `is_used` boolean not null default false
- `attempt_count` integer not null default 0
- `created_at` timestamptz not null

Indexes:

- index on `(user_id, purpose, is_used)`
- index on `expires_at`

### 6. normal_user_approvals

Purpose: owner approval workflow for normal users.

Columns:

- `id` bigint primary key
- `user_id` bigint not null unique references `users(id)`
- `status` text not null
  - allowed: `pending`, `approved`, `rejected`
- `reviewed_by_user_id` bigint null references `users(id)`
- `reviewed_at` timestamptz null
- `note` text null
- `created_at` timestamptz not null
- `updated_at` timestamptz not null

### 7. organization_signup_requests

Purpose: track organization onboarding lifecycle.

Columns:

- `id` bigint primary key
- `organization_id` bigint not null references `organizations(id)`
- `admin_user_id` bigint not null references `users(id)`
- `status` text not null
  - allowed: `pending_otp`, `pending_owner_review`, `verified`, `active`, `rejected`
- `created_at` timestamptz not null
- `updated_at` timestamptz not null

### 8. organization_status_approvals

Purpose: owner review and approval of tenant activation state.

Columns:

- `id` bigint primary key
- `organization_id` bigint not null references `organizations(id)`
- `status` text not null
  - allowed: `pending`, `approved`, `rejected`, `suspended`, `reactivated`
- `reviewed_by_user_id` bigint null references `users(id)`
- `reviewed_at` timestamptz null
- `note` text null
- `created_at` timestamptz not null
- `updated_at` timestamptz not null

Indexes:

- index on `(organization_id, status)`
- index on `reviewed_by_user_id`

### 9. organization_invitations

Purpose: tenant-bound invitation flow for onboarding organization users.

Columns:

- `id` bigint primary key
- `organization_id` bigint not null references `organizations(id)`
- `email` citext not null
- `invited_user_id` bigint null references `users(id)`
- `invited_by_user_id` bigint not null references `users(id)`
- `membership_role` text not null
  - allowed: `org_admin`, `org_user`
- `invite_token_hash` text not null
- `otp_hash` text null
- `status` text not null
  - allowed: `pending`, `accepted`, `expired`, `revoked`
- `expires_at` timestamptz not null
- `accepted_at` timestamptz null
- `created_at` timestamptz not null
- `updated_at` timestamptz not null

Constraints:

- active pending invitation uniqueness on `(organization_id, lower(email), status)` can be enforced with a partial unique index

Indexes:

- index on `(organization_id, status)`
- index on `lower(email)`
- index on `expires_at`

### 10. owners

Purpose: explicit owner registry.

Columns:

- `user_id` bigint primary key references `users(id)`
- `created_by_user_id` bigint null references `users(id)`
- `created_at` timestamptz not null

This can also be represented through `users.platform_role = 'owner'`, but a dedicated table gives stronger semantics and easier auditing.

### 11. audit_logs normalization target

Purpose: consistent audit visibility across platform and tenant scopes.

Recommended columns if the current table needs expansion:

- `id` bigint primary key
- `actor_user_id` bigint null references `users(id)`
- `actor_organization_id` bigint null references `organizations(id)`
- `tenant_organization_id` bigint null references `organizations(id)`
- `entity_type` text not null
- `entity_id` text not null
- `action` text not null
- `request_host` text null
- `subdomain` text null
- `details_json` jsonb not null default '{}'`
- `created_at` timestamptz not null

Indexes:

- index on `(tenant_organization_id, created_at desc)`
- index on `(actor_user_id, created_at desc)`
- index on `(entity_type, entity_id)`

## Tenant Keys On Resource Tables

All tenant-owned records must carry `organization_id` either directly or via a required parent.

Recommended direct ownership on:

- `projects`
- `permissions`
- any future portfolios, strategies, or organization-scoped content tables

If `projects` already contain `organization_id`, downstream permission rows should reference project ownership rather than trusting only module and project ids.

## Target Role Mapping

### Current To Future Mapping

- current `owner` -> `users.account_type='owner'`, `users.platform_role='owner'`
- current `super_admin` -> same temporary owner/elevated bucket, then reviewed
- current `buyer_admin` -> `organization_memberships.membership_role='org_admin'`
- current `org_user` -> `organization_memberships.membership_role='org_user'`

## Migration Strategy

### Phase 0. Preparation

- move runtime from SQLite target to PostgreSQL for production migration path
- add Alembic migration support
- freeze role changes while migration is running

### Phase 1. Additive Schema Introduction

Create new tables without deleting old ones:

- `organization_domains`
- `organization_memberships`
- `email_otp_challenges`
- `normal_user_approvals`
- `organization_signup_requests`
- `organization_status_approvals`
- `organization_invitations`
- `owners`

Add columns to `users`:

- `account_type`
- `platform_role`
- `email_verified`
- `last_login_at`

Add column to resource tables where missing:

- `organization_id`

### Phase 2. Backfill Users

#### Owners

For rows where `role in ('owner', 'super_admin')`:

- set `account_type='owner'`
- set `platform_role='owner'`
- set `email_verified=true`
- insert into `owners`

#### Buyer Admins

For rows where `role='buyer_admin'`:

- set `account_type='org_member'`
- set `platform_role=null`
- create `organization_memberships` with `membership_role='org_admin'`, `status='active'`

#### Org Users

For rows where `role='org_user'`:

- if business intent is organization-scoped user:
  - set `account_type='org_member'`
  - create `organization_memberships` with `membership_role='org_user'`
- if some are intended to be global normal users:
  - separate them using a migration rule or review list

### Phase 3. Backfill Organizations And Domains

For each organization:

- derive slug from name
- ensure uniqueness with suffixing if needed
- create `organization_domains` primary domain row

### Phase 4. Backfill Approval State

For future normal users:

- create `normal_user_approvals`

For current legacy users:

- if they are active and already platform-approved, mark appropriately

### Phase 5. ACL Realignment

Permission-bearing rows should be updated so every record can be resolved to one organization.

Tasks:

- backfill `permissions.organization_id` from owning project or user membership
- verify no permission row points across organizations
- add validation constraints in service layer before writes

### Phase 6. Application Cutover

Once code is updated to the new model:

- stop reading legacy `users.role`
- stop relying on `users.organization_id` as the primary membership marker
- route all membership checks through `organization_memberships`

### Phase 7. Cleanup

After stable rollout:

- deprecate legacy registration_requests shape if replaced
- remove legacy role logic from auth and admin services
- optionally drop or freeze obsolete columns

## Example Alembic Work Packages

Migration 001:

- add columns to `users`
- create `owners`
- create `organization_domains`

Migration 002:

- create `organization_memberships`
- create `email_otp_challenges`

Migration 003:

- create `normal_user_approvals`
- create `organization_signup_requests`

Migration 004:

- create `organization_status_approvals`
- create `organization_invitations`

Migration 005:

- add `organization_id` to tenant-owned business tables where missing
- create indexes on `organization_id`

Migration 006:

- data migration to backfill users, owners, memberships, domains

## Example Data Integrity Rules

- organization subdomain must be unique
- one user cannot have more than one membership in the same org
- owner accounts cannot be created inside organization membership flows
- org_admin cannot be assigned without organization membership
- resource rows must not point to another organization through ACL entries

## Query Patterns To Support

### Owner hierarchy query

Need efficient access to:

- all organizations
- org admins by organization
- org users by organization
- all normal users

This requires indexes on:

- `organization_memberships.organization_id`
- `organization_memberships.membership_role`
- `users.account_type`

### Tenant login query

Need efficient lookup by:

- `organization_domains.subdomain`
- `users.email`
- membership for `(organization_id, user_id)`

## Recommended Final Storage Model

### Development

- SQLite can remain temporarily for local work if necessary

### Production

- PostgreSQL required
- shared database
- tenant separation via `organization_id`
- optional future row-level security after application logic stabilizes

## Rollback Strategy

All migrations in early phases should be additive and reversible.

Rules:

- do not drop legacy columns until after application cutover
- do not overwrite `users.role` until new services are fully active
- keep read compatibility during transition

## Final Recommendation

Treat this as a staged identity migration, not just a new admin feature. The schema must be reshaped so tenant membership becomes explicit, auditable, and enforceable at query time.