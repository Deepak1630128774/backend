# Multi-Tenant Implementation Status

## Summary

This file tracks what is implemented in code now, what is partial, and what remains missing against:

- [backend/docs/fastapi-endpoint-implementation-plan.md](backend/docs/fastapi-endpoint-implementation-plan.md)
- [backend/docs/multi-tenant-architecture.md](backend/docs/multi-tenant-architecture.md)
- [backend/docs/multi-tenant-schema-and-migration-plan.md](backend/docs/multi-tenant-schema-and-migration-plan.md)

## Implemented

- OTP-backed signup request flow for normal users and organization signups
- Owner approval flow for pending platform users and pending organizations
- Invitation creation, acceptance, resend, and revoke lifecycle
- Admin UI for owner review queues and invitation operations
- Additive tenant tables for:
  - `organization_domains`
  - `organization_memberships`
- Additive approval and verification tables for:
  - `email_otp_challenges`
  - `normal_user_approvals`
  - `organization_status_approvals`
  - `owners`
- New route groups added:
  - `backend/app/routers/public_auth.py`
  - `backend/app/routers/owner_admin.py`
  - `backend/app/routers/org_admin.py`
  - `backend/app/routers/tenant_auth.py`
- Initial tenant context service added:
  - `backend/app/services/tenant.py`
- Membership-aware effective role and organization resolution added in authz/tenant/admin compatibility paths

## Partial

- Tenant resolution now prefers `organization_domains.subdomain` and falls back to `organizations.slug` for compatibility.
- JWT tokens still carry legacy role claims, but request-time principal resolution now derives effective role and organization from memberships when available.
- Business routers are being hardened with tenant-aware dependencies, but the underlying storage model still relies on `users.organization_id`.
- Membership rows are dual-written and backfilled. Core authz, tenant guards, and key admin organization checks now prefer membership-derived role/org context, but wider legacy router logic still remains.
- OTP flows now dual-write into `email_otp_challenges`, but legacy `signup_requests` and `admin_otp_requests` are still active compatibility paths.
- Owner approval flows now write to explicit approval tables, but legacy `users.is_approved` and `organizations.approval_status` are still maintained for compatibility.
- Audit logging exists, but it is not yet normalized to the target shape from the schema plan.

## Missing

- full service split into `identity.py`, `membership.py`, `invitations.py`, `owner_admin.py`, `org_admin.py`, `otp.py`
- final migration away from legacy `auth.py` and `admin.py`
- full tenant-subdomain login rollout in frontend deployment