from __future__ import annotations

from dataclasses import dataclass
from html import escape
from typing import Sequence


@dataclass(frozen=True)
class RenderedEmail:
    subject: str
    text_body: str
    html_body: str


def _clean_lines(lines: Sequence[str] | None) -> list[str]:
    cleaned: list[str] = []
    for line in lines or []:
        value = str(line or "").strip()
        if value:
            cleaned.append(value)
    return cleaned


def _greeting(name: str | None) -> str:
    value = " ".join(str(name or "").strip().split())
    return f"Hello {value}," if value else "Hello,"


def _render_email(
    *,
    subject: str,
    title: str,
    recipient_name: str | None,
    intro_lines: Sequence[str],
    detail_lines: Sequence[str] | None = None,
    action_label: str | None = None,
    action_url: str | None = None,
    code: str | None = None,
    outro_lines: Sequence[str] | None = None,
) -> RenderedEmail:
    intro = _clean_lines(intro_lines)
    details = _clean_lines(detail_lines)
    outro = _clean_lines(outro_lines)
    greeting = _greeting(recipient_name)

    text_parts = [greeting, ""]
    text_parts.extend(intro)
    if code:
        text_parts.extend(["", f"Verification code: {code}"])
    if action_label and action_url:
        text_parts.extend(["", f"{action_label}: {action_url}"])
    if details:
        text_parts.extend([""] + details)
    if outro:
        text_parts.extend([""] + outro)
    text_parts.extend(["", "Regards,", "EnergyOS Team"])
    text_body = "\n".join(text_parts)

    intro_html = "".join(f"<p style=\"margin:0 0 14px;color:#334155;font-size:15px;line-height:1.7;\">{escape(line)}</p>" for line in intro)
    details_html = "".join(f"<li style=\"margin:0 0 8px;\">{escape(line)}</li>" for line in details)
    outro_html = "".join(f"<p style=\"margin:0 0 12px;color:#64748b;font-size:14px;line-height:1.6;\">{escape(line)}</p>" for line in outro)
    code_html = ""
    if code:
        code_html = (
            "<div style=\"margin:22px 0;padding:18px 20px;border-radius:14px;"
            "background:linear-gradient(135deg,#eff6ff 0%,#f8fafc 100%);"
            "border:1px solid #bfdbfe;text-align:center;\">"
            f"<div style=\"font-size:12px;letter-spacing:0.14em;text-transform:uppercase;color:#1d4ed8;margin-bottom:8px;\">Verification code</div>"
            f"<div style=\"font-size:30px;font-weight:700;letter-spacing:0.18em;color:#0f172a;\">{escape(code)}</div>"
            "</div>"
        )
    action_html = ""
    if action_label and action_url:
        action_html = (
            "<div style=\"margin:24px 0 18px;\">"
            f"<a href=\"{escape(action_url, quote=True)}\" style=\"display:inline-block;padding:13px 22px;border-radius:999px;background:#0f766e;color:#ffffff;text-decoration:none;font-weight:600;font-size:14px;\">{escape(action_label)}</a>"
            "</div>"
            f"<p style=\"margin:0 0 12px;color:#64748b;font-size:13px;line-height:1.6;\">If the button does not work, copy and paste this link into your browser:<br><a href=\"{escape(action_url, quote=True)}\" style=\"color:#0f766e;text-decoration:none;word-break:break-all;\">{escape(action_url)}</a></p>"
        )

    html_body = (
        "<!DOCTYPE html>"
        "<html><body style=\"margin:0;padding:24px;background:#e2e8f0;font-family:Segoe UI,Arial,sans-serif;\">"
        "<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"border-collapse:collapse;\">"
        "<tr><td align=\"center\">"
        "<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"max-width:640px;border-collapse:collapse;\">"
        "<tr><td style=\"padding:0 0 14px 6px;color:#0f172a;font-size:13px;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;\">EnergyOS</td></tr>"
        "<tr><td style=\"background:#ffffff;border-radius:24px;padding:36px 36px 28px;box-shadow:0 18px 48px rgba(15,23,42,0.08);\">"
        f"<h1 style=\"margin:0 0 18px;color:#0f172a;font-size:28px;line-height:1.2;\">{escape(title)}</h1>"
        f"<p style=\"margin:0 0 16px;color:#0f172a;font-size:15px;font-weight:600;\">{escape(greeting)}</p>"
        f"{intro_html}"
        f"{code_html}"
        f"{action_html}"
        + (
            "<ul style=\"margin:18px 0 0 18px;padding:0;color:#475569;font-size:14px;line-height:1.6;\">"
            f"{details_html}"
            "</ul>"
            if details
            else ""
        )
        + f"{outro_html}"
        + "<p style=\"margin:22px 0 0;color:#0f172a;font-size:14px;line-height:1.6;\">Regards,<br>EnergyOS Team</p>"
        + "</td></tr>"
        + "<tr><td style=\"padding:14px 8px 0;color:#64748b;font-size:12px;line-height:1.6;\">This is an automated message from EnergyOS.</td></tr>"
        + "</table></td></tr></table></body></html>"
    )
    return RenderedEmail(subject=subject, text_body=text_body, html_body=html_body)


def build_account_verification_email(*, full_name: str, otp_code: str) -> RenderedEmail:
    return _render_email(
        subject="Verify your EnergyOS account",
        title="Verify your email address",
        recipient_name=full_name,
        intro_lines=[
            "Use the verification code below to continue creating your EnergyOS account.",
        ],
        detail_lines=["This code expires in 10 minutes."],
        code=otp_code,
        outro_lines=["If you did not request this, you can safely ignore this email."],
    )


def build_organization_signup_verification_email(*, full_name: str, organization_name: str, otp_code: str) -> RenderedEmail:
    return _render_email(
        subject="Verify your organization signup",
        title="Verify your organization signup",
        recipient_name=full_name,
        intro_lines=[
            f"Use the verification code below to confirm the signup request for {organization_name}.",
        ],
        detail_lines=["This code expires in 10 minutes."],
        code=otp_code,
        outro_lines=["If you did not start this request, no further action is required."],
    )


def build_workspace_signup_verification_email(*, full_name: str, organization_name: str, otp_code: str) -> RenderedEmail:
    return _render_email(
        subject=f"Verify your {organization_name} workspace signup",
        title="Verify your workspace signup",
        recipient_name=full_name,
        intro_lines=[
            f"Use the verification code below to confirm your access request for the {organization_name} workspace.",
        ],
        detail_lines=["This code expires in 10 minutes."],
        code=otp_code,
        outro_lines=["If you did not request access, you can ignore this email."],
    )


def build_invitation_email(*, full_name: str, organization_name: str, invitation_link: str, expiry_line: str) -> RenderedEmail:
    return _render_email(
        subject=f"Invitation to join {organization_name} on EnergyOS",
        title=f"You are invited to join {organization_name}",
        recipient_name=full_name,
        intro_lines=[
            f"You have been invited to collaborate in the {organization_name} workspace on EnergyOS.",
            "Use the secure link below to accept the invitation and complete your account setup.",
        ],
        detail_lines=[expiry_line],
        action_label="Accept invitation",
        action_url=invitation_link,
        outro_lines=["If you were not expecting this invitation, you can ignore this email."],
    )


def build_password_reset_email(*, full_name: str, reset_link: str) -> RenderedEmail:
    return _render_email(
        subject="Reset your EnergyOS password",
        title="Reset your password",
        recipient_name=full_name,
        intro_lines=[
            "We received a request to reset your EnergyOS password.",
            "Use the secure link below to choose a new password.",
        ],
        detail_lines=["This reset link expires in 30 minutes."],
        action_label="Reset password",
        action_url=reset_link,
        outro_lines=["If you did not request a password reset, you can ignore this email and your password will remain unchanged."],
    )


def build_admin_login_request_email(*, requested_for_name: str, requested_for_email: str, otp_code: str, requested_at: str) -> RenderedEmail:
    return _render_email(
        subject="Admin Login Verification Code Request",
        title="Admin login verification required",
        recipient_name=None,
        intro_lines=[
            "An admin login verification code has been requested.",
            f"Requested by: {requested_for_name} ({requested_for_email})",
        ],
        detail_lines=[
            f"Requested at: {requested_at}",
            "This code expires in 10 minutes.",
        ],
        code=otp_code,
        outro_lines=["Only share this code if you have verified the request through the approved workflow."],
    )


def build_project_update_reminder_email(*, full_name: str, project_code: str, reminder_type: str, dashboard_url: str) -> RenderedEmail:
    return _render_email(
        subject="Project update reminder",
        title="Project update reminder",
        recipient_name=full_name,
        intro_lines=[
            f"This is a reminder to review and update project {project_code}.",
            "Please log in and confirm the latest project actuals and status.",
        ],
        detail_lines=[f"Reminder type: {reminder_type}"],
        action_label="Open EnergyOS",
        action_url=dashboard_url,
    )