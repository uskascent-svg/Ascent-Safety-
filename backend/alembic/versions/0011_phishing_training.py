"""Database-backed phishing simulation scenarios and learner progress.

Revision ID: 0011
Revises: 0010
"""

from alembic import op
import sqlalchemy as sa


revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


_ACTIONS = ["report_message", "avoid_clicking", "preserve_evidence", "contact_security"]
_ACTION_TEXT = {
    "report_message": "Report it through the approved security channel so the organization can investigate and warn others.",
    "avoid_clicking": "Do not open links, scan QR codes, reply, or open attachments in a suspicious message.",
    "preserve_evidence": "Keep the original message and its headers; do not forward it in a way that removes forensic details.",
    "contact_security": "Contact the security team through a known, independent channel, especially if anyone interacted with it.",
    "reset_credentials": "If credentials were entered, contact security and reset them from a trusted device; revoke active sessions.",
    "enable_mfa": "Use phishing-resistant MFA where available, after the account has been secured.",
    "block_sender": "Report or block the sender using your approved mail or messaging controls.",
}


def _scenario(
    slug,
    title,
    category,
    artifact,
    sender,
    reply,
    subject,
    body,
    link,
    filename,
    flags,
    technique,
    objective,
    header_from=None,
    header_auth=None,
):
    return {
        "slug": slug,
        "title": title,
        "category": category,
        "difficulty": "intermediate" if len(flags) > 2 else "beginner",
        "artifact_type": artifact,
        "sender": sender,
        "reply_to": reply,
        "subject": subject,
        "received_at": "2026-10-06 09:14 UTC · simulated",
        "headers": {
            "From": header_from or sender,
            "Reply-To": reply or sender,
            "Received": "mx-training.example; 2026-10-06 09:14:02 UTC (SIMULATED)",
            "Authentication-Results": header_auth or "spf=fail; dkim=none; dmarc=fail (SIMULATED)",
        },
        "body": body,
        "links": ([{"label": "Simulated destination (never opens)", "url": link}] if link else []),
        "attachments": (
            [
                {
                    "name": filename,
                    "type": "Simulated attachment · never opens",
                    "size": "Training artifact",
                }
            ]
            if filename
            else []
        ),
        "indicators": [
            {"id": flag[0], "label": flag[1], "severity": flag[2], "explanation": flag[3]}
            for flag in flags
        ],
        "correct_decision": "report",
        "attack_technique": technique + " (simulated)",
        "explanation": "This fictional scenario combines social pressure with an untrusted sender or destination. The displayed evidence is generated for training and has no real delivery, domain, or infrastructure behind it.",
        "prevention": "Verify the request through a previously known contact method, inspect the complete sender and destination, and use the organization’s report-phishing control. Never enter real credentials in a training exercise.",
        "correct_actions": _ACTIONS,
        "action_rationales": _ACTION_TEXT,
        "objective": objective,
        "is_active": True,
        "created_by": None,
    }


def _seed_rows():
    def F(code, label, severity, explanation):
        return code, label, severity, explanation

    rows = [
        _scenario(
            "credential-reset",
            "Account recovery request",
            "credential_phishing",
            "email",
            "Identity Desk <notice@id-verify.example>",
            "reply@inbox-relay.example",
            "Action required: account access expires",
            "Your account will be paused in 20 minutes. Sign in to keep access. This training message never contacts a real service.",
            "https://id-verify.example/session",
            None,
            [
                F(
                    "sender_mismatch",
                    "Sender and reply-to use unrelated domains",
                    "high",
                    "The visible sender belongs to id-verify.example, while replies go to an unrelated inbox-relay.example domain.",
                ),
                F(
                    "urgency",
                    "Artificial deadline",
                    "medium",
                    "The short countdown pressures the recipient to act before checking the request.",
                ),
                F(
                    "credential_request",
                    "Unexpected sign-in request",
                    "critical",
                    "The message directs the reader to a sign-in page from an unsolicited email.",
                ),
            ],
            "Credential phishing",
            "Inspect sender and reply-to addresses before trusting an account recovery request.",
        ),
        _scenario(
            "executive-transfer",
            "Executive urgent transfer",
            "executive_impersonation",
            "email",
            "Mira Chen <mira.chen@northstar-leadership.example>",
            "payments@fast-reply.example",
            "Need a confidential transfer now",
            "I am in a board meeting. Buy digital vouchers and send the codes before 10:00. Keep this between us.",
            None,
            None,
            [
                F(
                    "reply_mismatch",
                    "Reply-to does not match the executive sender",
                    "high",
                    "Replies are routed to a different domain from the claimed leadership address.",
                ),
                F(
                    "payment_request",
                    "Unusual payment and secrecy request",
                    "critical",
                    "An urgent request for value transfer plus secrecy is a common executive-impersonation pattern.",
                ),
                F(
                    "urgency",
                    "Pressure to act immediately",
                    "medium",
                    "The artificial deadline discourages independent approval.",
                ),
            ],
            "Executive impersonation / payment diversion",
            "Pause unusual payment requests and verify them with a known approval contact.",
        ),
        _scenario(
            "payroll-update",
            "Payroll profile update",
            "hr_payroll",
            "email",
            "People Operations <payroll@northstar-people.example>",
            "profile@external-mail.example",
            "Update direct deposit details",
            "To avoid a payroll delay, confirm your bank details using the secure form. Never enter actual banking details in this simulation.",
            "https://payroll-profile.example/update",
            "Payroll_Change.html",
            [
                F(
                    "domain_lookalike",
                    "Payroll domain differs from the known organization domain",
                    "high",
                    "The sender and destination use a lookalike people domain rather than a verified HR portal.",
                ),
                F(
                    "sensitive_data",
                    "Requests financial information",
                    "critical",
                    "Direct-deposit updates should be completed in the known HR system, not via an email link.",
                ),
                F(
                    "attachment",
                    "Unexpected active HTML attachment",
                    "high",
                    "An HTML attachment can contain a credential-harvesting page; this simulated file must never be opened.",
                ),
            ],
            "Credential phishing / payroll fraud",
            "Complete payroll changes only through a known HR portal and report unexpected attachments.",
        ),
        _scenario(
            "invoice-review",
            "Overdue supplier invoice",
            "banking_payment",
            "email",
            "Accounts Desk <billing@ledger-notice.example>",
            "collections@ledger-notice.example",
            "Final notice: invoice payment due",
            "Review the attached statement and pay today to avoid a service hold. Verify payment changes with the supplier using a known number.",
            "https://invoice-center.example/pay",
            "Invoice_Review.pdf",
            [
                F(
                    "payment_request",
                    "Payment request arrives through an unverified channel",
                    "high",
                    "The message asks for immediate payment without an established verification workflow.",
                ),
                F(
                    "urgency",
                    "Threat of service interruption",
                    "medium",
                    "A consequence and deadline are used to pressure a fast response.",
                ),
                F(
                    "attachment",
                    "Unexpected payment attachment",
                    "medium",
                    "Unexpected files should be reported and checked without opening them.",
                ),
            ],
            "Payment diversion",
            "Verify invoices and bank-detail changes using a previously known supplier contact.",
        ),
        _scenario(
            "delivery-fee",
            "Delivery fee text",
            "delivery_scam",
            "sms",
            "Parcel Desk <dispatch@parcel-status.example>",
            None,
            "Delivery exception",
            "A small address correction fee is required before delivery. This simulated notice has no real parcel.",
            "https://parcel-status.example/fee",
            None,
            [
                F(
                    "unexpected_fee",
                    "Unexpected small fee",
                    "medium",
                    "Small fees are used to make a request seem harmless while collecting payment details.",
                ),
                F(
                    "credential_request",
                    "Unverified delivery link",
                    "high",
                    "Tracking should be checked in the carrier app or site opened independently.",
                ),
                F(
                    "urgency",
                    "Delivery pressure",
                    "low",
                    "Delivery urgency nudges the recipient to follow a link immediately.",
                ),
            ],
            "Smishing / delivery fee fraud",
            "Open the delivery provider’s known app or site yourself; do not use a message link.",
        ),
        _scenario(
            "mfa-fatigue",
            "Repeated sign-in approvals",
            "mfa_fatigue",
            "email",
            "Access Center <alerts@secure-approvals.example>",
            "help@secure-approvals.example",
            "Approve the pending login",
            "You may receive several approval prompts. Approve one to stop the notifications. If you did not sign in, deny and report them.",
            None,
            None,
            [
                F(
                    "unexpected_auth",
                    "Unrequested authentication prompts",
                    "critical",
                    "Repeated prompts can be an MFA-fatigue attempt intended to obtain one accidental approval.",
                ),
                F(
                    "urgency",
                    "Prompt fatigue pressure",
                    "medium",
                    "The sender frames approval as a way to stop interruptions.",
                ),
                F(
                    "sender_mismatch",
                    "Unverified access-center sender",
                    "high",
                    "The email domain has not been established as an organization authentication service.",
                ),
            ],
            "MFA request generation / push fatigue",
            "Deny unexpected prompts, report them, and contact security through a known channel.",
        ),
        _scenario(
            "cloud-login",
            "Cloud document shared with you",
            "microsoft_google_impersonation",
            "login_page",
            "Workspace Share <share@collab-notify.example>",
            "share@collab-notify.example",
            "A document needs your review",
            "This simulated login panel imitates a generic cloud sign-in. Check the domain before entering anything. No password field accepts or transmits data.",
            "https://cloud-workspace.example/sign-in",
            None,
            [
                F(
                    "domain_lookalike",
                    "Login hostname is not the provider’s verified domain",
                    "critical",
                    "Brand styling does not establish ownership of the hostname.",
                ),
                F(
                    "credential_request",
                    "Unexpected login form",
                    "critical",
                    "The page is reached from an unsolicited sharing message; do not type credentials.",
                ),
                F(
                    "urgency",
                    "Document review prompt",
                    "low",
                    "A familiar work action can reduce scrutiny of a destination.",
                ),
            ],
            "Credential phishing / brand impersonation",
            "Verify the complete hostname and open shared files from the provider’s known application.",
        ),
        _scenario(
            "recruiter-fee",
            "Recruitment equipment purchase",
            "recruitment_scam",
            "email",
            "Talent Team <jobs@career-track.example>",
            "recruiting@personal-mail.example",
            "Congratulations: final hiring step",
            "You are selected. Purchase a laptop from our approved supplier and we will reimburse you after onboarding.",
            "https://candidate-kit.example/onboard",
            None,
            [
                F(
                    "payment_request",
                    "Candidate must pay before employment",
                    "high",
                    "Requests to purchase equipment from a specified supplier are a common recruitment scam pattern.",
                ),
                F(
                    "reply_mismatch",
                    "Reply address uses a personal mail domain",
                    "high",
                    "A recruiter replies from an unrelated consumer mailbox despite claiming to represent an employer.",
                ),
                F(
                    "urgency",
                    "Offer pressure",
                    "medium",
                    "The message asks the recipient to act before independently verifying the offer.",
                ),
            ],
            "Recruitment fraud / advance-fee scam",
            "Verify a job offer using the company’s official career site and never pay a recruiter for equipment.",
        ),
        _scenario(
            "support-renewal",
            "Remote support renewal",
            "tech_support",
            "email",
            "Device Help <renewals@device-care.example>",
            "service@call-center.example",
            "Your protection plan is expiring",
            "Call the number in this simulated message and install the remote support utility to avoid a device lock.",
            None,
            "SupportTool.exe",
            [
                F(
                    "unexpected_attachment",
                    "Unexpected executable attachment",
                    "critical",
                    "Never run unexpected software; this fictional file is not supplied or executable.",
                ),
                F(
                    "urgency",
                    "Threat of device lock",
                    "high",
                    "Threats of immediate disruption are used to make recipients bypass normal support routes.",
                ),
                F(
                    "credential_request",
                    "Unsolicited remote access request",
                    "critical",
                    "Remote access should only be initiated through verified organizational support.",
                ),
            ],
            "Tech-support social engineering",
            "Use the support contact already published by your organization and do not install unsolicited tools.",
        ),
        _scenario(
            "sms-mfa-reset",
            "SMS account verification",
            "smishing",
            "sms",
            "Secure Account <no-reply@verify-mobile.example>",
            None,
            "Unusual login blocked",
            "A sign-in was blocked. Reply with your one-time code to keep the account secure. This scenario never requests a real code.",
            "https://verify-mobile.example/check",
            None,
            [
                F(
                    "otp_request",
                    "Requests a one-time passcode by reply",
                    "critical",
                    "Legitimate support teams should not ask you to send an OTP in an SMS reply.",
                ),
                F(
                    "domain_lookalike",
                    "Unverified mobile verification domain",
                    "high",
                    "The link does not establish a relationship to the service provider.",
                ),
                F(
                    "urgency",
                    "Account lock warning",
                    "medium",
                    "The warning pressures a quick reply before checking account activity independently.",
                ),
            ],
            "Smishing / OTP theft",
            "Never share one-time codes; open the service’s official app and report the text.",
        ),
        _scenario(
            "qr-conference",
            "Shared event schedule QR",
            "qr_phishing",
            "email",
            "Conference Desk <schedule@event-schedule.example>",
            None,
            "Updated agenda and attendee list",
            "Scan the QR preview to see the revised program. The image is represented as text here; it cannot be scanned or opened.",
            "https://agenda-access.example/conference",
            None,
            [
                F(
                    "hidden_destination",
                    "QR destination is hidden behind a scan action",
                    "high",
                    "QR codes can conceal a URL; inspect the destination through an approved scanner without opening it.",
                ),
                F(
                    "credential_request",
                    "Agenda link leads to a sign-in prompt",
                    "high",
                    "An agenda should not require credentials on an unrelated host.",
                ),
                F(
                    "sender_mismatch",
                    "Unverified event sender",
                    "medium",
                    "The display name alone does not validate the sender domain.",
                ),
            ],
            "QR-code credential phishing",
            "Verify QR destinations and use the event organizer’s known site instead of entering credentials.",
        ),
        _scenario(
            "typo-portal",
            "Lookalike benefits portal",
            "typosquatting",
            "url",
            "Benefits Notice <benefits@staff-benefit.example>",
            None,
            "Annual enrollment now open",
            "Inspect the hostname carefully. This task displays a reserved training URL only and will never navigate to it.",
            "https://beneflts-portal.example/enroll",
            None,
            [
                F(
                    "domain_lookalike",
                    "Lookalike spelling in the hostname",
                    "critical",
                    "The hostname substitutes a character to resemble a trusted benefits portal.",
                ),
                F(
                    "credential_request",
                    "Sign-in requested on a lookalike host",
                    "critical",
                    "Credentials entered on a lookalike site can be captured; this simulation has no login backend.",
                ),
                F(
                    "urgency",
                    "Enrollment deadline pressure",
                    "low",
                    "A deadline can distract from checking the hostname letter by letter.",
                ),
            ],
            "Typosquatting / credential phishing",
            "Read the hostname from right to left and navigate to benefits through a saved trusted bookmark.",
        ),
        _scenario(
            "vendor-bank-change",
            "Supplier bank-detail change",
            "business_email_compromise",
            "email",
            "A. Morgan <alex@northstar-suppliers.example>",
            "alex-morgan@external-mail.example",
            "Updated remittance account",
            "Please use the new bank account on the attached invoice. I am travelling, so do not call the office; the change is effective today.",
            None,
            "Remittance_Update.xlsx",
            [
                F(
                    "reply_mismatch",
                    "Reply-to differs from the established supplier address",
                    "high",
                    "The reply address has an additional external-mail domain.",
                ),
                F(
                    "payment_request",
                    "Bank details changed by email",
                    "critical",
                    "Payment changes require independent verification using a known supplier contact.",
                ),
                F(
                    "urgency",
                    "Discourages verification",
                    "high",
                    "The request to avoid calling the office is a strong social-engineering signal.",
                ),
            ],
            "Business email compromise / payment diversion",
            "Pause payment changes and verify them with the supplier using a known telephone number.",
        ),
        _scenario(
            "routine-benefit",
            "Routine benefit-plan summary",
            "benign_message",
            "email",
            "Benefits Desk <updates@benefits.northstar.example>",
            None,
            "Monthly plan summary is ready",
            "Your monthly plan summary is available in the employee portal. Open the portal from your saved bookmark or company intranet. No action is required by email.",
            None,
            None,
            [
                F(
                    "routine_notice",
                    "No urgent request or unexpected credential prompt",
                    "low",
                    "The message asks the reader to open the known portal independently and requests no secret or payment.",
                )
            ],
            "Benign administrative notice (simulation)",
            "Check whether the message requests a risky action; safe messages can be handled through a trusted route.",
            "updates@benefits.northstar.example",
            "spf=pass; dkim=pass; dmarc=pass (SIMULATED)",
        ),
    ]
    for row in rows:
        row["action_rationales"] = _ACTION_TEXT
    return rows


def upgrade() -> None:
    op.create_table(
        "phishing_training_scenarios",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("slug", sa.String(80), nullable=False),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("category", sa.String(48), nullable=False),
        sa.Column("difficulty", sa.String(16), nullable=False),
        sa.Column("artifact_type", sa.String(16), nullable=False),
        sa.Column("sender", sa.String(320), nullable=False),
        sa.Column("reply_to", sa.String(320), nullable=True),
        sa.Column("subject", sa.String(240), nullable=False),
        sa.Column("received_at", sa.String(80), nullable=False),
        sa.Column("headers", sa.JSON(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("links", sa.JSON(), nullable=False),
        sa.Column("attachments", sa.JSON(), nullable=False),
        sa.Column("indicators", sa.JSON(), nullable=False),
        sa.Column("correct_decision", sa.String(16), nullable=False),
        sa.Column("attack_technique", sa.String(240), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("prevention", sa.Text(), nullable=False),
        sa.Column("correct_actions", sa.JSON(), nullable=False),
        sa.Column("action_rationales", sa.JSON(), nullable=False),
        sa.Column("objective", sa.String(500), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug", name="uq_phishing_training_scenarios_slug"),
    )
    op.create_index("ix_phishing_training_scenarios_slug", "phishing_training_scenarios", ["slug"])
    op.create_index(
        "ix_phishing_training_scenarios_category", "phishing_training_scenarios", ["category"]
    )

    op.create_table(
        "phishing_training_attempts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("scenario_id", sa.Uuid(), nullable=False),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("discovered_indicators", sa.JSON(), nullable=False),
        sa.Column("response_actions", sa.JSON(), nullable=False),
        sa.Column("elapsed_seconds", sa.Integer(), nullable=False),
        sa.Column("security_score", sa.Integer(), nullable=False),
        sa.Column("detection_accuracy", sa.Float(), nullable=False),
        sa.Column("indicator_score", sa.Float(), nullable=False),
        sa.Column("action_score", sa.Float(), nullable=False),
        sa.Column("indicators_missed", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["scenario_id"], ["phishing_training_scenarios.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_phishing_training_attempts_user_id", "phishing_training_attempts", ["user_id"]
    )
    op.create_index(
        "ix_phishing_training_attempts_scenario_id", "phishing_training_attempts", ["scenario_id"]
    )
    op.bulk_insert(
        sa.table(
            "phishing_training_scenarios",
            *[
                sa.Column("id", sa.Uuid()),
                sa.Column("slug", sa.String()),
                sa.Column("title", sa.String()),
                sa.Column("category", sa.String()),
                sa.Column("difficulty", sa.String()),
                sa.Column("artifact_type", sa.String()),
                sa.Column("sender", sa.String()),
                sa.Column("reply_to", sa.String()),
                sa.Column("subject", sa.String()),
                sa.Column("received_at", sa.String()),
                sa.Column("headers", sa.JSON()),
                sa.Column("body", sa.Text()),
                sa.Column("links", sa.JSON()),
                sa.Column("attachments", sa.JSON()),
                sa.Column("indicators", sa.JSON()),
                sa.Column("correct_decision", sa.String()),
                sa.Column("attack_technique", sa.String()),
                sa.Column("explanation", sa.Text()),
                sa.Column("prevention", sa.Text()),
                sa.Column("correct_actions", sa.JSON()),
                sa.Column("action_rationales", sa.JSON()),
                sa.Column("objective", sa.String()),
                sa.Column("is_active", sa.Boolean()),
                sa.Column("created_by", sa.Uuid()),
            ],
        ),
        [{"id": __import__("uuid").uuid4(), **row} for row in _seed_rows()],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_phishing_training_attempts_scenario_id", table_name="phishing_training_attempts"
    )
    op.drop_index("ix_phishing_training_attempts_user_id", table_name="phishing_training_attempts")
    op.drop_table("phishing_training_attempts")
    op.drop_index(
        "ix_phishing_training_scenarios_category", table_name="phishing_training_scenarios"
    )
    op.drop_index("ix_phishing_training_scenarios_slug", table_name="phishing_training_scenarios")
    op.drop_table("phishing_training_scenarios")
