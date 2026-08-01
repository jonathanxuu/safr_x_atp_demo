from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .constants import DEMO_PRINCIPALS


SHARED_DB_PATH = Path(
    os.getenv(
        "SHARED_DB_PATH",
        str(Path(__file__).resolve().parents[3] / "data" / "safr-atp-demo.sqlite"),
    )
)


@dataclass
class SkillToolSpec:
    tool_name: str
    input_ref: str
    output_ref: str
    args: dict[str, str]


class GovernedTransferSkill:
    """Deterministic transfer skill that forces the required planning tools."""

    def build_required_tools(self, payload: dict[str, Any]) -> list[SkillToolSpec]:
        recipient_id = str(payload.get("recipient_id", DEMO_PRINCIPALS["recipient"]))
        recipient_account_ref = str(payload.get("recipient_account_ref", ""))
        amount = str(payload.get("amount", "0"))
        currency = str(payload.get("currency", "USD"))
        policy = payload.get("policy") or {}

        auto_execute_below = float(policy.get("autoExecuteBelow", 1000))
        admin_review_at_or_above = float(policy.get("adminReviewAtOrAbove", 1000))
        allowed_currencies = [str(item) for item in policy.get("allowedCurrencies", ["USD"])]
        recipient_allowlist_required = bool(policy.get("recipientAllowlistRequired", True))
        amount_value = self._safe_amount(amount)
        recipient_allowlisted = self._is_allowlisted_recipient(recipient_id, recipient_account_ref)

        policy_decision = self._compute_policy_decision(
            amount_value=amount_value,
            currency=currency,
            allowed_currencies=allowed_currencies,
            recipient_allowlist_required=recipient_allowlist_required,
            recipient_allowlisted=recipient_allowlisted,
            auto_execute_below=auto_execute_below,
            admin_review_at_or_above=admin_review_at_or_above,
        )

        return [
            SkillToolSpec(
                tool_name="resolve_recipient",
                input_ref=recipient_id,
                output_ref=recipient_account_ref,
                args={
                    "recipient_id": recipient_id,
                    "recipient_account_ref": recipient_account_ref,
                    "allowlisted": str(recipient_allowlisted).lower(),
                },
            ),
            SkillToolSpec(
                tool_name="validate_transfer_policy",
                input_ref=f"{amount}|{currency}",
                output_ref=policy_decision,
                args={
                    "flow_id": str(payload.get("flow_id", "")),
                    "amount": amount,
                    "currency": currency,
                    "auto_execute_below": f"{auto_execute_below:.2f}",
                    "admin_review_at_or_above": f"{admin_review_at_or_above:.2f}",
                    "allowed_currencies": ",".join(allowed_currencies),
                    "recipient_allowlist_required": str(recipient_allowlist_required).lower(),
                    "recipient_allowlisted": str(recipient_allowlisted).lower(),
                    "policy_decision": policy_decision,
                },
            ),
        ]

    def summarize_required_steps(self, payload: dict[str, Any]) -> str:
        amount = str(payload.get("amount", "0"))
        currency = str(payload.get("currency", "USD"))
        recipient_account_ref = str(payload.get("recipient_account_ref", "recipient"))
        return (
            f"Resolve the selected recipient into a concrete account, then validate whether "
            f"{amount} {currency} to {recipient_account_ref} is auto-executable, requires admin review, "
            "or must be rejected by policy before verifier evaluation."
        )

    def build_fallback_reasoning(self, payload: dict[str, Any]) -> str:
        amount = str(payload.get("amount", "0"))
        currency = str(payload.get("currency", "USD"))
        return (
            f"Prepared a governed transfer plan for {amount} {currency} with two mandatory tools: "
            "Resolve Recipient and Validate Amount Against Policy."
        )

    def _compute_policy_decision(
        self,
        *,
        amount_value: float,
        currency: str,
        allowed_currencies: list[str],
        recipient_allowlist_required: bool,
        recipient_allowlisted: bool,
        auto_execute_below: float,
        admin_review_at_or_above: float,
    ) -> str:
        if currency not in allowed_currencies:
            return "policy_reject_currency_not_allowed"

        if recipient_allowlist_required and not recipient_allowlisted:
            return "policy_reject_recipient_not_allowlisted"

        if amount_value < auto_execute_below:
            return "auto_execute_allowed"

        if amount_value >= admin_review_at_or_above:
            return "admin_approval_required"

        return "policy_review_required"

    def _safe_amount(self, value: str) -> float:
        try:
            return float(value)
        except Exception:
            return 0.0

    def _is_allowlisted_recipient(self, recipient_id: str, recipient_account_ref: str) -> bool:
        if not recipient_id or not recipient_account_ref:
            return False

        try:
            with sqlite3.connect(SHARED_DB_PATH) as connection:
                row = connection.execute(
                    """
                    SELECT owner_id, owner_role
                    FROM bank_accounts
                    WHERE account_id = ?
                    """,
                    (recipient_account_ref,),
                ).fetchone()
        except Exception:
            return False

        if not row:
            return False

        owner_id, owner_role = row
        return owner_id == recipient_id and owner_role == "recipient"
