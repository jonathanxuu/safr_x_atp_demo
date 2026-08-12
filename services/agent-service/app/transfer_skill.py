from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx

from .constants import DEMO_PRINCIPALS


VERIFIER_SERVICE_URL = os.getenv("VERIFIER_SERVICE_URL", "http://localhost:4103")


@dataclass
class SkillToolSpec:
    tool_name: str
    input_ref: str
    output_ref: str
    args: dict[str, str]


class GovernedTransferSkill:
    """Deterministic transfer skill that forces the required planning tools."""

    def build_prompt_text(self, payload: dict[str, Any]) -> str:
        amount = str(payload.get("amount", "0"))
        currency = str(payload.get("currency", "USD"))
        recipient_id = str(payload.get("recipient_id", DEMO_PRINCIPALS["recipient"]))
        recipient_account_ref = str(payload.get("recipient_account_ref", ""))
        memo = str(payload.get("memo", "")).strip() or "No memo provided"
        policy = payload.get("policy") or {}
        auto_execute_below = float(policy.get("autoExecuteBelow", 1000))
        admin_review_at_or_above = float(policy.get("adminReviewAtOrAbove", 1000))
        allowed_currencies = ", ".join(str(item) for item in policy.get("allowedCurrencies", ["USD"]))
        recipient_allowlist_required = bool(policy.get("recipientAllowlistRequired", True))

        return (
            "You are a financial transfer orchestration agent for the SAFR x ATP governance demo.\n"
            "Review the transfer request below and prepare the next operational step for the transfer.\n"
            "Do not emit a verdict or final disposition. Verifier review must still happen before bank execution.\n"
            "Return strict JSON only.\n\n"
            f"Transfer amount: {amount} {currency}\n"
            f"Recipient principal: {recipient_id}\n"
            f"Recipient account reference: {recipient_account_ref or 'not provided'}\n"
            f"Memo: {memo}\n"
            f"Auto-execute below: {auto_execute_below:.2f} {currency}\n"
            f"Admin review at or above: {admin_review_at_or_above:.2f} {currency}\n"
            f"Allowed currencies: {allowed_currencies}\n"
            f"Recipient allowlist required: {str(recipient_allowlist_required).lower()}\n\n"
            "The transfer skill must always run these tools in order:\n"
            "1. resolve_recipient\n"
            "2. check_recipient_allowlist\n"
            "3. validate_transfer_policy\n"
            "Use the tool results and policy context to write a detailed reasoning, next_step, and logic_checks."
        )

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
        recipient_allowlisted = self.check_recipient_allowlist(recipient_id, recipient_account_ref)

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
                tool_name="check_recipient_allowlist",
                input_ref=recipient_id,
                output_ref=str(recipient_allowlisted).lower(),
                args={
                    "recipient_id": recipient_id,
                    "recipient_account_ref": recipient_account_ref,
                    "allowlisted": str(recipient_allowlisted).lower(),
                    "allowlist_source": "verifier.recipient-allowlist",
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
        recipient_id = str(payload.get("recipient_id", DEMO_PRINCIPALS["recipient"]))
        recipient_account_ref = str(payload.get("recipient_account_ref", "unknown"))
        policy = payload.get("policy") or {}
        auto_execute_below = float(policy.get("autoExecuteBelow", 1000))
        admin_review_at_or_above = float(policy.get("adminReviewAtOrAbove", 1000))
        allowed_currencies = ", ".join(str(item) for item in policy.get("allowedCurrencies", ["USD"]))
        allowlist_required = "required" if bool(policy.get("recipientAllowlistRequired", True)) else "optional"
        return (
            f"Prepared a governed transfer plan for {amount} {currency} from the transfer-side agent. "
            f"The instruction was interpreted for recipient principal {recipient_id} and mapped to account {recipient_account_ref}. "
            "The plan must resolve the recipient first, confirm the recipient is on the allowlist, and then validate the amount "
            "against the active policy before any verifier handoff. "
            f"For this request, the auto-execute threshold is {auto_execute_below:.2f} {currency}, the admin-review threshold is "
            f"{admin_review_at_or_above:.2f} {currency}, the allowed currencies are {allowed_currencies}, and recipient allowlist "
            f"checking is {allowlist_required}. "
            "The next step should explain whether the signed instruction is ready to hand to the verifier or whether the transfer "
            "needs the recipient or currency adjusted first."
        )

    def build_next_step(self, payload: dict[str, Any]) -> str:
        policy_decision = self._policy_decision_for_payload(payload)
        mapping = {
            "auto_execute_allowed": "Submit the signed governance envelope to the verifier for reasoning and policy verification.",
            "admin_approval_required": "Submit the signed governance envelope to the verifier for reasoning and policy verification; the verifier will issue the escalation decision if required.",
            "policy_review_required": "Submit the signed governance envelope to the verifier for reasoning and policy verification.",
            "policy_reject_currency_not_allowed": "Select a currency that is allowed by policy, then resubmit.",
            "policy_reject_recipient_not_allowlisted": "Select an allowlisted recipient account, then resubmit.",
        }
        return mapping.get(policy_decision, "Prepare the signed instruction for verifier review.")

    def _policy_decision_for_payload(self, payload: dict[str, Any]) -> str:
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
        recipient_allowlisted = self.check_recipient_allowlist(recipient_id, recipient_account_ref)

        return self._compute_policy_decision(
            amount_value=amount_value,
            currency=currency,
            allowed_currencies=allowed_currencies,
            recipient_allowlist_required=recipient_allowlist_required,
            recipient_allowlisted=recipient_allowlisted,
            auto_execute_below=auto_execute_below,
            admin_review_at_or_above=admin_review_at_or_above,
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

    def check_recipient_allowlist(self, recipient_id: str, recipient_account_ref: str) -> bool:
        if not recipient_id or not recipient_account_ref:
            return False

        try:
            response = httpx.get(
                f"{VERIFIER_SERVICE_URL}/verifier/recipient-allowlist",
                params={"principalId": recipient_id},
                timeout=10.0,
            )
            response.raise_for_status()
            body = response.json()
        except Exception:
            return False

        allowed_accounts = body.get("allowedRecipientAccountRefs")
        if not isinstance(allowed_accounts, list):
            return False

        return recipient_account_ref in {str(account_id) for account_id in allowed_accounts}
