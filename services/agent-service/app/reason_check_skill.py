from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


@dataclass
class ReasonCheckReport:
    verdict: str
    recommended_outcome: str
    confidence: float
    summary: str
    findings: list[str]
    logic_checks: list[dict[str, str]]
    observed_signals: list[str]
    model_note: str
    review_prompt: str | None = None
    fallback_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "verdict": self.verdict,
            "recommended_outcome": self.recommended_outcome,
            "summary": self.summary,
            "findings": self.findings,
            "logic_checks": self.logic_checks,
            "observed_signals": self.observed_signals,
            "model_note": self.model_note,
        }
        if self.review_prompt:
            payload["review_prompt"] = self.review_prompt
        if self.fallback_reason:
            payload["fallback_reason"] = self.fallback_reason
        return payload


class ReasonCheckSkill:
    """Lightweight reasoning review helper for the verifier review loop."""

    FOUR_OUTCOMES = ("auto_execute", "escalate", "deny", "observe")

    def build_review_prompt(self, payload: dict[str, Any]) -> str:
        amount = str(payload.get("amount") or payload.get("requested_amount") or "0")
        currency = str(payload.get("currency") or payload.get("requested_currency") or "USD")
        recipient_account_ref = str(payload.get("recipient_account_ref") or "unknown")
        signed_payload = str(payload.get("signed_payload") or payload.get("signed_payload_c14n") or "")
        reasoning = str(payload.get("reasoning") or payload.get("reasoning_summary") or "No reasoning provided.")
        final_result = str(payload.get("final_result") or payload.get("policy_decision") or "observe")
        policy_decision = str(payload.get("policy_decision") or final_result or "observe")
        prompt_preview = str(payload.get("prompt_preview") or "")
        input_payload = str(payload.get("input_payload") or "")
        reasoning_notes = payload.get("reasoning_notes") if isinstance(payload.get("reasoning_notes"), list) else []
        logic_checks = payload.get("logic_checks") if isinstance(payload.get("logic_checks"), list) else []
        tool_calls = payload.get("tool_calls") if isinstance(payload.get("tool_calls"), list) else []
        context_metadata = payload.get("context_metadata") if isinstance(payload.get("context_metadata"), dict) else {}
        review_phase = str(context_metadata.get("review_phase") or "initial_verification")
        is_post_admin_reverification = review_phase == "post_admin_signature_reverify"
        task_instruction = (
            "This is a post-administrator-signature re-verification. Confirm that the original packet remains valid and that the validated administrator approval is bound to this exact escalation. Decide only whether execution may proceed, must be denied, or may proceed under observation. Do not request another escalation."
            if is_post_admin_reverification
            else "Your task is to decide whether the transfer can move forward as requested, must pause for escalation, must be denied, or should be allowed to proceed under observation."
        )
        escalate_definition = (
            "- escalate: not permitted in this post-administrator-signature re-verification"
            if is_post_admin_reverification
            else "- escalate: the transfer is not allowed to continue automatically and requires admin approval"
        )
        outcome_requirement = (
            "- recommended_outcome must be one of: auto_execute, deny, observe"
            if is_post_admin_reverification
            else f"- recommended_outcome must be one of: {', '.join(self.FOUR_OUTCOMES)}"
        )

        if signed_payload.strip():
            signed_payload_excerpt = signed_payload[:4000]
            return (
                "You are the verifier for a governed transfer in the SAFR x ATP flow.\n"
                "\n"
                "Your role is to review the signed transfer packet and produce the verifier's decision record for product, operations, and audit use.\n"
                "\n"
                "You are not the transfer planner.\n"
                "You are not the bank executor.\n"
                "Do not restate the transfer agent's prompt.\n"
                "Do not invent new facts outside the signed packet and attached evidence.\n"
                "\n"
                "Review the transfer using the signed artifacts as the source of truth:\n"
                "1. the signed instruction from the principal\n"
                "2. the pinned policy snapshot and policy constraints\n"
                "3. the signed proposal / actual tool intent from the agent\n"
                "4. the tool trace, resolved recipient data, and other attached evidence\n"
                "5. the declared transfer-side outcome and reasoning, only as supporting context\n"
                "\n"
                f"{task_instruction}\n"
                "\n"
                "Decision meanings:\n"
                "- auto_execute: the transfer is consistent, policy-valid, and may continue automatically\n"
                f"{escalate_definition}\n"
                "- deny: the transfer is invalid or unsupported and must not proceed\n"
                "- observe: the transfer may proceed, but the verifier wants it explicitly flagged for follow-up, anomaly monitoring, or post-run review\n"
                "\n"
                "Review rules:\n"
                "- Treat the signed packet and verifier inputs as the source of truth\n"
                "- Prefer evidence over natural-language reasoning\n"
                "- If reasoning and evidence disagree, trust the evidence\n"
                "- If the declared outcome is unsupported by the signed artifacts or policy facts, do not preserve it\n"
                "- Be concise, operational, and audit-friendly\n"
                "- Do not claim execution already happened unless execution evidence is present\n"
                "\n"
                "Return strict JSON only with these keys:\n"
                "verdict, recommended_outcome, summary, findings, logic_checks, observed_signals, model_note\n"
                "\n"
                "Output requirements:\n"
                "- verdict must be one of: pass, observe, fail\n"
                f"{outcome_requirement}\n"
                "- summary should read like a product-facing verifier conclusion\n"
                "- findings should list the most decision-relevant facts or gaps\n"
                "- logic_checks should describe the specific checks performed and whether each passed\n"
                "- observed_signals should capture risk or governance signals worth surfacing\n"
                "- model_note should briefly state whether this was ADK review or deterministic fallback\n\n"
                f"Transfer amount: {amount} {currency}\n"
                f"Recipient account reference: {recipient_account_ref}\n"
                f"Signed payload excerpt: {signed_payload_excerpt}\n"
                f"Input payload: {input_payload or 'No input payload provided'}\n"
                f"Reasoning: {reasoning}\n"
                f"Policy decision: {policy_decision}\n"
                f"Review phase: {review_phase}\n"
                f"Prompt preview: {prompt_preview or 'No prompt preview provided'}\n"
                f"Reasoning notes: {reasoning_notes}\n"
                f"Logic checks: {logic_checks}\n"
                f"Tool calls: {tool_calls}\n"
            )

        return (
            "You are the verifier for a governed transfer in the SAFR x ATP flow.\n"
            "\n"
            "Your role is to review the signed transfer packet and produce the verifier's decision record for product, operations, and audit use.\n"
            "\n"
            "You are not the transfer planner.\n"
            "You are not the bank executor.\n"
            "Do not restate the transfer agent's prompt.\n"
            "Do not invent new facts outside the signed packet and attached evidence.\n"
            "\n"
            "Review the transfer using the signed artifacts as the source of truth:\n"
            "1. the signed instruction from the principal\n"
            "2. the pinned policy snapshot and policy constraints\n"
            "3. the signed proposal / actual tool intent from the agent\n"
            "4. the tool trace, resolved recipient data, and other attached evidence\n"
            "5. the declared transfer-side outcome and reasoning, only as supporting context\n"
            "\n"
            f"{task_instruction}\n"
            "\n"
            "Decision meanings:\n"
            "- auto_execute: the transfer is consistent, policy-valid, and may continue automatically\n"
            f"{escalate_definition}\n"
            "- deny: the transfer is invalid or unsupported and must not proceed\n"
            "- observe: the transfer may proceed, but the verifier wants it explicitly flagged for follow-up, anomaly monitoring, or post-run review\n"
            "\n"
            "Review rules:\n"
            "- Treat the signed packet and verifier inputs as the source of truth\n"
            "- Prefer evidence over natural-language reasoning\n"
            "- If reasoning and evidence disagree, trust the evidence\n"
            "- If the declared outcome is unsupported by the signed artifacts or policy facts, do not preserve it\n"
            "- Be concise, operational, and audit-friendly\n"
            "- Do not claim execution already happened unless execution evidence is present\n"
            "\n"
            "Return strict JSON only with these keys:\n"
            "verdict, recommended_outcome, summary, findings, logic_checks, observed_signals, model_note\n"
            "\n"
            "Output requirements:\n"
            "- verdict must be one of: pass, observe, fail\n"
            f"{outcome_requirement}\n"
            "- summary should read like a product-facing verifier conclusion\n"
            "- findings should list the most decision-relevant facts or gaps\n"
            "- logic_checks should describe the specific checks performed and whether each passed\n"
            "- observed_signals should capture risk or governance signals worth surfacing\n"
            "- model_note should briefly state whether this was ADK review or deterministic fallback\n\n"
            f"Transfer amount: {amount} {currency}\n"
            f"Recipient account reference: {recipient_account_ref}\n"
            f"Prompt preview: {prompt_preview or 'No prompt preview provided'}\n"
            f"Input payload: {input_payload or 'No input payload provided'}\n"
            f"Reasoning: {reasoning}\n"
            f"Policy decision: {policy_decision}\n"
            f"Review phase: {review_phase}\n"
            f"Reasoning notes: {reasoning_notes}\n"
            f"Logic checks: {logic_checks}\n"
            f"Tool calls: {tool_calls}\n"
        )

    def review(self, payload: dict[str, Any], fallback_reason: str | None = None) -> ReasonCheckReport:
        policy_decision = str(payload.get("policy_decision") or payload.get("final_result") or "")
        final_result = str(payload.get("final_result") or policy_decision or "observe")
        reasoning = str(payload.get("reasoning") or payload.get("reasoning_summary") or "")
        prompt_text = str(payload.get("prompt_text") or "")
        prompt_preview = str(payload.get("prompt_preview") or "")
        amount = self._as_float(payload.get("amount") or payload.get("requested_amount"), 0.0)
        currency = str(payload.get("currency") or payload.get("requested_currency") or "USD")
        tool_calls = payload.get("tool_calls") if isinstance(payload.get("tool_calls"), list) else []
        context_metadata = payload.get("context_metadata") if isinstance(payload.get("context_metadata"), dict) else {}
        policy = payload.get("policy") if isinstance(payload.get("policy"), dict) else {}
        control_bundle_v = str(payload.get("control_bundle_v") or payload.get("bundle_version") or "")
        has_signed_payload = bool(str(payload.get("signed_payload") or payload.get("signed_payload_c14n") or "").strip())

        if has_signed_payload:
            logic_checks = [
                self._check_signed_payload(payload),
                self._check_reasoning_present(reasoning),
                self._check_tool_count(tool_calls),
                self._check_context_keys(context_metadata, control_bundle_v),
            ]
        else:
            logic_checks = [
                self._check_contains(prompt_text, "amount", "Prompt references the transfer amount"),
                self._check_contains(prompt_text, "recipient", "Prompt references the recipient"),
                self._check_reasoning_present(reasoning),
                self._check_tool_count(tool_calls),
                self._check_context_keys(context_metadata, control_bundle_v),
            ]

        signal_text = " ".join(
            [
                prompt_text,
                prompt_preview,
                reasoning,
                str(policy_decision),
                str(final_result),
            ]
        ).lower()
        observed_signals = [
            signal
            for signal in [
                "policy",
                "recipient",
                "amount",
                "admin",
                "reverify",
                "execute",
            ]
            if signal in signal_text
        ]

        policy_outcome = self._infer_outcome(policy_decision, policy, final_result, amount=amount, currency=currency)
        confidence = self._compute_confidence(logic_checks, policy_outcome, reasoning)
        verdict = "pass" if confidence >= 0.72 else "observe" if confidence >= 0.4 else "fail"
        summary = self._build_summary(policy_outcome, confidence, logic_checks)
        findings = [
            check["detail"]
            for check in logic_checks
            if check["status"] != "pass"
        ]
        if not findings:
            findings = [f"Reasoning aligns with the requested {policy_outcome} disposition."]

        return ReasonCheckReport(
            verdict=verdict,
            recommended_outcome=policy_outcome,
            confidence=confidence,
            summary=summary,
            findings=findings,
            logic_checks=logic_checks,
            observed_signals=observed_signals,
            model_note=(
                "Model review preferred; deterministic fallback used"
                if fallback_reason
                else "Model review preferred"
            ),
            review_prompt=self.build_review_prompt(payload),
            fallback_reason=fallback_reason,
        )

    def _infer_outcome(
        self,
        policy_decision: str,
        policy: dict[str, Any],
        final_result: str,
        *,
        amount: float,
        currency: str,
    ) -> str:
        normalized = self._normalize_outcome(final_result or policy_decision)
        if normalized in self.FOUR_OUTCOMES:
            return normalized

        if policy_decision.startswith("policy_reject_"):
            return "deny"

        auto_execute_below = self._as_float(policy.get("autoExecuteBelow"), 1000.0)
        admin_review_at_or_above = self._as_float(policy.get("adminReviewAtOrAbove"), 1000.0)

        if amount < auto_execute_below:
            return "auto_execute"
        if amount >= admin_review_at_or_above:
            return "escalate"
        return "observe"

    def _compute_confidence(
        self,
        logic_checks: list[dict[str, str]],
        policy_outcome: str,
        reasoning: str,
    ) -> float:
        passed = sum(1 for check in logic_checks if check["status"] == "pass")
        total = max(len(logic_checks), 1)
        confidence = passed / total

        if policy_outcome in {"auto_execute", "escalate"} and reasoning.strip():
            confidence += 0.08
        if policy_outcome == "deny":
            confidence += 0.05

        return max(0.0, min(confidence, 0.99))

    def _build_summary(self, policy_outcome: str, confidence: float, logic_checks: list[dict[str, str]]) -> str:
        failures = [check["name"] for check in logic_checks if check["status"] != "pass"]
        if failures:
            return (
                f"Reasoning points to {policy_outcome}, but some signals need manual attention: "
                + ", ".join(failures)
            )
        return f"Reasoning is consistent with {policy_outcome} at confidence {confidence:.2f}."

    def _check_contains(self, value: str, needle: str, label: str) -> dict[str, str]:
        if not value.strip():
            return {"name": label, "status": "warn", "detail": f"{label} is missing"}
        if re.search(rf"\b{re.escape(needle)}\b", value, flags=re.IGNORECASE):
            return {"name": label, "status": "pass", "detail": f"{label} is present"}
        return {"name": label, "status": "warn", "detail": f"{label} is not explicit"}

    def _check_signed_payload(self, payload: dict[str, Any]) -> dict[str, str]:
        signed_payload = str(payload.get("signed_payload") or payload.get("signed_payload_c14n") or "").strip()
        if not signed_payload:
            return {"name": "Signed payload", "status": "warn", "detail": "Signed payload is missing"}
        try:
            parsed = json.loads(signed_payload)
        except Exception:
            return {"name": "Signed payload", "status": "warn", "detail": "Signed payload is not valid JSON"}

        if not isinstance(parsed, dict):
            return {"name": "Signed payload", "status": "warn", "detail": "Signed payload is not an object"}

        analysis = parsed.get("analysis") if isinstance(parsed.get("analysis"), dict) else {}
        has_reasoning = bool(
            str(
                parsed.get("reasoning")
                or parsed.get("reasoning_summary")
                or analysis.get("reasoning")
                or analysis.get("reasoning_summary")
                or ""
            ).strip()
        )
        has_final_result = bool(
            str(
                parsed.get("final_result")
                or parsed.get("policy_decision")
                or analysis.get("final_result")
                or analysis.get("policy_decision")
                or ""
            ).strip()
        )
        has_analysis = bool(analysis)
        if has_reasoning and has_final_result:
            if has_analysis:
                return {"name": "Signed payload", "status": "pass", "detail": "Signed payload includes reasoning and declared outcome"}
            return {"name": "Signed payload", "status": "pass", "detail": "Signed payload includes reasoning and declared outcome"}
        return {
            "name": "Signed payload",
            "status": "warn",
            "detail": "Signed payload is present but missing reasoning or declared outcome",
        }

    def _check_tool_count(self, tool_calls: list[Any]) -> dict[str, str]:
        if len(tool_calls) >= 2:
            return {"name": "Tool trace", "status": "pass", "detail": "Required tool trace is present"}
        return {"name": "Tool trace", "status": "warn", "detail": "Tool trace is incomplete"}

    def _check_reasoning_present(self, reasoning: str) -> dict[str, str]:
        if reasoning.strip():
            return {"name": "Reasoning", "status": "pass", "detail": "Reasoning is present"}
        return {"name": "Reasoning", "status": "warn", "detail": "Reasoning is missing"}

    def _check_context_keys(self, context_metadata: dict[str, Any], control_bundle_v: str = "") -> dict[str, str]:
        required_keys = {"current_account_state", "policy_constraints"}
        missing = sorted(key for key in required_keys if key not in context_metadata)
        if control_bundle_v.strip() and not missing:
            return {"name": "Context metadata", "status": "pass", "detail": "Context metadata is complete"}
        if not control_bundle_v.strip() and not missing:
            return {"name": "Context metadata", "status": "warn", "detail": "Control bundle version is missing"}
        if control_bundle_v.strip() and missing:
            return {"name": "Context metadata", "status": "warn", "detail": f"Missing context keys: {', '.join(missing)}"}
        return {"name": "Context metadata", "status": "warn", "detail": f"Missing context keys: {', '.join(missing) if missing else 'control_bundle_v'}"}

    def _normalize_outcome(self, value: str) -> str:
        normalized = value.strip().lower().replace("-", "_")
        aliases = {
            "approved_auto_execute": "auto_execute",
            "auto_execute_allowed": "auto_execute",
            "approved_pending_admin_signature": "escalate",
            "admin_approval_required": "escalate",
            "policy_review_required": "observe",
            "reject": "deny",
            "rejected": "deny",
            "deny": "deny",
            "observe": "observe",
        }
        return aliases.get(normalized, normalized)

    def _as_float(self, value: Any, fallback: float) -> float:
        try:
            parsed = float(value)
        except Exception:
            return fallback
        return parsed if parsed == parsed else fallback
