from __future__ import annotations

import ast
import json
import os
import re
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "").lower() == "true":
    # Force local ADK runs onto Vertex AI even when the parent shell exports API keys.
    os.environ.pop("GEMINI_API_KEY", None)
    os.environ.pop("GOOGLE_API_KEY", None)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from google.adk.agents import Agent
from google.adk.agents.run_config import RunConfig, StreamingMode
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from .constants import DEMO_AGENT_IDS, DEMO_PRINCIPALS
from .reason_check_skill import ReasonCheckReport, ReasonCheckSkill
from .transfer_skill import GovernedTransferSkill


MODEL_NAME = os.getenv("GOOGLE_ADK_MODEL", "gemini-2.5-flash-lite")
AGENT_MODE = os.getenv("AGENT_EXECUTION_MODE", "adk")
KEY_DIR = Path(os.getenv("AGENT_KEY_DIR", Path(__file__).resolve().parent.parent / "keys"))
PRIVATE_KEY_PATH = Path(os.getenv("AGENT_PRIVATE_KEY_PATH", KEY_DIR / "agent_ed25519_private.pem"))
PUBLIC_KEY_PATH = Path(os.getenv("AGENT_PUBLIC_KEY_PATH", KEY_DIR / "agent_ed25519_public.pem"))
AGENT_KEY_ID = os.getenv("AGENT_KEY_ID", "ag_transfer_01#ed25519#v1")
AGENT_PRINCIPAL = os.getenv("AGENT_PRINCIPAL", DEMO_PRINCIPALS["agent"])
SHARED_DB_PATH = Path(
    os.getenv(
        "SHARED_DB_PATH",
        str(Path(__file__).resolve().parents[3] / "data" / "safr-atp-demo.sqlite"),
    )
)


@dataclass
class AgentPlan:
    mode: str
    reasoning: str
    next_step: str
    policy_decision: str
    tool_calls: list[dict[str, Any]]
    context_metadata: dict[str, Any]
    control_bundle_v: str
    started_at: str
    completed_at: str
    duration_ms: int
    prompt_text: str
    prompt_preview: str
    input_payload: str
    skill_name: str
    mandatory_tools: list[str]
    logic_checks: list[dict[str, str]]
    fallback_reason: str | None = None


root_agent = Agent(
    name="safr_transfer_agent",
    model=MODEL_NAME,
    instruction="""
You are a financial transfer orchestration agent for a SAFR x ATP governance demo.

You receive a transfer instruction payload and must return strict JSON only.
Your JSON should contain:
- reasoning: a detailed natural-language explanation of the governed transfer plan and the checks that led to it
- next_step: the next operational step for the transfer-side agent
- logic_checks: a short list of key checks that informed the outcome

Rules:
- The transfer skill always runs three mandatory tools in this order:
  1. resolve_recipient
  2. check_recipient_allowlist
  3. validate_transfer_policy
- Do not invent or remove tools from that fixed skill.
- The mandatory tools have already completed by the time you write next_step. For a policy-valid request, next_step must say to submit the signed governance envelope to the verifier for reasoning and policy verification; never instruct the caller to run resolve_recipient, check_recipient_allowlist, or validate_transfer_policy again.
- Never claim execution has happened.
- Never skip verifier. Verifier must happen before bank execution.
- Use flow_id / flowId terminology consistently. Do not invent transfer_id.
- Output valid JSON only with no markdown fences.
""".strip(),
)


class AdkTransferPlanner:
    def __init__(self) -> None:
        self.mode = AGENT_MODE
        self.session_service = InMemorySessionService()
        self.runner = Runner(agent=root_agent, session_service=self.session_service, app_name="safr_atp_demo")
        self.review_runner = Runner(agent=self._build_reason_check_agent(), session_service=self.session_service, app_name="safr_atp_demo_reason_check")
        self.signer = AgentSigner()
        self.transfer_skill = GovernedTransferSkill()
        self.reason_check_skill = ReasonCheckSkill()

    def plan_transfer(self, payload: dict[str, Any]) -> AgentPlan:
        started_at = utc_now_iso()
        if self.mode != "adk":
            return self._deterministic_plan(payload, started_at=started_at)

        try:
            return self._run_adk_plan(payload, started_at=started_at)
        except Exception as error:
            return self._deterministic_plan(payload, started_at=started_at, fallback_reason=str(error))

    def review_reasoning(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.mode != "adk":
            return self.reason_check_skill.review(payload, fallback_reason="agent mode not set to adk").as_dict()

        try:
            return self._run_adk_reason_check(payload)
        except Exception as error:
            return self.reason_check_skill.review(payload, fallback_reason=str(error)).as_dict()

    def _next_step_after_completed_tools(self, payload: dict[str, Any]) -> str:
        """Keep the displayed handoff aligned with the completed agent orchestration."""
        policy_decision = self._policy_decision_for_payload(payload)
        if policy_decision.startswith("policy_reject_"):
            return self.transfer_skill.build_next_step(payload)
        return "Submit the signed governance envelope to the verifier for reasoning and policy verification."

    def _run_adk_plan(self, payload: dict[str, Any], *, started_at: str) -> AgentPlan:
        session = self.session_service.create_session_sync(
            app_name="safr_atp_demo",
            user_id=str(payload.get("principal_id", DEMO_PRINCIPALS["transferor"])),
            session_id=f"session_{uuid.uuid4().hex}",
        )
        prompt = self.transfer_skill.build_prompt_text(payload)
        input_payload = json.dumps(payload, ensure_ascii=True)
        message = types.Content(role="user", parts=[types.Part.from_text(text=prompt)])
        events = list(
            self.runner.run(
                user_id=str(payload.get("principal_id", DEMO_PRINCIPALS["transferor"])),
                session_id=session.id,
                new_message=message,
                run_config=RunConfig(streaming_mode=StreamingMode.NONE),
            )
        )

        text_parts: list[str] = []
        for event in events:
            if event.content and event.content.parts:
                for part in event.content.parts:
                    if getattr(part, "text", None):
                        text_parts.append(part.text)

        if not text_parts:
            raise ValueError("ADK agent returned no text output")

        last_text = self._best_adk_text_candidate(text_parts)
        parsed: dict[str, Any] = {}
        try:
            parsed = self._parse_adk_json(last_text)
            nested = self._parse_structured_candidate(parsed.get("reasoning")) if isinstance(parsed, dict) else None
            if isinstance(nested, dict):
                reasoning = self._to_text(
                    nested.get("reasoning"),
                    nested.get("reasoning_summary"),
                    parsed.get("reasoning_summary") if isinstance(parsed, dict) else None,
                    self.transfer_skill.build_fallback_reasoning(payload),
                )
                next_step = self._next_step_after_completed_tools(payload)
                logic_checks = self._to_logic_checks(
                    nested.get("logic_checks"),
                    parsed.get("logic_checks") if isinstance(parsed, dict) else None,
                )
            else:
                reasoning = self._to_text(
                    parsed.get("reasoning") if isinstance(parsed, dict) else None,
                    parsed.get("reasoning_summary") if isinstance(parsed, dict) else None,
                    self.transfer_skill.build_fallback_reasoning(payload),
                )
                next_step = self._next_step_after_completed_tools(payload)
                logic_checks = self._to_logic_checks(parsed.get("logic_checks") if isinstance(parsed, dict) else None)
        except json.JSONDecodeError:
            reasoning = last_text.strip() or self.transfer_skill.build_fallback_reasoning(payload)
            next_step = self._next_step_after_completed_tools(payload)
            logic_checks = []

        completed_at = utc_now_iso()
        return AgentPlan(
            mode="adk",
            reasoning=reasoning,
            next_step=next_step,
            policy_decision=self._policy_decision_for_payload(payload),
            tool_calls=self._build_required_tool_calls(payload),
            context_metadata=dict(parsed.get("context_metadata", {})) if isinstance(parsed, dict) else {},
            control_bundle_v=self._to_text(
                parsed.get("control_bundle_v") if isinstance(parsed, dict) else None,
                "bundle_demo_finance_001@1.0.0",
            ),
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms_between(started_at, completed_at),
            prompt_text=prompt,
            prompt_preview=self.transfer_skill.summarize_required_steps(payload),
            input_payload=input_payload,
            skill_name="governed_transfer_skill_v1",
            mandatory_tools=["resolve_recipient", "check_recipient_allowlist", "validate_transfer_policy"],
            logic_checks=logic_checks,
        )

    def _deterministic_plan(
        self,
        payload: dict[str, Any],
        *,
        started_at: str,
        fallback_reason: str | None = None,
    ) -> AgentPlan:
        amount = str(payload.get("amount", "0"))
        currency = str(payload.get("currency", "USD"))
        recipient_id = str(payload.get("recipient_id", DEMO_PRINCIPALS["recipient"]))
        completed_at = utc_now_iso()
        prompt = self.transfer_skill.build_prompt_text(payload)
        input_payload = json.dumps(payload, ensure_ascii=True)
        policy_decision = self._policy_decision_for_payload(payload)
        next_step = self._next_step_after_completed_tools(payload)

        return AgentPlan(
            mode="deterministic",
            reasoning=self.transfer_skill.build_fallback_reasoning(payload),
            next_step=next_step,
            policy_decision=policy_decision,
            tool_calls=self._build_required_tool_calls(payload),
            context_metadata={
                "agent_id": str(payload.get("agent_id", DEMO_AGENT_IDS["transfer"])),
                "principal_id": str(payload.get("principal_id", DEMO_PRINCIPALS["transferor"])),
                "recipient_id": recipient_id,
                "mandate_id": "mandate_demo_001",
                "requested_amount": amount,
                "requested_currency": currency,
            },
            control_bundle_v="bundle_demo_finance_001@1.0.0",
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms_between(started_at, completed_at),
            prompt_text=prompt,
            prompt_preview=self.transfer_skill.summarize_required_steps(payload),
            input_payload=input_payload,
            skill_name="governed_transfer_skill_v1",
            mandatory_tools=["resolve_recipient", "check_recipient_allowlist", "validate_transfer_policy"],
            logic_checks=[
                {"name": "policy_decision", "status": "pass", "detail": policy_decision},
            ],
            fallback_reason=fallback_reason,
        )

    def _run_adk_reason_check(self, payload: dict[str, Any]) -> dict[str, Any]:
        session = self.session_service.create_session_sync(
            app_name="safr_atp_demo_reason_check",
            user_id=str(payload.get("principal_id", DEMO_PRINCIPALS["transferor"])),
            session_id=f"review_{uuid.uuid4().hex}",
        )
        prompt = self.reason_check_skill.build_review_prompt(payload)
        message = types.Content(role="user", parts=[types.Part.from_text(text=prompt)])
        events = list(
            self.review_runner.run(
                user_id=str(payload.get("principal_id", DEMO_PRINCIPALS["transferor"])),
                session_id=session.id,
                new_message=message,
                run_config=RunConfig(streaming_mode=StreamingMode.NONE),
            )
        )

        text_parts: list[str] = []
        for event in events:
            if event.content and event.content.parts:
                for part in event.content.parts:
                    if getattr(part, "text", None):
                        text_parts.append(part.text)

        if not text_parts:
            raise ValueError("Reason check agent returned no text output")

        last_text = self._best_adk_text_candidate(text_parts)
        try:
            parsed = self._parse_adk_json(last_text)
            parsed_review = parsed.get("review") if isinstance(parsed.get("review"), dict) else parsed
            if not isinstance(parsed_review, dict):
                parsed_review = parsed if isinstance(parsed, dict) else {}
            parsed_payload = payload if isinstance(payload, dict) else {}
            report = self.reason_check_skill.review(
                {
                    **parsed_payload,
                    "reasoning": self._to_text(
                        parsed_payload.get("reasoning"),
                        parsed_payload.get("reasoning_summary"),
                        "",
                    ),
                    "reasoning_summary": self._to_text(
                        parsed_payload.get("reasoning_summary"),
                        parsed_payload.get("reasoning"),
                        "",
                    ),
                    "final_result": self._to_text(
                        parsed_payload.get("final_result"),
                        parsed_payload.get("policy_decision"),
                        "",
                    ),
                    "policy_decision": self._to_text(
                        parsed_payload.get("policy_decision"),
                        parsed_payload.get("final_result"),
                        "",
                    ),
                }
            ).as_dict()
            if isinstance(parsed_review, dict):
                report.update(
                    {
                        "verdict": str(parsed_review.get("verdict", report["verdict"])),
                        "recommended_outcome": str(
                            parsed_review.get("recommended_outcome", report["recommended_outcome"])
                        ),
                        "summary": str(parsed_review.get("summary", report["summary"])),
                        "findings": parsed_review.get("findings", report["findings"]),
                        "logic_checks": parsed_review.get("logic_checks", report["logic_checks"]),
                        "observed_signals": parsed_review.get("observed_signals", report["observed_signals"]),
                        "model_note": str(parsed_review.get("model_note", report["model_note"])),
                    }
                )
            return report
        except Exception as error:
            return self.reason_check_skill.review(payload, fallback_reason=str(error)).as_dict()

    def _build_required_tool_calls(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            self.signer.build_trace_evidence(
                tool_name=tool.tool_name,
                input_ref=tool.input_ref,
                output_ref=tool.output_ref,
                args=tool.args,
            )
            for tool in self.transfer_skill.build_required_tools(payload)
        ]

    def _build_reason_check_context(self, payload: dict[str, Any]) -> dict[str, Any]:
        signed_payload = str(payload.get("signed_payload", ""))
        signed_payload_c14n = str(payload.get("signed_payload_c14n", ""))
        incoming_context_metadata = payload.get("context_metadata")
        base_context_metadata = (
            dict(incoming_context_metadata)
            if isinstance(incoming_context_metadata, dict)
            else {}
        )
        control_bundle_v = str(
            payload.get("control_bundle_v")
            or payload.get("bundle_version")
            or base_context_metadata.get("control_bundle_v")
            or "bundle_demo_finance_001@1.0.0"
        )
        current_account_state = base_context_metadata.get("current_account_state")
        if not isinstance(current_account_state, dict):
            current_account_state = (
                payload.get("current_account_state")
                if isinstance(payload.get("current_account_state"), dict)
                else {}
            )
        policy_constraints = base_context_metadata.get("policy_constraints")
        if not isinstance(policy_constraints, dict):
            policy_constraints = (
                payload.get("policy_constraints")
                if isinstance(payload.get("policy_constraints"), dict)
                else {}
            )

        base_context_metadata.update(
            {
                "agent_id": str(payload.get("agent_id", DEMO_AGENT_IDS["transfer"])),
                "principal_id": str(payload.get("principal_id", DEMO_PRINCIPALS["transferor"])),
                "recipient_id": str(payload.get("recipient_id", DEMO_PRINCIPALS["recipient"])),
                "mandate_id": "mandate_demo_001",
                "requested_amount": str(payload.get("amount", "0")),
                "requested_currency": str(payload.get("currency", "USD")),
                "control_bundle_v": control_bundle_v,
                "current_account_state": current_account_state,
                "policy_constraints": policy_constraints,
            }
        )
        return {
            "amount": str(payload.get("amount", "0")),
            "currency": str(payload.get("currency", "USD")),
            "memo": str(payload.get("memo", "")),
            "recipient_id": str(payload.get("recipient_id", DEMO_PRINCIPALS["recipient"])),
            "recipient_account_ref": str(payload.get("recipient_account_ref", "")),
            "principal_id": str(payload.get("principal_id", DEMO_PRINCIPALS["transferor"])),
            "policy_decision": self._policy_decision_for_payload(payload),
            "next_step": self.transfer_skill.build_next_step(payload),
            "input_payload": json.dumps(payload, ensure_ascii=True),
            "reasoning": self.transfer_skill.build_fallback_reasoning(payload),
            "prompt_preview": self.transfer_skill.summarize_required_steps(payload),
            "tool_calls": self._build_required_tool_calls(payload),
            "signed_payload": signed_payload,
            "signed_payload_c14n": signed_payload_c14n,
            "control_bundle_v": str(
                payload.get("control_bundle_v")
                or payload.get("bundle_version")
                or "bundle_demo_finance_001@1.0.0"
            ),
            "context_metadata": {
                "agent_id": str(payload.get("agent_id", DEMO_AGENT_IDS["transfer"])),
                "principal_id": str(payload.get("principal_id", DEMO_PRINCIPALS["transferor"])),
                "recipient_id": str(payload.get("recipient_id", DEMO_PRINCIPALS["recipient"])),
                "mandate_id": "mandate_demo_001",
                "requested_amount": str(payload.get("amount", "0")),
                "requested_currency": str(payload.get("currency", "USD")),
                "control_bundle_v": str(
                    payload.get("control_bundle_v")
                    or payload.get("bundle_version")
                    or "bundle_demo_finance_001@1.0.0"
                ),
                "current_account_state": current_account_state,
                "policy_constraints": policy_constraints,
                **base_context_metadata,
            },
            "policy": payload.get("policy") or {},
        }

    def _policy_decision_for_payload(self, payload: dict[str, Any]) -> str:
        policy = payload.get("policy") or {}
        amount = str(payload.get("amount", "0"))
        currency = str(payload.get("currency", "USD"))
        recipient_id = str(payload.get("recipient_id", DEMO_PRINCIPALS["recipient"]))
        recipient_account_ref = str(payload.get("recipient_account_ref", ""))
        tool_specs = self.transfer_skill.build_required_tools(
            {
                **payload,
                "policy": policy,
            }
        )
        policy_decision = str(tool_specs[-1].output_ref if tool_specs else "")
        if not policy_decision:
            policy_decision = self.transfer_skill._compute_policy_decision(
                amount_value=self.transfer_skill._safe_amount(amount),
                currency=currency,
                allowed_currencies=[str(item) for item in policy.get("allowedCurrencies", ["USD"])],
                recipient_allowlist_required=bool(policy.get("recipientAllowlistRequired", True)),
                recipient_allowlisted=self.transfer_skill.check_recipient_allowlist(
                    recipient_id,
                    recipient_account_ref,
                ),
                auto_execute_below=float(policy.get("autoExecuteBelow", 1000)),
                admin_review_at_or_above=float(policy.get("adminReviewAtOrAbove", 1000)),
            )
        return policy_decision

    def _infer_final_result(self, payload: dict[str, Any]) -> str:
        policy_decision = self._policy_decision_for_payload(payload)
        mapping = {
            "auto_execute_allowed": "auto_execute",
            "admin_approval_required": "escalate",
            "policy_review_required": "observe",
            "policy_reject_currency_not_allowed": "deny",
            "policy_reject_recipient_not_allowlisted": "deny",
        }
        return mapping.get(policy_decision, "observe")

    def _to_confidence(self, value: Any, payload: dict[str, Any]) -> float:
        try:
            confidence = float(value)
        except Exception:
            confidence = 0.72 if self._infer_final_result(payload) in {"auto_execute", "escalate"} else 0.6
        return max(0.0, min(confidence, 0.99))

    def _to_string_list(self, value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(item) for item in value if str(item).strip()]

    def _to_logic_checks(self, *values: Any) -> list[dict[str, str]]:
        for value in values:
            normalized = self._normalize_logic_checks(value)
            if normalized:
                return normalized
        return []

    def _to_text(self, value: Any, *fallbacks: Any) -> str:
        for candidate in (value, *fallbacks):
            if isinstance(candidate, str):
                text = candidate.strip()
                if text:
                    parsed = self._parse_structured_candidate(text)
                    if isinstance(parsed, dict):
                        rendered = self._render_text_from_object(parsed)
                        if rendered:
                            return rendered
                    return text
            elif isinstance(candidate, (int, float)) and not isinstance(candidate, bool):
                return str(candidate)
            elif isinstance(candidate, dict):
                rendered = self._render_text_from_object(candidate)
                if rendered:
                    return rendered
        return ""

    def _to_next_step_text(self, value: Any, *fallbacks: Any) -> str:
        for candidate in (value, *fallbacks):
            if isinstance(candidate, str):
                text = candidate.strip()
                if text:
                    parsed = self._parse_structured_candidate(text)
                    if isinstance(parsed, dict):
                        rendered = self._render_text_from_object(parsed)
                        if rendered:
                            return rendered
                    return text
            elif isinstance(candidate, dict):
                rendered = self._render_text_from_object(candidate)
                if rendered:
                    return rendered
            elif isinstance(candidate, (int, float)) and not isinstance(candidate, bool):
                return str(candidate)
        return ""

    def _parse_adk_json(self, text: str) -> dict[str, Any]:
        candidate = self._extract_json_object(text)
        parsed = json.loads(candidate)
        if not isinstance(parsed, dict):
            raise json.JSONDecodeError("Expected JSON object", candidate, 0)
        return parsed

    def _best_adk_text_candidate(self, text_parts: list[str]) -> str:
        for candidate in reversed(text_parts):
            text = candidate.strip()
            if not text:
                continue
            try:
                self._parse_adk_json(text)
                return text
            except Exception:
                continue
        return "\n".join(part for part in text_parts if part.strip()) or text_parts[-1]

    def _parse_structured_candidate(self, value: Any) -> dict[str, Any] | None:
        if isinstance(value, dict):
            return value
        if not isinstance(value, str):
            return None

        text = value.strip()
        if not text:
            return None

        for parser in (self._parse_adk_json, self._parse_literal_object):
            try:
                parsed = parser(text)
            except Exception:
                continue
            if isinstance(parsed, dict):
                return parsed
        return None

    def _parse_literal_object(self, text: str) -> dict[str, Any]:
        parsed = ast.literal_eval(text)
        if not isinstance(parsed, dict):
            raise ValueError("Expected mapping")
        return parsed

    def _render_text_from_object(self, value: dict[str, Any]) -> str:
        for key in ("reasoning", "reasoning_summary", "summary", "detail", "message", "text", "value", "next_step"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()

        tool_name = next(
            (
                str(value.get(key)).strip()
                for key in ("tool_name", "name", "action")
                if isinstance(value.get(key), str) and str(value.get(key)).strip()
            ),
            "",
        )
        if tool_name:
            args = value.get("parameters") if isinstance(value.get("parameters"), dict) else None
            if not isinstance(args, dict):
                args = value.get("args") if isinstance(value.get("args"), dict) else None
            if not isinstance(args, dict):
                args = value.get("params") if isinstance(value.get("params"), dict) else None
            if isinstance(args, dict) and args:
                rendered_args = ", ".join(f"{key}={self._render_scalar(value)}" for key, value in args.items())
                return f"Call {tool_name}({rendered_args})"
            return f"Call {tool_name}()"
        return ""

    def _render_scalar(self, value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return str(value)
        if isinstance(value, bool):
            return "true" if value else "false"
        if value is None:
            return "null"
        if isinstance(value, dict):
            rendered = self._render_text_from_object(value)
            if rendered:
                return rendered
            return json.dumps(value, ensure_ascii=True, separators=(",", ":"))
        if isinstance(value, list):
            return "[" + ", ".join(self._render_scalar(item) for item in value) + "]"
        return str(value)

    def _normalize_logic_checks(self, value: Any) -> list[dict[str, str]]:
        if isinstance(value, str):
            parsed = self._parse_structured_candidate(value)
            if parsed is not None:
                return self._normalize_logic_checks(parsed.get("logic_checks") if "logic_checks" in parsed else parsed)
            text = value.strip()
            if text:
                return [{"name": text[:80], "status": "pass", "detail": text}]
            return []
        if isinstance(value, dict):
            if "logic_checks" in value:
                return self._normalize_logic_checks(value.get("logic_checks"))
            name = str(value.get("name") or value.get("label") or value.get("title") or "check")
            detail = str(value.get("detail") or value.get("message") or value.get("summary") or value.get("reason") or name)
            status = str(value.get("status") or "pass")
            if status not in {"pass", "warn", "fail"}:
                status = "pass"
            return [{"name": name, "status": status, "detail": detail}]
        if not isinstance(value, list):
            return []

        normalized: list[dict[str, str]] = []
        for index, item in enumerate(value):
            if isinstance(item, dict):
                name = str(item.get("name") or item.get("label") or item.get("title") or f"check_{index + 1}")
                detail = str(item.get("detail") or item.get("message") or item.get("summary") or item.get("reason") or name)
                status = str(item.get("status") or "pass")
                if status not in {"pass", "warn", "fail"}:
                    status = "pass"
                normalized.append({"name": name, "status": status, "detail": detail})
            elif isinstance(item, str):
                text = item.strip()
                if text:
                    normalized.append({"name": text[:80], "status": "pass", "detail": text})
            elif item is not None:
                text = str(item).strip()
                if text:
                    normalized.append({"name": text[:80], "status": "pass", "detail": text})
        return normalized

    def _extract_json_object(self, text: str) -> str:
        stripped = text.strip()
        if not stripped:
            raise json.JSONDecodeError("Empty JSON payload", text, 0)

        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.IGNORECASE)
        stripped = re.sub(r"\s*```$", "", stripped)

        start = stripped.find("{")
        if start < 0:
            return stripped

        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(stripped)):
            char = stripped[index]
            if escaped:
                escaped = False
                continue
            if char == "\\" and in_string:
                escaped = True
                continue
            if char == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return stripped[start : index + 1]

        return stripped[start:]

    def _build_reason_check_input(self, payload: dict[str, Any], plan: AgentPlan) -> dict[str, Any]:
        signed_payload = str(payload.get("signed_payload", ""))
        signed_payload_c14n = str(payload.get("signed_payload_c14n", ""))
        return {
            **self._build_reason_check_context(payload),
            "prompt_text": plan.prompt_text,
            "reasoning": plan.reasoning,
            "reasoning_summary": plan.reasoning,
            "final_result": self._infer_final_result(payload),
            "next_step": plan.next_step,
            "logic_checks": plan.logic_checks,
            "policy": payload.get("policy") or {},
            "signed_payload": signed_payload,
            "signed_payload_c14n": signed_payload_c14n,
        }

    def _build_reason_check_agent(self) -> Agent:
        return Agent(
            name="safr_reason_checker",
            model=MODEL_NAME,
            instruction="""
You are the verifier for a governed transfer in the SAFR x ATP flow.

Your role is to review the signed transfer packet and produce the verifier's decision record for product, operations, and audit use.

You are not the transfer planner.
You are not the bank executor.
Do not restate the transfer agent's prompt.
Do not invent new facts outside the signed packet and attached evidence.
Do not claim the bank execution already happened.

Review the transfer using the signed artifacts as the source of truth:
1. the signed instruction from the principal
2. the pinned policy snapshot and policy constraints
3. the signed proposal / actual tool intent from the agent
4. the tool trace, resolved recipient data, and other attached evidence
5. the declared transfer-side outcome and reasoning, only as supporting context

Your task is to decide whether the transfer can move forward as requested, must pause for escalation, must be denied, or should be allowed to proceed under observation.

Decision meanings:
- auto_execute: the transfer is consistent, policy-valid, and may continue automatically
- escalate: the transfer is not allowed to continue automatically and requires admin approval
- deny: the transfer is invalid or unsupported and must not proceed
- observe: the transfer may proceed, but the verifier wants it explicitly flagged for follow-up, anomaly monitoring, or post-run review

Return strict JSON only with:
- verdict: pass, observe, or fail
- recommended_outcome: auto_execute, escalate, deny, or observe
- summary: short human-readable summary
- findings: array of short strings
- logic_checks: array of objects with name, status, detail
- observed_signals: array of short strings
- model_note: one short string

Rules:
- Treat the signed packet and verifier inputs as the source of truth.
- Prefer evidence over natural-language reasoning.
- If reasoning and evidence disagree, trust the evidence.
- If the declared outcome is unsupported by the signed artifacts or policy facts, do not preserve it.
- Be concise, operational, and audit-friendly.
- Do not claim execution already happened unless execution evidence is present.

Output requirements:
- summary should read like a product-facing verifier conclusion
- findings should list the most decision-relevant facts or gaps
- logic_checks should describe the specific checks performed and whether each passed
- observed_signals should capture risk or governance signals worth surfacing
- model_note should briefly state whether this was ADK review or deterministic fallback
""".strip(),
        )

    def _normalize_tool_calls(self, raw_tool_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for tool_call in raw_tool_calls:
            tool_name = str(
                tool_call.get("tool_name")
                or tool_call.get("name")
                or tool_call.get("tool")
                or tool_call.get("action")
                or "unknown_tool"
            )
            args = (
                tool_call.get("args")
                or tool_call.get("tool_args")
                or tool_call.get("arguments")
                or tool_call.get("params")
                or tool_call.get("input")
                or {}
            )
            if not isinstance(args, dict):
                args = {}
            args = self._normalize_arg_names(args)

            input_ref = str(tool_call.get("input_ref", ""))
            output_ref = str(tool_call.get("output_ref", ""))

            if tool_name == "unknown_tool":
                tool_name = self._infer_tool_name(args)

            if tool_name in {"resolve_recipient", "recipient_lookup"}:
                tool_name = "resolve_recipient"
                input_ref = input_ref or str(args.get("recipient_id", ""))
                output_ref = output_ref or str(
                    args.get("account_ref", "") or args.get("recipient_account_ref", "")
                )
            elif tool_name in {
                "policy_preview",
                "policy_check_preview",
                "transfer_policy_check",
                "validate_transfer_policy",
            }:
                tool_name = "validate_transfer_policy"
                input_ref = input_ref or str(args.get("currency", ""))
                output_ref = output_ref or str(
                    args.get("policy_decision", "")
                    or args.get("threshold", "")
                    or args.get("amount", "")
                    or "policy preview prepared"
                )
            elif tool_name == "verifier":
                input_ref = input_ref or "governance envelope"
                output_ref = output_ref or "pre-execution verification"
            else:
                if not input_ref and args:
                    input_ref = str(next(iter(args.values())))
                if not output_ref and len(args) > 1:
                    output_ref = " | ".join(str(value) for value in list(args.values())[1:])

            normalized.append(
                self.signer.build_trace_evidence(
                    tool_name=tool_name,
                    input_ref=input_ref,
                    output_ref=output_ref,
                    args={str(key): str(value) for key, value in args.items()},
                )
            )

        return normalized

    def _infer_tool_name(self, args: dict[str, Any]) -> str:
        arg_keys = set(args.keys())

        if "recipient_id" in arg_keys and (
            "recipient_account_ref" in arg_keys or "account_ref" in arg_keys
        ):
            return "resolve_recipient"

        if "currency" in arg_keys and ("amount" in arg_keys or "principal_id" in arg_keys):
            return "validate_transfer_policy"

        if "envelope_ref" in arg_keys or "governance_envelope" in arg_keys:
            return "verifier"

        return "unknown_tool"

    def _normalize_arg_names(self, args: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(args)
        if "transfer_id" in normalized and "flow_id" not in normalized and "flowId" not in normalized:
            normalized["flow_id"] = normalized["transfer_id"]
        return normalized


class AgentSigner:
    def __init__(self) -> None:
        self.principal_id = AGENT_PRINCIPAL
        self.key_id = AGENT_KEY_ID
        self.private_key = self._load_or_create_private_key()
        self._sync_signing_registry()

    def sign_envelope(self, payload: dict[str, Any]) -> dict[str, str]:
        canonical_payload = canonical_json(payload)
        signature = self.private_key.sign(canonical_payload.encode("utf-8"))
        return {
            "agent_principal": self.principal_id,
            "agent_key_id": self.key_id,
            "agent_sig_alg": "ed25519",
            "signed_payload_c14n": "sorted-json",
            "signed_payload": canonical_payload,
            "agent_sig": signature.hex(),
        }

    def build_trace_evidence(
        self,
        *,
        tool_name: str,
        input_ref: str,
        output_ref: str,
        args: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        trace_id = f"trace_{uuid.uuid4().hex[:16]}"
        trace_payload = {
            "trace_id": trace_id,
            "tool_name": tool_name,
            "input_ref": input_ref,
            "output_ref": output_ref,
            "args": args or {},
        }
        canonical_payload = canonical_json(trace_payload)
        trace_hash = f"sha256:{sha256_hex(canonical_payload.encode('utf-8'))}"
        trace_sig = self.private_key.sign(trace_hash.encode("utf-8")).hex()
        return {
            "tool_name": tool_name,
            "input_ref": input_ref,
            "output_ref": output_ref,
            "args": args or {},
            "trace_id": trace_id,
            "trace_hash": trace_hash,
            "trace_sig": trace_sig,
            "trace_sig_alg": "ed25519",
            "trace_signer": self.principal_id,
            "trace_key_id": self.key_id,
        }

    def _load_or_create_private_key(self) -> Ed25519PrivateKey:
        PRIVATE_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        if PRIVATE_KEY_PATH.exists():
            return serialization.load_pem_private_key(
                PRIVATE_KEY_PATH.read_bytes(),
                password=None,
            )

        private_key = Ed25519PrivateKey.generate()
        PRIVATE_KEY_PATH.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        PUBLIC_KEY_PATH.write_bytes(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        return private_key

    def _sync_signing_registry(self) -> None:
        SHARED_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        public_key_pem = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        now = utc_now_iso()
        with sqlite3.connect(SHARED_DB_PATH) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS principal_signing_keys (
                    principal_id TEXT PRIMARY KEY,
                    key_id TEXT NOT NULL UNIQUE,
                    role TEXT NOT NULL,
                    key_type TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    public_key_pem TEXT,
                    public_key_path TEXT,
                    private_key_path TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                INSERT INTO principal_signing_keys (
                    principal_id,
                    key_id,
                    role,
                    key_type,
                    algorithm,
                    public_key_pem,
                    public_key_path,
                    private_key_path,
                    created_at,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(principal_id) DO UPDATE SET
                    key_id = excluded.key_id,
                    role = excluded.role,
                    key_type = excluded.key_type,
                    algorithm = excluded.algorithm,
                    public_key_pem = excluded.public_key_pem,
                    public_key_path = excluded.public_key_path,
                    private_key_path = excluded.private_key_path,
                    updated_at = excluded.updated_at
                """,
                (
                    self.principal_id,
                    self.key_id,
                    "agent",
                    "signing",
                    "ed25519",
                    public_key_pem,
                    str(PUBLIC_KEY_PATH),
                    str(PRIVATE_KEY_PATH),
                    now,
                    now,
                ),
            )
            connection.commit()


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def sha256_hex(value: bytes) -> str:
    import hashlib

    return hashlib.sha256(value).hexdigest()


def utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def duration_ms_between(started_at: str, completed_at: str) -> int:
    try:
        started = datetime.fromisoformat(started_at)
        completed = datetime.fromisoformat(completed_at)
        return max(int((completed - started).total_seconds() * 1000), 0)
    except Exception:
        return 0
