from __future__ import annotations

import json
import os
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from google.adk.agents import Agent
from google.adk.agents.run_config import RunConfig, StreamingMode
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from .constants import DEMO_AGENT_IDS, DEMO_PRINCIPALS
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
    reasoning_summary: str
    tool_calls: list[dict[str, Any]]
    context_metadata: dict[str, Any]
    control_bundle_v: str
    started_at: str
    completed_at: str
    duration_ms: int
    prompt_text: str
    prompt_preview: str
    skill_name: str
    mandatory_tools: list[str]
    fallback_reason: str | None = None


root_agent = Agent(
    name="safr_transfer_agent",
    model=MODEL_NAME,
    instruction="""
You are a financial transfer orchestration agent for a SAFR x ATP governance demo.

You receive a transfer instruction payload and must return strict JSON only.
Your JSON should contain:
- reasoning_summary: a short explanation of the governed transfer plan

Rules:
- The transfer skill always runs two mandatory tools in this order:
  1. resolve_recipient
  2. validate_transfer_policy
- Do not invent or remove tools from that fixed skill.
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
        self.signer = AgentSigner()
        self.transfer_skill = GovernedTransferSkill()

    def plan_transfer(self, payload: dict[str, Any]) -> AgentPlan:
        started_at = utc_now_iso()
        if self.mode != "adk":
            return self._deterministic_plan(payload, started_at=started_at)

        try:
            return self._run_adk_plan(payload, started_at=started_at)
        except Exception as error:
            return self._deterministic_plan(payload, started_at=started_at, fallback_reason=str(error))

    def _run_adk_plan(self, payload: dict[str, Any], *, started_at: str) -> AgentPlan:
        session = self.session_service.create_session_sync(
            app_name="safr_atp_demo",
            user_id=str(payload.get("principal_id", DEMO_PRINCIPALS["transferor"])),
            session_id=f"session_{uuid.uuid4().hex}",
        )
        prompt = json.dumps(payload, ensure_ascii=True)
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

        last_text = text_parts[-1]
        try:
            parsed = json.loads(last_text)
            reasoning_summary = str(
                parsed.get("reasoning_summary") or self.transfer_skill.summarize_required_steps(payload)
            )
        except json.JSONDecodeError:
            reasoning_summary = last_text.strip() or self.transfer_skill.summarize_required_steps(payload)

        completed_at = utc_now_iso()
        return AgentPlan(
            mode="adk",
            reasoning_summary=reasoning_summary,
            tool_calls=self._build_required_tool_calls(payload),
            context_metadata=dict(parsed.get("context_metadata", {})),
            control_bundle_v=str(parsed.get("control_bundle_v", "bundle_demo_finance_001@1.0.0"))
            if "parsed" in locals()
            else "bundle_demo_finance_001@1.0.0",
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms_between(started_at, completed_at),
            prompt_text=prompt,
            prompt_preview=self.transfer_skill.summarize_required_steps(payload),
            skill_name="governed_transfer_skill_v1",
            mandatory_tools=["resolve_recipient", "validate_transfer_policy"],
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
        prompt = json.dumps(payload, ensure_ascii=True)

        return AgentPlan(
            mode="deterministic",
            reasoning_summary=self.transfer_skill.build_fallback_reasoning(payload),
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
            skill_name="governed_transfer_skill_v1",
            mandatory_tools=["resolve_recipient", "validate_transfer_policy"],
            fallback_reason=fallback_reason,
        )

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
