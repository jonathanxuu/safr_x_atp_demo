from __future__ import annotations

import os
import json
from datetime import datetime, timedelta, timezone
import hashlib
from typing import Any
from uuid import uuid4

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .agent import AdkTransferPlanner, AgentSigner
from .constants import DEMO_AGENT_IDS, DEMO_PRINCIPALS


PORT = int(os.getenv("PORT", "4106"))
EVENT_SERVICE_URL = os.getenv("EVENT_SERVICE_URL", "http://localhost:4101")
VERIFIER_SERVICE_URL = os.getenv("VERIFIER_SERVICE_URL", "http://localhost:4103")
MCP_BANK_URL = os.getenv("MCP_BANK_URL", "http://localhost:4104")
IDENTITY_SERVICE_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:4105")

app = FastAPI(title="SAFR x ATP Agent Service")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
planner = AdkTransferPlanner()
signer = AgentSigner()


class EvaluateTransferRequest(BaseModel):
    flowId: str
    amount: str
    currency: str
    memo: str
    recipientAccountRef: str
    recipientId: str
    principalId: str
    agentId: str = DEMO_AGENT_IDS["transfer"]
    transferorPasskey: dict[str, Any]


class AdminApproveRequest(BaseModel):
    flowId: str
    firstVerifierEventId: str
    envelopeEventId: str
    instructionEventId: str
    adminProofRef: str
    adminVerified: bool
    adminPrincipalId: str


class ExecuteTransferRequest(BaseModel):
    flowId: str
    verifierEventId: str
    fromAccountId: str
    toAccountId: str
    amount: float
    currency: str


async def post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, json=payload)
    if response.status_code >= 400:
        try:
            body = response.json()
        except Exception:
            body = {"error": response.text}
        raise HTTPException(status_code=response.status_code, detail=body.get("error", "Request failed"))
    return response.json()


async def get_json(url: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url)
    if response.status_code >= 400:
        try:
            body = response.json()
        except Exception:
            body = {"error": response.text}
        detail = body.get("error") or body.get("detail") or "Request failed"
        raise HTTPException(status_code=response.status_code, detail=detail)
    return response.json()


async def validate_identity_proof(
    *,
    proof_id: str,
    principal_id: str,
    role: str,
    proof_type: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "proofId": proof_id,
        "principalId": principal_id,
        "role": role,
    }
    if proof_type:
        payload["proofType"] = proof_type
    return await post_json(
        f"{IDENTITY_SERVICE_URL}/proofs/validate",
        payload,
    )


def now_epoch() -> int:
    return int(datetime.now(tz=timezone.utc).timestamp())


def iso_after(minutes: int) -> str:
    return (datetime.now(tz=timezone.utc) + timedelta(minutes=minutes)).isoformat()


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def sha256_prefixed(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def build_instruction_payload(request: EvaluateTransferRequest) -> dict[str, Any]:
    passkey = request.transferorPasskey
    signed_at = str(
        passkey.get("lastVerifiedAt")
        or passkey.get("registeredAt")
        or datetime.now(tz=timezone.utc).isoformat()
    )
    challenge = str(passkey.get("challenge", "") or f"chl_{uuid4().hex[:12]}")

    submitted_at = datetime.now(tz=timezone.utc).isoformat()
    expiry_at = iso_after(10)
    instruction_nonce = f"nonce_{uuid4().hex}"
    signing_payload = {
        "payload_version": "1.0",
        "payload_type": "transfer_instruction",
        "canonicalization": "jcs-rfc8785",
        "signed_fields": [
            "instruction_id",
            "principal_id",
            "agent_id",
            "action_type",
            "amount",
            "currency",
            "recipient_id",
            "recipient_account_ref",
            "memo",
            "submitted_at",
            "expiry_at",
            "instruction_nonce",
        ],
    }
    signed_payload_values = {
        "instruction_id": f"instr_{request.flowId}",
        "principal_id": request.principalId,
        "agent_id": request.agentId,
        "action_type": "payment.transfer",
        "amount": request.amount,
        "currency": request.currency,
        "recipient_id": request.recipientId,
        "recipient_account_ref": request.recipientAccountRef,
        "memo": request.memo,
        "submitted_at": submitted_at,
        "expiry_at": expiry_at,
        "instruction_nonce": instruction_nonce,
    }
    signing_payload["payload_hash"] = sha256_prefixed(canonical_json(signed_payload_values))

    return {
        "id": f"evt_instr_{request.flowId}_hash",
        "kind": 101,
        "ai_id": request.principalId,
        "created_at": now_epoch(),
        "tags": [
            ["flow_id", request.flowId],
            ["role", "transferor"],
            ["action", "transfer"],
        ],
        "content": {
            "instruction_id": f"instr_{request.flowId}",
            "principal_id": request.principalId,
            "agent_id": request.agentId,
            "action_type": "payment.transfer",
            "amount": request.amount,
            "currency": request.currency,
            "recipient_id": request.recipientId,
            "recipient_account_ref": request.recipientAccountRef,
            "memo": request.memo,
            "submitted_at": submitted_at,
            "expiry_at": expiry_at,
            "instruction_nonce": instruction_nonce,
            "signing_payload": signing_payload,
            "signature_proof": {
                "passkey_verified": bool(passkey.get("verified")),
                "signature": "passkey_sig_demo_transferor",
                "proof_ref": str(passkey.get("proofRef", "")),
                "signature_alg": "webauthn-passkey-es256",
                "credential_id": str(passkey.get("credentialId", "")),
                "public_key_ref": str(passkey.get("publicKeyRef", "")),
                "challenge": challenge,
                "signed_at": signed_at,
                "verifier_material_ref": "webauthn_assertion_bundle_001",
            },
        },
    }


def build_envelope_payload(
    request: EvaluateTransferRequest,
    instruction_event_id: str,
    plan_context: dict[str, Any],
    policy_view: dict[str, Any],
    transferor_account: dict[str, Any] | None,
) -> dict[str, Any]:
    policy = policy_view.get("policy", {})
    bundle = policy_view.get("bundle", {})
    tool_calls = plan_context.get("tool_calls", [])
    context_metadata = dict(plan_context.get("context_metadata", {}))
    context_metadata["current_account_state"] = {
        "available_balance": f"{float(transferor_account.get('availableBalance', 0)):.2f}"
        if transferor_account
        else "0.00",
    }
    context_metadata["policy_constraints"] = {
        "auto_execute_below": f"{float(policy.get('autoExecuteBelow', 1000)):.2f}",
        "admin_review_at_or_above": f"{float(policy.get('adminReviewAtOrAbove', 1000)):.2f}",
        "currency_allowlist": policy.get("allowedCurrencies", ["USD"]),
        "recipient_allowlist_required": bool(policy.get("recipientAllowlistRequired", True)),
    }

    content = {
        "instruction_ref": instruction_event_id,
        "agent_principal": DEMO_PRINCIPALS["agent"],
        "action": {
            "tool_name": "mcp_bank_transfer_execute",
            "params": {
                "amount": request.amount,
                "currency": request.currency,
                "recipient_account_ref": request.recipientAccountRef,
                "memo": request.memo,
            },
        },
        "tool_calls": tool_calls,
        "context_metadata": context_metadata,
        "control_bundle_v": plan_context.get(
            "control_bundle_v",
            f"{bundle.get('bundleId', 'bundle_demo_finance_001')}@{bundle.get('bundleVersion', '1.0.0')}",
        ),
        "origin_sig": request.transferorPasskey.get("proofRef", ""),
    }
    signing_material = signer.sign_envelope(content)
    content["agent_signature"] = signing_material

    return {
        "id": f"evt_env_{uuid4().hex}_hash",
        "kind": 102,
        "ai_id": DEMO_PRINCIPALS["agent"],
        "created_at": now_epoch(),
        "tags": [
            ["flow_id", request.flowId],
            ["action", "payment.transfer"],
            ["agent_mode", str(plan_context.get("mode", "deterministic"))],
            ["agent_principal", DEMO_PRINCIPALS["agent"]],
            ["agent_key_id", signing_material["agent_key_id"]],
        ],
        "content": content,
    }


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "agent-service",
        "mode": planner.mode,
        "eventServiceBaseUrl": EVENT_SERVICE_URL,
        "verifierServiceBaseUrl": VERIFIER_SERVICE_URL,
        "mcpBankBaseUrl": MCP_BANK_URL,
    }


@app.post("/transfers/evaluate")
async def evaluate_transfer(request: EvaluateTransferRequest) -> dict[str, Any]:
    if not request.transferorPasskey.get("proofRef"):
        raise HTTPException(status_code=400, detail="Transferor proofRef is required")
    if not request.transferorPasskey.get("verified"):
        raise HTTPException(status_code=400, detail="Transferor passkey must be verified for submission")

    await validate_identity_proof(
        proof_id=str(request.transferorPasskey["proofRef"]),
        principal_id=request.principalId,
        role="transferor",
        proof_type="authentication",
    )

    instruction_payload = build_instruction_payload(request)
    instruction_body = await post_json(
        f"{EVENT_SERVICE_URL}/events",
        {"flowId": request.flowId, "payload": instruction_payload},
    )

    policy_view = await get_json(f"{VERIFIER_SERVICE_URL}/verifier/policy/current?currency={request.currency}")
    accounts_body = await get_json(f"{MCP_BANK_URL}/accounts")
    transferor_account = next(
        (account for account in accounts_body.get("accounts", []) if account.get("ownerRole") == "transferor"),
        None,
    )

    plan = planner.plan_transfer(
        {
            "flow_id": request.flowId,
            "principal_id": request.principalId,
            "agent_id": request.agentId,
            "recipient_id": request.recipientId,
            "recipient_account_ref": request.recipientAccountRef,
            "amount": request.amount,
            "currency": request.currency,
            "memo": request.memo,
            "policy": policy_view.get("policy", {}),
        }
    )
    plan_context = {
        "mode": plan.mode,
        "reasoning_summary": plan.reasoning_summary,
        "tool_calls": plan.tool_calls,
        "context_metadata": plan.context_metadata,
        "control_bundle_v": plan.control_bundle_v,
    }

    envelope_payload = build_envelope_payload(
        request,
        instruction_body["event"]["eventId"],
        plan_context,
        policy_view,
        transferor_account,
    )
    envelope_body = await post_json(
        f"{EVENT_SERVICE_URL}/events",
        {"flowId": request.flowId, "payload": envelope_payload},
    )
    verifier_body = await post_json(
        f"{VERIFIER_SERVICE_URL}/verifier/evaluate-envelope",
        {
            "flowId": request.flowId,
            "envelopeEventId": envelope_body["event"]["eventId"],
        },
    )

    return {
        "agent": {
            "mode": plan.mode,
            "reasoning_summary": plan.reasoning_summary,
            "tool_calls": plan.tool_calls,
            "started_at": plan.started_at,
            "completed_at": plan.completed_at,
            "duration_ms": plan.duration_ms,
            "prompt_text": plan.prompt_text,
            "prompt_preview": plan.prompt_preview,
            "skill_name": plan.skill_name,
            "mandatory_tools": plan.mandatory_tools,
            "fallback_reason": plan.fallback_reason,
        },
        "instructionEvent": instruction_body["event"],
        "envelopeEvent": envelope_body["event"],
        "verifierEvent": verifier_body["event"],
    }


@app.post("/transfers/admin-approve")
async def admin_approve(request: AdminApproveRequest) -> dict[str, Any]:
    if not request.adminProofRef:
        raise HTTPException(status_code=400, detail="Admin proofRef is required")

    admin_payload = {
        "id": f"evt_admin_{uuid4().hex}_hash",
        "kind": 105,
        "ai_id": request.adminPrincipalId,
        "created_at": now_epoch(),
        "tags": [
            ["flow_id", request.flowId],
            ["decision", "admin_signed_approval"],
        ],
        "content": {
            "verifier_record_ref": request.firstVerifierEventId,
            "admin_id": request.adminPrincipalId,
            "decision": "admin_signed_approval",
            "comment": "Approved by administrator passkey through agent-service",
            "signature_proof": {
                "passkey_verified": request.adminVerified,
                "signature": "passkey_sig_demo_admin",
                "proof_ref": request.adminProofRef,
            },
        },
    }
    admin_body = await post_json(
        f"{EVENT_SERVICE_URL}/events",
        {"flowId": request.flowId, "payload": admin_payload},
    )
    verifier_body = await post_json(
        f"{VERIFIER_SERVICE_URL}/verifier/reverify-admin-signature",
        {
            "flowId": request.flowId,
            "adminReviewEventId": admin_body["event"]["eventId"],
            "firstVerifierEventId": request.firstVerifierEventId,
            "envelopeEventId": request.envelopeEventId,
            "instructionEventId": request.instructionEventId,
        },
    )
    return {
        "adminEvent": admin_body["event"],
        "verifierEvent": verifier_body["event"],
    }


@app.post("/transfers/execute")
async def execute_transfer(request: ExecuteTransferRequest) -> dict[str, Any]:
    return await post_json(
        f"{MCP_BANK_URL}/transfers/execute",
        {
            "flowId": request.flowId,
            "verifierEventId": request.verifierEventId,
            "fromAccountId": request.fromAccountId,
            "toAccountId": request.toAccountId,
            "amount": request.amount,
            "currency": request.currency,
        },
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=PORT, reload=False)
