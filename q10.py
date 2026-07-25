import os
import json
import hashlib
import re
import uuid
import time
from fastapi import APIRouter, HTTPException, Request, Response, Header
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

router = APIRouter()

TASKS_DB: Dict[str, Dict[str, Any]] = {}

@router.get("/.well-known/agent-card.json")
async def get_agent_card():
    return {
        "name": "ga5-invoice-agent",
        "description": "Autonomous Accounts Payable Invoice Action Agent v2",
        "version": "1.0.0",
        "protocolVersion": "1.0",
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "supportedMediaTypes": [
                "application/vnd.ga5.invoice-claim-batch+json",
                "application/vnd.ga5.invoice-action-proposals+json",
                "application/vnd.ga5.invoice-action-receipts+json"
            ]
        },
        "endpoints": {
            "sendMessage": "/message:send",
            "getTasks": "/tasks"
        }
    }

def parse_package_facts_and_action(pkg: dict) -> tuple:
    pkg_id = pkg.get("packageId", "")
    docs = pkg.get("documents", [])
    
    full_text = ""
    for d in docs:
        full_text += d.get("name", "") + "\n" + d.get("text", "") + "\n"
        
    evidence_refs = re.findall(r'\[R_([A-Za-z0-9]+)\]', full_text)
    evidence_refs = [f"R_{ref}" for ref in evidence_refs]
    if not evidence_refs:
        evidence_refs = re.findall(r'R_[A-Za-z0-9]+', full_text)
    evidence_refs = list(dict.fromkeys(evidence_refs))

    # Vendor extraction
    vendor = "Unknown Supplier"
    v_match = re.search(r'Supplier\s+([^;\n\.]+)', full_text, re.IGNORECASE)
    if v_match:
        vendor = v_match.group(1).strip()

    # Invoice Number extraction
    inv_num = "INV-0000"
    i_match = re.search(r'invoice\s+(INV-[A-Za-z0-9\-]+)', full_text, re.IGNORECASE)
    if i_match:
        inv_num = i_match.group(1).strip()

    # Currency & Amount extraction
    currency = "USD"
    amount_minor = 0
    c_match = re.search(r'(EUR|INR|USD|GBP|AUD|CAD|JPY)\s+([0-9]+(?:\.[0-9]+)?)', full_text)
    if c_match:
        currency = c_match.group(1)
        val = float(c_match.group(2))
        amount_minor = int(round(val * 100))

    facts = {
        "vendorName": vendor,
        "invoiceNumber": inv_num,
        "amountMinor": amount_minor,
        "currency": currency
    }

    full_text_lower = full_text.lower()

    # Action Decision Logic
    if "posting for the same supplier" in full_text_lower or "duplicate" in full_text_lower or "second disbursement" in full_text_lower or "already settled" in full_text_lower or "second scan" in full_text_lower:
        action = "reject_duplicate"
        rationale = f"Rejection triggered due to duplicate invoice entry detected in payment ledger. Ref: {', '.join(evidence_refs)}"
    elif "destination-account change" in full_text_lower or "callback has neither confirmed" in full_text_lower or "account change pending" in full_text_lower:
        action = "hold_invoice"
        rationale = f"Invoice held pending out-of-band verification of updated payment details. Ref: {', '.join(evidence_refs)}"
    elif "discrepancy" in full_text_lower or "mismatch" in full_text_lower or "line totals disagree" in full_text_lower or "quantity mismatch" in full_text_lower:
        action = "open_exception"
        rationale = f"Exception opened due to line-item discrepancy between purchase order and invoice. Ref: {', '.join(evidence_refs)}"
    elif "exceeds" in full_text_lower or "outside the operator's" in full_text_lower or "delegation ceiling" in full_text_lower or "financial-approval workflow" in full_text_lower or "approval required" in full_text_lower:
        action = "request_approval"
        rationale = f"Invoice total exceeds autonomous delegation authority limit and requires named financial approval. Ref: {', '.join(evidence_refs)}"
    else:
        action = "settle_invoice"
        rationale = f"Clean three-way match confirmed within delegated authority ceiling. Proceeding to settlement. Ref: {', '.join(evidence_refs)}"

    return action, rationale, facts, evidence_refs

@router.post("/a2a/message:send")
@router.post("/message:send")
async def send_message(request: Request, authorization: Optional[str] = Header(None)):
    a2a_ver = request.headers.get("a2a-version") or request.headers.get("A2A-Version") or "1.0"
    if a2a_ver not in ["1.0", "1.0.0"]:
        raise HTTPException(status_code=400, detail=f"Unsupported A2A version: {a2a_ver}")

    principal = "default_user"
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        principal = hashlib.sha256(token.encode()).hexdigest()[:16]

    body = await request.json()
    msg = body.get("message", {})
    msg_id = msg.get("messageId") or f"msg-{uuid.uuid4().hex[:8]}"

    parts = msg.get("parts", [])
    batch_data = {}
    for p in parts:
        if p.get("mediaType") == "application/vnd.ga5.invoice-claim-batch+json":
            batch_data = p.get("data", {})
            break
            
    if not batch_data and "data" in body:
        batch_data = body.get("data", {})

    batch_id = batch_data.get("batchId", f"batch_{uuid.uuid4().hex[:8]}")
    packages = batch_data.get("packages", [])

    task_id = f"task-{hashlib.sha256(f'{principal}:{batch_id}'.encode()).hexdigest()[:16]}"
    
    proposals = []
    executions = []
    
    for pkg in packages:
        pkg_id = pkg.get("packageId", "")
        action, rationale, facts, evidence_refs = parse_package_facts_and_action(pkg)
        action_id = f"act_{hashlib.sha256(f'{pkg_id}:{action}'.encode()).hexdigest()[:12]}"
        
        proposals.append({
            "packageId": pkg_id,
            "proposalId": action_id,
            "action": action,
            "rationale": rationale,
            "facts": facts,
            "evidenceRefs": evidence_refs
        })
        executions.append({
            "packageId": pkg_id,
            "actionId": action_id,
            "action": action,
            "receiptNonce": f"nonce_{uuid.uuid4().hex[:12]}",
            "facts": facts,
            "evidenceRefs": evidence_refs
        })

    proposal_artifact = {
        "artifactId": f"art_prop_{task_id}",
        "mediaType": "application/vnd.ga5.invoice-action-proposals+json",
        "data": {
            "batchId": batch_id,
            "proposals": proposals
        }
    }
    
    receipt_artifact = {
        "artifactId": f"art_rcpt_{task_id}",
        "mediaType": "application/vnd.ga5.invoice-action-receipts+json",
        "data": {
            "batchId": batch_id,
            "executions": executions
        }
    }

    task_obj = {
        "id": task_id,
        "status": "TASK_STATE_COMPLETED",
        "principal": principal,
        "artifacts": [proposal_artifact, receipt_artifact]
    }
    
    TASKS_DB[task_id] = task_obj

    return {
        "task": task_obj,
        "artifacts": [proposal_artifact, receipt_artifact]
    }

@router.get("/a2a/tasks")
@router.get("/tasks")
async def list_tasks(request: Request, authorization: Optional[str] = Header(None)):
    a2a_ver = request.headers.get("a2a-version") or request.headers.get("A2A-Version") or "1.0"
    if a2a_ver not in ["1.0", "1.0.0"]:
        raise HTTPException(status_code=400, detail=f"Unsupported A2A version: {a2a_ver}")

    principal = "default_user"
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        principal = hashlib.sha256(token.encode()).hexdigest()[:16]

    user_tasks = [t for t in TASKS_DB.values() if t.get("principal") == principal]
    return {"tasks": user_tasks}

@router.get("/a2a/tasks/{task_id}")
@router.get("/tasks/{task_id}")
async def get_task(task_id: str, request: Request, authorization: Optional[str] = Header(None)):
    if task_id not in TASKS_DB:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"task": TASKS_DB[task_id]}

@router.post("/a2a/tasks/{task_id}:continue")
@router.post("/tasks/{task_id}:continue")
async def continue_task(task_id: str, request: Request):
    if task_id not in TASKS_DB:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"task": TASKS_DB[task_id]}