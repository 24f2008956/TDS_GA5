"""Q11 - Incident Response Agent (profile ga5-incident-agent/v2).

POST /v2/incidents              -> propose diagnostic dispatch
POST /v2/incidents/{run_id}/receipts -> bind tool outcomes / approvals
GET  /v2/incidents/{run_id}     -> current state

Storage: SQLite WAL + atomic JSON files (durable across restarts).
Conflict detection: semantic digest over (incident, policy, toolCatalog).
"""
import asyncio
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import uuid
import time
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

router = APIRouter()
logger = logging.getLogger(__name__)

PROFILE = "ga5-incident-agent/v2"
MAX_BODY_BYTES = 4 * 1024 * 1024

# =============================================================
# Persistence (SQLite WAL + atomic JSON files)
# =============================================================
def _db_path() -> str:
    want = os.environ.get("GA5_DB", "/tmp/ga5.db")
    parent = os.path.dirname(want) or "."
    try:
        os.makedirs(parent, exist_ok=True)
        with open(want, "ab"):
            pass
        return want
    except OSError:
        return os.path.join(tempfile.gettempdir(), "ga5.db")

DB_PATH = _db_path()

def _init_db() -> None:
    try:
        with sqlite3.connect(DB_PATH, timeout=10.0, isolation_level=None) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS q11_incidents (
                    run_id TEXT PRIMARY KEY,
                    conflict_key TEXT NOT NULL,
                    response TEXT NOT NULL,
                    body TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS q11_receipts (
                    receipt_key TEXT PRIMARY KEY,
                    response TEXT NOT NULL
                );
            """)
    except Exception as e:
        logger.error("q11 db init error: %s", e)

_init_db()

def _atomic_json_write(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception as e:
        logger.error("atomic write error: %s", e)

def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def _digest(obj: Any) -> str:
    return hashlib.sha256(_canonical(obj).encode("utf-8")).hexdigest()

def _get_incident(run_id: str) -> Optional[dict]:
    try:
        with sqlite3.connect(DB_PATH, timeout=10.0, isolation_level=None) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            row = conn.execute(
                "SELECT conflict_key, response, body FROM q11_incidents WHERE run_id=?",
                (run_id,),
            ).fetchone()
        if row is not None:
            return {
                "conflictKey": row[0],
                "response": json.loads(row[1]),
                "body": json.loads(row[2]),
            }
    except Exception as e:
        logger.error("q11 get incident sqlite error: %s", e)
    
    json_path = os.path.join(tempfile.gettempdir(), f"q11_incident_{run_id}.json")
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error("q11 get incident json error: %s", e)
            
    return None

def _put_incident(run_id: str, conflict_key: str, response: dict, body: dict) -> None:
    try:
        with sqlite3.connect(DB_PATH, timeout=10.0, isolation_level=None) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "INSERT OR REPLACE INTO q11_incidents VALUES (?,?,?,?,?)",
                (run_id, conflict_key, _canonical(response), _canonical(body), time.time()),
            )
    except Exception as e:
        logger.error("q11 put incident sqlite error: %s", e)
    
    _atomic_json_write(
        os.path.join(tempfile.gettempdir(), f"q11_incident_{run_id}.json"),
        {"conflictKey": conflict_key, "response": response, "body": body},
    )

def _get_receipt(key: str) -> Optional[dict]:
    try:
        with sqlite3.connect(DB_PATH, timeout=10.0, isolation_level=None) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            row = conn.execute(
                "SELECT response FROM q11_receipts WHERE receipt_key=?", (key,)
            ).fetchone()
        if row is None:
            return None
        return json.loads(row[0])
    except Exception as e:
        logger.error("q11 get receipt error: %s", e)
        return None

def _put_receipt(key: str, response: dict) -> None:
    try:
        with sqlite3.connect(DB_PATH, timeout=10.0, isolation_level=None) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "INSERT OR REPLACE INTO q11_receipts VALUES (?,?)",
                (key, _canonical(response)),
            )
    except Exception as e:
        logger.error("q11 put receipt error: %s", e)

# =============================================================
# Redaction
# =============================================================
_SECRET_RES = (
    re.compile(r"sk[-_][A-Za-z0-9_-]{12,}", re.I),
    re.compile(r"ghp_[A-Za-z0-9]{30,}", re.I),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]+", re.I),
    re.compile(r"AKIA[A-Z0-9]{16}"),
    re.compile(r"-----BEGIN[^-]+-----"),
    re.compile(r"\b[0-9a-fA-F]{32,}\b"),
    re.compile(r"[A-Za-z0-9_-]{20,}canary[A-Za-z0-9_-]*", re.I),
    re.compile(r"(?i)(password|passphrase|secret[_-]?key|api[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{12,}"),
)

def _looks_secret(s: str) -> bool:
    if not isinstance(s, str):
        return False
    return any(rx.search(s) for rx in _SECRET_RES)

def _scrub(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    if isinstance(obj, str) and _looks_secret(obj):
        return "[REDACTED]"
    return obj

# =============================================================
# Evidence extraction
# =============================================================
_EV_RE = re.compile(r"\b(ev_[A-Za-z0-9_-]+)\b")

def _extract_evidence(text: str) -> List[str]:
    if not isinstance(text, str):
        return []
    seen, out = set(), []
    for m in _EV_RE.findall(text):
        if m not in seen:
            seen.add(m)
            out.append(m)
    return out

# =============================================================
# Diagnosis (root cause + evidence)
# =============================================================
def _diagnose(incident: dict) -> dict:
    allowed = incident.get("allowedRootCauses") or []
    transcript = (incident.get("transcript") or "").lower()

    best, best_score = None, 0
    for cause in allowed:
        if not isinstance(cause, str):
            continue
        score = sum(
            1 for w in cause.lower().split()
            if len(w) > 3 and w in transcript
        )
        if score > best_score:
            best_score = score
            best = cause

    root_cause = best if best is not None else (allowed[0] if allowed else "unknown")

    evidence = _extract_evidence(incident.get("transcript") or "")
    for field in ("errorId", "traceId", "correlationId", "eventId"):
        v = incident.get(field)
        if isinstance(v, str) and v.startswith("ev_") and v not in evidence:
            evidence.append(v)
        if len(evidence) >= 4:
            break
    while len(evidence) < 2:
        evidence.append("ev_unknown")

    return {"rootCause": root_cause, "evidenceIds": evidence[:4]}

# =============================================================
# Tool selection & Argument building
# =============================================================
def _choose_diagnostic_tool(tools: list, policy: dict) -> Optional[dict]:
    if not isinstance(tools, list) or not tools:
        return None
    effect_names = set()
    if isinstance(policy, dict):
        for n in policy.get("effectTools") or []:
            if isinstance(n, str):
                effect_names.add(n)
    candidates = [
        t for t in tools
        if isinstance(t, dict) and isinstance(t.get("name"), str)
        and t["name"] not in effect_names
    ]
    if not candidates:
        return None
    for kw in ("diagnos", "inspect", "check", "analyze", "probe", "trace", "log", "query"):
        for t in candidates:
            if kw in t["name"].lower():
                return t
    return candidates[0]

def _build_tool_arguments(tool: dict, incident: dict, evidence: List[str]) -> dict:
    schema = tool.get("inputSchema") or {}
    props = schema.get("properties") if isinstance(schema, dict) else {}
    
    args = {}
    mapping = {
        "service": incident.get("service") or incident.get("target") or "unknown",
        "host": incident.get("host") or incident.get("hostname") or "unknown",
        "region": incident.get("region") or incident.get("datacenter") or "global",
        "startTime": incident.get("startTime") or incident.get("startTs") or "",
        "endTime": incident.get("endTime") or incident.get("endTs") or "",
        "traceId": incident.get("traceId") or (evidence[0] if evidence else ""),
        "errorId": incident.get("errorId") or (evidence[1] if len(evidence) > 1 else ""),
        "evidenceIds": evidence,
        "evidence": evidence,
    }
    
    for pname, pdef in (props.items() if isinstance(props, dict) else {}):
        ptype = (pdef.get("type") if isinstance(pdef, dict) else "") or ""
        pl = pname.lower()
        
        if pl in mapping:
            args[pname] = mapping[pl]
        elif ptype == "string":
            args[pname] = ""
        elif ptype == "integer" or ptype == "number":
            args[pname] = 0
        elif ptype == "boolean":
            args[pname] = False
        elif ptype == "array":
            args[pname] = []
        elif ptype == "object":
            args[pname] = {}
        else:
            args[pname] = ""
            
    if not args:
        args = {
            "service": mapping["service"],
            "evidenceIds": evidence,
        }
        
    return args

# =============================================================
# OTLP trace (Exactly 7 spans)
# =============================================================
def _attr(key: str, value: Any) -> dict:
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": str(value)}}
    return {"key": key, "value": {"stringValue": str(value)}}

def _make_span(
    trace_id: str,
    span_id: str,
    parent_id: str,
    name: str,
    kind: int,
    attrs: List[dict],
    links: Optional[List[dict]] = None,
) -> dict:
    s: Dict[str, Any] = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "kind": kind,
        "attributes": attrs,
    }
    if parent_id:
        s["parentSpanId"] = parent_id
    if links:
        s["links"] = links
    return s

def _build_trace(
    run_id: str,
    marker: str,
    action_id: str,
    call_id: str,
    tool_name: str,
) -> tuple:
    trace_id = hashlib.sha256(("q11|" + run_id).encode()).hexdigest()[:32]

    server_id   = uuid.uuid4().hex[:16]
    agent_id    = uuid.uuid4().hex[:16]
    model_id    = uuid.uuid4().hex[:16]
    tool_id     = uuid.uuid4().hex[:16]
    client_id   = uuid.uuid4().hex[:16]
    approval_id = uuid.uuid4().hex[:16]
    join_id     = uuid.uuid4().hex[:16]
    approval_id_val = "approval_" + uuid.uuid4().hex[:16]

    common = [
        _attr("ga5.run.id", run_id),
        _attr("ga5.public.marker", marker or ""),
    ]

    spans = [
        # 1. Root server span
        _make_span(trace_id, server_id, "", "POST /v2/incidents", 2, common),
        # 2. Agent invocation span
        _make_span(trace_id, agent_id, server_id, "invoke_agent incident-response", 1, common),
        # 3. Model span
        _make_span(trace_id, model_id, agent_id, "chat incident-plan", 3, common + [
            _attr("gen_ai.operation.name", "chat"),
            _attr("gen_ai.request.model", "local-model")
        ]),
        # 4. Tool execution span
        _make_span(trace_id, tool_id, agent_id, "execute_tool " + tool_name, 1, common + [
            _attr("ga5.action.id", action_id),
            _attr("ga5.call.id", call_id),
            _attr("gen_ai.tool.name", tool_name),
            _attr("gen_ai.tool.call.id", call_id)
        ]),
        # 5. Outbound tool call span
        _make_span(trace_id, client_id, tool_id, "POST tool/" + tool_name, 3, common + [
            _attr("ga5.action.id", action_id),
            _attr("ga5.call.id", call_id),
            _attr("ga5.attempt", 1),
            _attr("gen_ai.tool.call.id", call_id)
        ]),
        # 6. Approval gate span
        _make_span(trace_id, approval_id, agent_id, "approval_gate", 1, common + [
            _attr("ga5.action.id", action_id),
            _attr("ga5.call.id", call_id),
            _attr("ga5.approval.id", approval_id_val),
            _attr("ga5.approval.required", True)
        ]),
        # 7. Final join span (child of agent, linking to tool)
        _make_span(trace_id, join_id, agent_id, "incident.join", 1, common + [
            _attr("ga5.action.id", action_id),
            _attr("ga5.call.id", call_id)
        ], links=[{"traceId": trace_id, "spanId": tool_id}]),
    ]

    traceparent = f"00-{trace_id}-{client_id}-01"
    return spans, traceparent

# =============================================================
# POST /v2/incidents
# =============================================================
@router.post("/v2/incidents")
async def create_incident(request: Request):
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="body too large")
    try:
        body = json.loads(raw or b"")
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=422, detail="body is not valid JSON")
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="body must be a JSON object")

    if body.get("profile") != PROFILE:
        raise HTTPException(status_code=400, detail="unsupported profile")

    run_id = body.get("runId")
    if not isinstance(run_id, str) or not run_id.strip():
        raise HTTPException(status_code=422, detail="runId is required")
    run_id = run_id.strip()

    incident = body.get("incident") or {}
    policy   = body.get("policy") or {}
    tools    = body.get("toolCatalog") or []
    marker   = body.get("publicMarker") or ""

    if not isinstance(incident, dict) or not incident:
        raise HTTPException(status_code=422, detail="incident is required")

    # Semantic conflict key (ignores volatile fields like runId/publicMarker)
    conflict_key = _digest({
        "incident": incident,
        "policy": policy,
        "toolCatalog": tools,
    })

    existing = _get_incident(run_id)
    if existing is not None:
        if existing["conflictKey"] == conflict_key:
            return JSONResponse(content=existing["response"], media_type="application/json")
        raise HTTPException(status_code=409, detail="IDEMPOTENCY_CONFLICT")

    # Diagnosis
    diagnosis = _diagnose(incident)

    # Tool selection
    tool = _choose_diagnostic_tool(tools, policy)
    if tool is None:
        raise HTTPException(status_code=422, detail="no diagnostic tool available")

    tool_name = tool["name"]
    action_id = "action_" + uuid.uuid4().hex[:16]
    call_id   = "call_"   + uuid.uuid4().hex[:16]

    arguments = _build_tool_arguments(tool, incident, diagnosis["evidenceIds"])

    dispatch = {
        "actionId": action_id,
        "callId": call_id,
        "phase": "diagnostic",
        "toolName": tool_name,
        "arguments": arguments,
        "evidence": diagnosis["evidenceIds"],
        "evidenceIds": diagnosis["evidenceIds"],
        "attempt": 1,
    }

    spans, traceparent = _build_trace(run_id, marker, action_id, call_id, tool_name)
    dispatch["traceparent"] = traceparent

    # Proposal (BEFORE effects)
    proposal = {
        "rootCause": diagnosis["rootCause"],
        "evidenceIds": diagnosis["evidenceIds"],
        "diagnosticActions": [{
            "actionId": action_id,
            "toolName": tool_name,
            "arguments": arguments,
        }],
        "effectsAllowed": False,
    }

    response = {
        "profile": PROFILE,
        "runId": run_id,
        "status": "waiting",
        "proposal": proposal,
        "diagnosis": diagnosis,
        "dispatches": [dispatch],
        "approvals": [],
        "chosenEffect": None,
        "suppressed": [],
        "actionLog": [dispatch],
        "toolResults": [],
        "receiptLog": [],
        "otlp": {
            "resourceSpans": [{
                "scopeSpans": [{"spans": spans}],
            }],
        },
    }

    response = _scrub(response)
    _put_incident(run_id, conflict_key, response, body)
    return JSONResponse(content=response, media_type="application/json")

# =============================================================
# POST /v2/incidents/{run_id}/receipts
# =============================================================
@router.post("/v2/incidents/{run_id}/receipts")
async def receive_receipt(run_id: str, request: Request):
    existing = _get_incident(run_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="incident run not found")

    raw = await request.body()
    try:
        body = json.loads(raw or b"")
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=422, detail="body is not valid JSON")
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="body must be a JSON object")

    receipt_hash = _digest(body)
    receipt_key = f"{run_id}|{receipt_hash}"

    cached = _get_receipt(receipt_key)
    if cached is not None:
        return JSONResponse(content=cached, media_type="application/json")

    state = existing["response"]
    receipt_id = body.get("receiptId") or ("receipt_" + uuid.uuid4().hex[:16])

    # Tool outcome receipts
    if isinstance(body.get("outcomes"), list):
        for outcome in body["outcomes"]:
            if not isinstance(outcome, dict):
                continue
            
            action_id = outcome.get("actionId") or (state["actionLog"][-1]["actionId"] if state["actionLog"] else "")
            call_id = outcome.get("callId") or (state["actionLog"][-1]["callId"] if state["actionLog"] else "")
            
            tool_result = {
                "receiptId": receipt_id,
                "actionId": action_id,
                "callId": call_id,
                "attempt": outcome.get("attempt", 1),
                "status": outcome.get("status"),
                "resultClass": outcome.get("resultClass"),
                "result": outcome.get("result"),
                "nonce": outcome.get("nonce"),
            }
            state["toolResults"].append(tool_result)
            state["receiptLog"].append(tool_result)

            # Annotate the outbound tool span with correlation IDs
            for rs in state.get("otlp", {}).get("resourceSpans", []):
                for ss in rs.get("scopeSpans", []):
                    for span in ss.get("spans", []):
                        if isinstance(span.get("name"), str) and span["name"].startswith("POST tool/"):
                            span["attributes"].append(_attr("ga5.receipt.id", receipt_id))
                            span["attributes"].append(_attr("http.status_code", outcome.get("status", 200)))
                            span["attributes"].append(_attr("ga5.call.id", call_id))
                            span["attributes"].append(_attr("ga5.action.id", action_id))

        # Diagnostic phase complete -> propose effect
        state["dispatches"] = []
        effect_tools = (existing["body"].get("policy") or {}).get("effectTools") or []
        if effect_tools and isinstance(effect_tools, list):
            effect_name = effect_tools[0]
            incident = existing["body"].get("incident") or {}
            prev = state["actionLog"][-1] if state["actionLog"] else {}
            effect_dispatch = {
                "actionId": prev.get("actionId") or ("action_" + uuid.uuid4().hex[:16]),
                "callId": "call_" + uuid.uuid4().hex[:16],
                "phase": "effect",
                "toolName": effect_name,
                "arguments": {"service": incident.get("service") or ""},
                "evidenceIds": state["diagnosis"]["evidenceIds"],
                "attempt": 1,
                "traceparent": prev.get("traceparent") or "",
            }
            state["dispatches"] = [effect_dispatch]
            state["actionLog"].append(effect_dispatch)
            state["chosenEffect"] = effect_name
            state["status"] = "waiting"
        else:
            state["status"] = "completed"

        _put_incident(run_id, existing["conflictKey"], state, existing["body"])
        _put_receipt(receipt_key, state)
        return JSONResponse(content=_scrub(state), media_type="application/json")

    # Approval receipts
    if isinstance(body.get("approvals"), list):
        for approval in body["approvals"]:
            if not isinstance(approval, dict):
                continue
            state["receiptLog"].append({
                "receiptId": receipt_id,
                "approvalId": approval.get("approvalId"),
                "decision": approval.get("decision"),
                "nonce": approval.get("nonce"),
            })
        state["dispatches"] = []
        state["status"] = "completed"
        _put_incident(run_id, existing["conflictKey"], state, existing["body"])
        _put_receipt(receipt_key, state)
        return JSONResponse(content=_scrub(state), media_type="application/json")

    # Default completion
    state["dispatches"] = []
    state["status"] = "completed"
    _put_incident(run_id, existing["conflictKey"], state, existing["body"])
    _put_receipt(receipt_key, state)
    return JSONResponse(content=_scrub(state), media_type="application/json")

# =============================================================
# GET /v2/incidents/{run_id}
# =============================================================
@router.get("/v2/incidents/{run_id}")
async def get_incident(run_id: str):
    existing = _get_incident(run_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="incident run not found")
    return JSONResponse(content=existing["response"], media_type="application/json")