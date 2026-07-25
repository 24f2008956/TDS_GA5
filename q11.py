import json
import time
import uuid
import hashlib
import re
from typing import Dict, Any, Optional

from fastapi import APIRouter, HTTPException, Request

router = APIRouter()

INCIDENTS_DB: Dict[str, Dict[str, Any]] = {}
RECEIPTS_DB: Dict[str, Dict[str, Any]] = {}


# -----------------------------
# Helpers
# -----------------------------

def sha256_json(data):
    return hashlib.sha256(
        json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":")
        ).encode()
    ).hexdigest()


def new_id(prefix):
    return prefix + "_" + uuid.uuid4().hex[:12]


def extract_evidence(transcript):
    ids = re.findall(r"\[(ev_[A-Za-z0-9_-]+)\]", transcript)
    return list(dict.fromkeys(ids))[:4]


def choose_root_cause(incident):

    allowed = incident.get(
        "allowedRootCauses",
        []
    )

    transcript = incident.get(
        "transcript",
        ""
    ).lower()

    # simple deterministic reasoning layer
    for cause in allowed:
        words = cause.lower().split()
        if any(w in transcript for w in words):
            return cause

    if allowed:
        return allowed[0]

    return "unknown"


def make_trace(run_id):

    trace_id = hashlib.sha256(
        run_id.encode()
    ).hexdigest()[:32]

    def span(name, parent, kind):
        sid = uuid.uuid4().hex[:16]

        return {
            "traceId": trace_id,
            "spanId": sid,
            "parentSpanId": parent,
            "name": name,
            "kind": kind,
            "attributes": [
                {
                    "key": "ga5.run.id",
                    "value": {
                        "stringValue": run_id
                    }
                }
            ]
        }, sid

    spans = []

    root, root_id = span(
        "POST /v2/incidents",
        "",
        2
    )
    spans.append(root)

    agent, agent_id = span(
        "invoke_agent incident-response",
        root_id,
        1
    )
    spans.append(agent)

    model, model_id = span(
        "chat incident-plan",
        agent_id,
        3
    )

    model["attributes"].extend([
        {
            "key":"gen_ai.operation.name",
            "value":{"stringValue":"chat"}
        },
        {
            "key":"gen_ai.request.model",
            "value":{"stringValue":"local-model"}
        }
    ])

    spans.append(model)

    return spans, trace_id


# -----------------------------
# Create Incident
# -----------------------------

@router.post("/v2/incidents")
async def create_incident(request: Request):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            400,
            "Invalid JSON"
        )


    if body.get("profile") != "ga5-incident-agent/v2":
        raise HTTPException(
            400,
            "Invalid profile"
        )


    run_id = body.get("runId")

    if not run_id:
        raise HTTPException(
            400,
            "Missing runId"
        )


    request_hash = sha256_json(body)


    # replay/conflict
    if run_id in INCIDENTS_DB:

        old = INCIDENTS_DB[run_id]

        if old["requestHash"] != request_hash:
            raise HTTPException(
                status_code=409,
                detail="IDEMPOTENCY_CONFLICT"
            )

        return old["response"]



    incident = body.get(
        "incident",
        {}
    )

    transcript = incident.get(
        "transcript",
        ""
    )


    evidence = extract_evidence(
        transcript
    )

    root = choose_root_cause(
        incident
    )


    action_id = new_id("action")

    call_id = new_id("call")


    trace_spans, trace_id = make_trace(
        run_id
    )


    dispatch = {

        "actionId": action_id,

        "callId": call_id,

        "phase":"diagnostic",

        "toolName":
            "query_metrics",

        "arguments":{
            "service":
                incident.get(
                    "service",
                    ""
                )
        },

        "evidence":
            evidence[:1],

        "attempt":1,

        "traceparent":
            f"00-{trace_id}-{uuid.uuid4().hex[:16]}-01"
    }


    response = {

        "runId":run_id,

        "status":"waiting",

        "diagnosis":{
            "rootCause":root,
            "evidence":evidence
        },


        "dispatches":[
            dispatch
        ],


        "approvals":[],


        "actionLog":[
            dispatch
        ],


        "receiptLog":[],


        "otlp":{
            "resourceSpans":[
                {
                    "scopeSpans":[
                        {
                            "spans":
                                trace_spans
                        }
                    ]
                }
            ]
        }
    }


    INCIDENTS_DB[run_id] = {

        "requestHash":
            request_hash,

        "response":
            response,

        "pending":{
            action_id:
            dispatch
        }

    }


    return response



# -----------------------------
# Receipts
# -----------------------------

@router.post(
"/v2/incidents/{run_id}/receipts"
)
async def receipts(
    run_id:str,
    request:Request
):

    if run_id not in INCIDENTS_DB:
        raise HTTPException(
            404,
            "Incident run not found"
        )


    body = await request.json()

    receipt_hash = sha256_json(body)


    if run_id in RECEIPTS_DB:

        old = RECEIPTS_DB[run_id]

        if old["hash"] != receipt_hash:
            raise HTTPException(
                409,
                "IDEMPOTENCY_CONFLICT"
            )

        return INCIDENTS_DB[run_id]["response"]



    state = INCIDENTS_DB[run_id]

    response = state["response"]


    receipt_entry = {

        "receiptId":
            body.get(
                "receiptId",
                new_id("receipt")
            ),

        "raw":
            body
    }


    response["receiptLog"].append(
        receipt_entry
    )


    response["dispatches"] = []


    response["status"]="completed"


    RECEIPTS_DB[run_id]={
        "hash":receipt_hash
    }


    return response



# -----------------------------
# Get
# -----------------------------

@router.get(
"/v2/incidents/{run_id}"
)
async def get_incident(
    run_id:str
):

    if run_id not in INCIDENTS_DB:
        raise HTTPException(
            404,
            "Incident run not found"
        )

    return INCIDENTS_DB[run_id]["response"]