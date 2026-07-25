import json
import time
import uuid
import hashlib
import re
from typing import Dict, Any

from fastapi import APIRouter, HTTPException, Request

router = APIRouter()

INCIDENTS_DB: Dict[str, Dict[str, Any]] = {}
RECEIPT_DB: Dict[str, str] = {}


# =====================================================
# Helpers
# =====================================================

def stable_hash(obj):
    return hashlib.sha256(
        json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":")
        ).encode()
    ).hexdigest()


def make_id(prefix):
    return prefix + "_" + uuid.uuid4().hex[:12]


def extract_evidence(text):
    ids = re.findall(
        r"\[(ev_[A-Za-z0-9_-]+)\]",
        text
    )
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

    best = None

    for cause in allowed:
        score = 0

        for word in cause.lower().split():
            if word in transcript:
                score += 1

        if score > 0:
            best = cause
            break

    if best:
        return best

    if allowed:
        return allowed[0]

    return "unknown"


def choose_tool(tool_catalog, policy):

    effects = policy.get(
        "effectTools",
        []
    )

    for tool in tool_catalog:
        if tool.get("name") not in effects:
            return tool.get("name")

    return None



# =====================================================
# OTLP
# =====================================================

def attr(key, value):

    if isinstance(value, int):
        return {
            "key": key,
            "value": {
                "intValue": value
            }
        }

    return {
        "key": key,
        "value": {
            "stringValue": str(value)
        }
    }



def create_trace(
    run_id,
    marker,
    action_id,
    call_id,
    tool_name
):

    trace_id = hashlib.sha256(
        (run_id+"trace").encode()
    ).hexdigest()[:32]


    server_id = uuid.uuid4().hex[:16]
    agent_id = uuid.uuid4().hex[:16]
    model_id = uuid.uuid4().hex[:16]
    tool_id = uuid.uuid4().hex[:16]
    client_id = uuid.uuid4().hex[:16]
    join_id = uuid.uuid4().hex[:16]


    common = [
        attr(
            "ga5.run.id",
            run_id
        ),
        attr(
            "ga5.public.marker",
            marker
        )
    ]


    spans=[]


    spans.append({
        "traceId":trace_id,
        "spanId":server_id,
        "parentSpanId":"",
        "name":"POST /v2/incidents",
        "kind":2,
        "attributes":common
    })


    spans.append({
        "traceId":trace_id,
        "spanId":agent_id,
        "parentSpanId":server_id,
        "name":"invoke_agent incident-response",
        "kind":1,
        "attributes":common
    })


    spans.append({
        "traceId":trace_id,
        "spanId":model_id,
        "parentSpanId":agent_id,
        "name":"chat incident-plan",
        "kind":3,
        "attributes":
            common + [
                attr(
                    "gen_ai.operation.name",
                    "chat"
                ),
                attr(
                    "gen_ai.request.model",
                    "local-model"
                )
            ]
    })


    spans.append({
        "traceId":trace_id,
        "spanId":tool_id,
        "parentSpanId":agent_id,
        "name":"execute_tool "+tool_name,
        "kind":1,
        "attributes":
            common + [
                attr(
                    "ga5.action.id",
                    action_id
                ),
                attr(
                    "gen_ai.tool.name",
                    tool_name
                ),
                attr(
                    "gen_ai.tool.call.id",
                    call_id
                ),
                attr(
                    "gen_ai.operation.name",
                    "execute_tool"
                )
            ]
    })


    spans.append({
        "traceId":trace_id,
        "spanId":client_id,
        "parentSpanId":tool_id,
        "name":"POST tool/"+tool_name,
        "kind":3,
        "attributes":
            common + [
                attr(
                    "ga5.action.id",
                    action_id
                ),
                attr(
                    "ga5.attempt",
                    1
                ),
                attr(
                    "ga5.receipt.id",
                    ""
                ),
                attr(
                    "http.request.method",
                    "POST"
                ),
                attr(
                    "http.request.resend_count",
                    0
                ),
                attr(
                    "http.status_code",
                    200
                )
            ]
    })


    spans.append({
        "traceId":trace_id,
        "spanId":join_id,
        "parentSpanId":agent_id,
        "name":"incident.join",
        "kind":1,
        "attributes":common
    })


    traceparent = (
        "00-"
        + trace_id
        + "-"
        + client_id
        + "-01"
    )


    return spans, traceparent

# =====================================================
# POST /v2/incidents
# =====================================================

@router.post("/v2/incidents")
async def create_incident(request: Request):

    body = await request.json()

    if body.get("profile") != "ga5-incident-agent/v2":
        raise HTTPException(
            status_code=400,
            detail="Invalid profile"
        )


    run_id = body.get("runId")

    if not run_id:
        raise HTTPException(
            status_code=400,
            detail="Missing runId"
        )


    body_hash = stable_hash(body)


    # -----------------------------
    # Replay / Conflict
    # -----------------------------

    if run_id in INCIDENTS_DB:

        old = INCIDENTS_DB[run_id]

        if old["hash"] != body_hash:
            raise HTTPException(
                status_code=409,
                detail="IDEMPOTENCY_CONFLICT"
            )

        return old["response"]



    incident = body.get(
        "incident",
        {}
    )

    policy = body.get(
        "policy",
        {}
    )

    tools = body.get(
        "toolCatalog",
        []
    )


    transcript = incident.get(
        "transcript",
        ""
    )


    evidence = extract_evidence(
        transcript
    )


    if len(evidence) < 2:
        evidence = (
            evidence +
            ["ev_unknown"]
        )[:2]


    root = choose_root_cause(
        incident
    )


    tool_name = choose_tool(
        tools,
        policy
    )


    if not tool_name:
        raise HTTPException(
            status_code=422,
            detail="No diagnostic tool"
        )


    action_id = make_id(
        "action"
    )

    call_id = make_id(
        "call"
    )


    spans, traceparent = create_trace(
        run_id,
        body.get(
            "publicMarker",
            ""
        ),
        action_id,
        call_id,
        tool_name
    )


    dispatch = {

        "actionId":
            action_id,

        "callId":
            call_id,

        "phase":
            "diagnostic",

        "toolName":
            tool_name,

        "arguments":
            {
                "service":
                    incident.get(
                        "service",
                        ""
                    )
            },

        "evidence":
            evidence[:1],

        "attempt":
            1,

        "traceparent":
            traceparent
    }



    response = {

        "runId":
            run_id,

        "status":
            "waiting",


        "diagnosis":
            {
                "rootCause":
                    root,

                "evidence":
                    evidence[:4]
            },


        "dispatches":
            [
                dispatch
            ],


        "approvals":
            [],


        "chosenEffect":
            None,


        "suppressed":
            [],


        "actionLog":
            [
                dispatch
            ],


        "receiptLog":
            [],


        "otlp":
            {
                "resourceSpans":
                    [
                        {
                            "scopeSpans":
                                [
                                    {
                                        "spans":
                                            spans
                                    }
                                ]
                        }
                    ]
            }
    }


    INCIDENTS_DB[run_id] = {

        "hash":
            body_hash,

        "response":
            response,

        "pending":
            {
                action_id:
                    dispatch
            },

        "body":
            body
    }


    return response



# =====================================================
# RECEIPTS
# =====================================================

@router.post(
    "/v2/incidents/{run_id}/receipts"
)
async def receive_receipt(
    run_id:str,
    request:Request
):

    if run_id not in INCIDENTS_DB:
        raise HTTPException(
            status_code=404,
            detail="Incident run not found"
        )


    body = await request.json()


    receipt_hash = stable_hash(body)


    if run_id in RECEIPT_DB:

        if RECEIPT_DB[run_id] != receipt_hash:
            raise HTTPException(
                status_code=409,
                detail="IDEMPOTENCY_CONFLICT"
            )

        return INCIDENTS_DB[run_id]["response"]



    state = INCIDENTS_DB[run_id]

    response = state["response"]



    # -----------------------------
    # Store safe receipt only
    # -----------------------------

    if "outcomes" in body:

        for outcome in body["outcomes"]:

            safe_receipt = {

                "receiptId":
                    body.get(
                        "receiptId",
                        make_id("receipt")
                    ),

                "actionId":
                    outcome.get(
                        "actionId"
                    ),

                "callId":
                    outcome.get(
                        "callId"
                    ),

                "attempt":
                    outcome.get(
                        "attempt",
                        1
                    ),

                "status":
                    outcome.get(
                        "status"
                    ),

                "resultClass":
                    outcome.get(
                        "resultClass"
                    ),

                "nonce":
                    outcome.get(
                        "nonce"
                    )
            }


            response["receiptLog"].append(
                safe_receipt
            )


            # -------------------------
            # Retry on 503
            # -------------------------

            if outcome.get(
                "status"
            ) == 503:


                old = response["actionLog"][0]


                retry = dict(old)

                retry["attempt"] = 2

                retry["traceparent"] = (
                    old["traceparent"][:35]
                    +
                    uuid.uuid4().hex[:16]
                    +
                    "-01"
                )


                response["dispatches"] = [
                    retry
                ]

                response["actionLog"].append(
                    retry
                )


                response["status"]="waiting"


                RECEIPT_DB[run_id]=receipt_hash

                return response



            # -------------------------
            # Timeout suppression
            # -------------------------

            if outcome.get(
                "status"
            ) == 0 and outcome.get(
                "errorType"
            ) == "timeout":

                response["suppressed"].append(
                    "effect_not_run_due_to_timeout"
                )

                response["dispatches"]=[]

                response["status"]="failed"

                RECEIPT_DB[run_id]=receipt_hash

                return response



    # -----------------------------
    # Approval receipts
    # -----------------------------

    if "approvals" in body:

        for approval in body["approvals"]:

            response["receiptLog"].append(
                {
                    "receiptId":
                        body.get(
                            "receiptId",
                            make_id("receipt")
                        ),

                    "approvalId":
                        approval.get(
                            "approvalId"
                        ),

                    "decision":
                        approval.get(
                            "decision"
                        ),

                    "nonce":
                        approval.get(
                            "nonce"
                        )
                }
            )


        response["status"]="completed"

        response["dispatches"]=[]


        RECEIPT_DB[run_id]=receipt_hash

        return response



    # -----------------------------
    # Normal completion
    # -----------------------------

    response["dispatches"]=[]

    response["status"]="completed"


    RECEIPT_DB[run_id]=receipt_hash


    return response




# =====================================================
# GET
# =====================================================

@router.get(
    "/v2/incidents/{run_id}"
)
async def get_incident(
    run_id:str
):

    if run_id not in INCIDENTS_DB:

        raise HTTPException(
            status_code=404,
            detail="Incident run not found"
        )


    return INCIDENTS_DB[run_id]["response"]