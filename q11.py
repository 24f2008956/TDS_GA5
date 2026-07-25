import json
import uuid
import hashlib
import re
import time

from typing import Dict, Any

from fastapi import APIRouter, HTTPException, Request


router = APIRouter()


# =====================================================
# Persistent memory
# =====================================================

INCIDENTS_DB: Dict[str, Dict[str, Any]] = {}

RECEIPTS_DB: Dict[str, str] = {}

RECEIPT_IDS: Dict[str, str] = {}



# =====================================================
# Helpers
# =====================================================


def stable_hash(data):

    return hashlib.sha256(
        json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":")
        ).encode()
    ).hexdigest()



def make_id(prefix):

    return (
        prefix
        + "_"
        + uuid.uuid4().hex[:16]
    )



def make_hex_id(length):

    return uuid.uuid4().hex[:length]



def extract_evidence_lines(transcript):

    result=[]

    for line in transcript.splitlines():

        m=re.search(
            r"\[(ev_[A-Za-z0-9_-]+)\]",
            line
        )

        if m:

            result.append(
                {
                    "id":m.group(1),
                    "text":line
                }
            )

    return result



# =====================================================
# Diagnosis planner
# =====================================================


def plan_diagnosis(incident):

    allowed = incident.get(
        "allowedRootCauses",
        []
    )

    transcript = incident.get(
        "transcript",
        ""
    )


    evidence_lines = extract_evidence_lines(
        transcript
    )


    best_root = None
    best_score = -1
    best_evidence=[]


    for root in allowed:

        score=0
        matched=[]

        words=[
            w.lower()
            for w in root.split()
            if len(w)>3
        ]


        for item in evidence_lines:

            text=item["text"].lower()


            hits=0

            for w in words:

                if w in text:
                    hits+=1


            if hits:

                score += hits

                matched.append(
                    item["id"]
                )


        if score > best_score:

            best_score=score
            best_root=root
            best_evidence=matched



    if not best_root and allowed:

        best_root=allowed[0]



    if len(best_evidence)<2:

        # fallback only if incident has insufficient matching lines

        for e in evidence_lines:

            if e["id"] not in best_evidence:

                best_evidence.append(
                    e["id"]
                )

            if len(best_evidence)==2:
                break



    return {

        "rootCause":best_root,

        "evidence":
            list(
                dict.fromkeys(
                    best_evidence
                )
            )[:4]

    }




# =====================================================
# Tool planner
# =====================================================


def choose_diagnostic_tool(
    tools,
    policy
):

    effect_tools = policy.get(
        "effectTools",
        []
    )


    for tool in tools:

        if tool.get("name") not in effect_tools:

            return tool



    return None




def choose_effect_tool(
    tools,
    policy
):

    allowed = policy.get(
        "effectTools",
        []
    )


    for tool in tools:

        if tool.get("name") in allowed:

            return tool


    return None




# =====================================================
# OTLP Trace
# =====================================================


def attribute(
    key,
    value
):

    if isinstance(value,int):

        return {
            "key":key,
            "value":{
                "intValue":value
            }
        }


    return {
        "key":key,
        "value":{
            "stringValue":str(value)
        }
    }




def create_trace(
    run_id,
    marker,
    action_id,
    call_id,
    tool_name,
    receipt_id=""
):


    trace_id = hashlib.sha256(
        (
            run_id
            +
            "trace"
        ).encode()
    ).hexdigest()[:32]



    server_id=make_hex_id(16)
    agent_id=make_hex_id(16)
    model_id=make_hex_id(16)
    exec_id=make_hex_id(16)
    client_id=make_hex_id(16)
    join_id=make_hex_id(16)



    common=[

        attribute(
            "ga5.run.id",
            run_id
        ),

        attribute(
            "ga5.public.marker",
            marker
        )

    ]



    spans=[]



    spans.append({

        "traceId":trace_id,

        "spanId":server_id,

        "parentSpanId":"",

        "name":
            "POST /v2/incidents",

        "kind":2,

        "attributes":
            common

    })



    spans.append({

        "traceId":trace_id,

        "spanId":agent_id,

        "parentSpanId":server_id,

        "name":
            "invoke_agent incident-response",

        "kind":1,

        "attributes":
            common

    })



    spans.append({

        "traceId":trace_id,

        "spanId":model_id,

        "parentSpanId":agent_id,

        "name":
            "chat incident-plan",

        "kind":3,

        "attributes":
            common
            +
            [

            attribute(
                "gen_ai.operation.name",
                "chat"
            ),

            attribute(
                "gen_ai.request.model",
                "local-model"
            )

            ]

    })



    spans.append({

        "traceId":trace_id,

        "spanId":exec_id,

        "parentSpanId":agent_id,

        "name":
            "execute_tool "+tool_name,

        "kind":1,

        "attributes":
            common
            +
            [

            attribute(
                "ga5.action.id",
                action_id
            ),

            attribute(
                "gen_ai.tool.name",
                tool_name
            ),

            attribute(
                "gen_ai.tool.call.id",
                call_id
            ),

            attribute(
                "gen_ai.operation.name",
                "execute_tool"
            )

            ]

    })



    spans.append({

        "traceId":trace_id,

        "spanId":client_id,

        "parentSpanId":exec_id,

        "name":
            "POST tool/"+tool_name,

        "kind":3,


        "attributes":
            common
            +
            [

            attribute(
                "ga5.action.id",
                action_id
            ),

            attribute(
                "gen_ai.tool.call.id",
                call_id
            ),

            attribute(
                "ga5.attempt",
                1
            ),

            attribute(
                "ga5.receipt.id",
                receipt_id
            ),

            attribute(
                "http.request.method",
                "POST"
            ),

            attribute(
                "http.request.resend_count",
                0
            )

            ]

    })



    spans.append({

        "traceId":trace_id,

        "spanId":join_id,

        "parentSpanId":agent_id,

        "name":
            "incident.join",

        "kind":1,

        "links":[
            {
                "traceId":trace_id,
                "spanId":exec_id
            }
        ],

        "attributes":
            common

    })



    traceparent = (
        "00-"
        +
        trace_id
        +
        "-"
        +
        client_id
        +
        "-01"
    )


    return spans, traceparent

# =====================================================
# RECEIPT HANDLER
# =====================================================

@router.post("/v2/incidents/{run_id}/receipts")
async def receive_receipt(
    run_id: str,
    request: Request
):

    if run_id not in INCIDENTS_DB:
        raise HTTPException(
            status_code=404,
            detail="Incident run not found"
        )


    body = await request.json()

    receipt_hash = stable_hash(body)


    state = INCIDENTS_DB[run_id]


    # replay receipt
    if state.get("lastReceiptHash"):

        if state["lastReceiptHash"] != receipt_hash:
            raise HTTPException(
                status_code=409,
                detail="IDEMPOTENCY_CONFLICT"
            )

        return state["response"]



    response = state["response"]


    # -------------------------------
    # TOOL OUTCOME RECEIPTS
    # -------------------------------

    if "outcomes" in body:


        for outcome in body["outcomes"]:


            receipt = {

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
                receipt
            )



            # update OTLP client span
            for rs in response["otlp"]["resourceSpans"]:

                for ss in rs["scopeSpans"]:

                    for span in ss["spans"]:


                        if span["name"].startswith(
                            "POST tool/"
                        ):


                            span["attributes"].append(
                                attr(
                                    "ga5.receipt.id",
                                    receipt["receiptId"]
                                )
                            )


                            span["attributes"].append(
                                attr(
                                    "ga5.receipt.nonce",
                                    receipt["nonce"]
                                )
                            )


                            span["attributes"].append(
                                attr(
                                    "http.status_code",
                                    receipt["status"]
                                )
                            )



            # -------------------------
            # 503 RETRY
            # -------------------------

            if outcome.get("status") == 503:


                old = response["actionLog"][0]


                retry = old.copy()


                retry["attempt"] = 2


                parts = old["traceparent"].split("-")


                new_span = uuid.uuid4().hex[:16]


                retry["traceparent"] = (
                    parts[0]
                    + "-"
                    + parts[1]
                    + "-"
                    + new_span
                    + "-01"
                )


                response["dispatches"] = [
                    retry
                ]


                response["actionLog"].append(
                    retry
                )


                response["status"] = "waiting"


                state["lastReceiptHash"] = receipt_hash


                return response



            # -------------------------
            # TIMEOUT
            # -------------------------

            if (
                outcome.get("status") == 0
                and
                outcome.get("errorType")
                ==
                "timeout"
            ):


                response["status"] = "failed"


                response["dispatches"] = []


                response["suppressed"].append(
                    "effect_blocked_timeout"
                )


                state["lastReceiptHash"] = receipt_hash


                return response



        # diagnostic success

        response["dispatches"] = []


        # choose effect

        policy = state["body"].get(
            "policy",
            {}
        )


        effects = policy.get(
            "effectTools",
            []
        )


        if effects:


            effect = effects[0]


            action_id = (
                response["actionLog"][0]
                ["actionId"]
            )


            call_id = make_id(
                "call"
            )


            effect_dispatch = {


                "actionId":
                    action_id,


                "callId":
                    call_id,


                "phase":
                    "effect",


                "toolName":
                    effect,


                "arguments":
                    {
                        "service":
                            state["body"]
                            ["incident"]
                            .get(
                                "service",
                                ""
                            )
                    },


                "evidence":
                    response["diagnosis"]
                    ["evidence"][:2],


                "attempt":
                    1,


                "traceparent":
                    response["actionLog"][0]
                    ["traceparent"]

            }



            response["dispatches"] = [
                effect_dispatch
            ]


            response["actionLog"].append(
                effect_dispatch
            )


            response["chosenEffect"] = effect


            response["status"]="waiting"


            state["lastReceiptHash"] = receipt_hash


            return response



    # -------------------------------
    # APPROVAL
    # -------------------------------


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


        response["dispatches"] = []


        response["status"] = "completed"


        state["lastReceiptHash"] = receipt_hash


        return response



    # normal completion

    response["dispatches"] = []

    response["status"] = "completed"


    state["lastReceiptHash"] = receipt_hash


    return response




# =====================================================
# GET STORED STATE
# =====================================================


@router.get("/v2/incidents/{run_id}")
async def get_incident(
    run_id:str
):

    if run_id not in INCIDENTS_DB:

        raise HTTPException(
            status_code=404,
            detail="Incident run not found"
        )


    return INCIDENTS_DB[run_id]["response"]