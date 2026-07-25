import json
import uuid
import hashlib
import re

from typing import Dict, Any

from fastapi import APIRouter, HTTPException, Request


router = APIRouter()


# =====================================================
# Persistent memory
# =====================================================

INCIDENTS_DB: Dict[str, Dict[str, Any]] = {}

RECEIPTS_DB: Dict[str, str] = {}



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



def make_hex_id(length=16):

    return uuid.uuid4().hex[:length]



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



# =====================================================
# Evidence extraction
# =====================================================

def extract_evidence(text):

    ids = re.findall(
        r"\[(ev_[A-Za-z0-9_-]+)\]",
        text
    )

    return list(
        dict.fromkeys(ids)
    )



# =====================================================
# Diagnosis + Proposal
# =====================================================

def diagnose(incident):

    allowed = incident.get(
        "allowedRootCauses",
        []
    )


    transcript = incident.get(
        "transcript",
        ""
    ).lower()



    selected = None


    for cause in allowed:

        score = 0


        for word in cause.lower().split():

            if len(word) > 3 and word in transcript:

                score += 1


        if score:

            selected = cause
            break



    if selected is None and allowed:

        selected = allowed[0]



    evidence = extract_evidence(
        incident.get(
            "transcript",
            ""
        )
    )



    while len(evidence) < 2:

        evidence.append(
            "ev_unknown"
        )



    return {

        "rootCause": selected,

        "evidence":
            evidence[:4]

    }





def build_proposal(
    diagnosis,
    dispatch
):

    return {

        "rootCause":
            diagnosis["rootCause"],


        "evidenceIds":
            diagnosis["evidence"],


        "diagnosticActions":
            [
                {
                    "actionId":
                        dispatch["actionId"],

                    "toolName":
                        dispatch["toolName"],

                    "arguments":
                        dispatch["arguments"]
                }
            ],


        "effectsAllowed":
            False

    }





# =====================================================
# Tool selection
# =====================================================

def choose_diagnostic_tool(
    tools,
    policy
):

    effects = policy.get(
        "effectTools",
        []
    )


    for tool in tools:

        if tool.get("name") not in effects:

            return tool


    return None




# =====================================================
# OTLP Trace generation
# =====================================================

def create_trace(
    run_id,
    marker,
    action_id,
    call_id,
    tool_name
):


    trace_id = hashlib.sha256(
        (
            run_id +
            "trace"
        ).encode()
    ).hexdigest()[:32]



    server_id = make_hex_id()
    agent_id = make_hex_id()
    model_id = make_hex_id()
    tool_id = make_hex_id()
    client_id = make_hex_id()
    approval_id = make_hex_id()
    join_id = make_hex_id()



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



    spans = []



    # Root span

    spans.append({

        "traceId":
            trace_id,

        "spanId":
            server_id,

        "parentSpanId":
            "",

        "name":
            "POST /v2/incidents",

        "kind":
            2,

        "attributes":
            common

    })



    # Agent span

    spans.append({

        "traceId":
            trace_id,

        "spanId":
            agent_id,

        "parentSpanId":
            server_id,

        "name":
            "invoke_agent incident-response",

        "kind":
            1,

        "attributes":
            common

    })



    # Model span

    spans.append({

        "traceId":
            trace_id,

        "spanId":
            model_id,

        "parentSpanId":
            agent_id,

        "name":
            "chat incident-plan",

        "kind":
            3,

        "attributes":
            common +
            [

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



    # Tool execution span

    spans.append({

        "traceId":
            trace_id,

        "spanId":
            tool_id,

        "parentSpanId":
            agent_id,

        "name":
            "execute_tool " + tool_name,

        "kind":
            1,

        "attributes":
            common +
            [

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
                )

            ]

    })



    # Tool call span

    spans.append({

        "traceId":
            trace_id,

        "spanId":
            client_id,

        "parentSpanId":
            tool_id,

        "name":
            "POST tool/" + tool_name,

        "kind":
            3,

        "attributes":
            common +
            [

                attr(
                    "ga5.action.id",
                    action_id
                ),

                attr(
                    "ga5.attempt",
                    1
                ),

                attr(
                    "gen_ai.tool.call.id",
                    call_id
                )

            ]

    })



    # NEW approval gate span

    spans.append({

        "traceId":
            trace_id,

        "spanId":
            approval_id,

        "parentSpanId":
            agent_id,

        "name":
            "approval_gate",

        "kind":
            1,

        "attributes":
            common +
            [

                attr(
                    "ga5.action.id",
                    action_id
                ),

                attr(
                    "ga5.approval.required",
                    True
                )

            ]

    })



    # Final join

    spans.append({

        "traceId":
            trace_id,

        "spanId":
            join_id,

        "parentSpanId":
            agent_id,

        "name":
            "incident.join",

        "kind":
            1,

        "links":
            [
                {
                    "traceId":
                        trace_id,

                    "spanId":
                        tool_id
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
# POST /v2/incidents
# =====================================================

@router.post("/v2/incidents")
async def create_incident(
    request: Request
):

    body = await request.json()



    # -----------------------------
    # Validate profile
    # -----------------------------

    if body.get("profile") != "ga5-incident-agent/v2":

        raise HTTPException(
            status_code=400,
            detail="Invalid profile"
        )



    run_id = body.get(
        "runId"
    )


    if not run_id:

        raise HTTPException(
            status_code=400,
            detail="Missing runId"
        )



    body_hash = stable_hash(
        body
    )



    # -----------------------------
    # Idempotency
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



    # -----------------------------
    # Diagnosis
    # -----------------------------

    diagnosis = diagnose(
        incident
    )



    diagnostic_tool = choose_diagnostic_tool(
        tools,
        policy
    )



    if not diagnostic_tool:

        raise HTTPException(
            status_code=422,
            detail="No diagnostic tool"
        )



    tool_name = diagnostic_tool.get(
        "name"
    )



    # -----------------------------
    # IDs
    # -----------------------------

    action_id = make_id(
        "action"
    )


    call_id = make_id(
        "call"
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
            diagnosis["evidence"],


        "attempt":
            1

    }




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



    dispatch["traceparent"] = traceparent




    # -----------------------------
    # Proposal
    # -----------------------------

    proposal = build_proposal(

        diagnosis,

        dispatch

    )




    response = {


        "runId":

            run_id,


        "status":

            "waiting",



        "proposal":

            proposal,



        "diagnosis":

            diagnosis,



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



        "toolResults":

            [],



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


        "body":

            body,



        "response":

            response,



        "lastReceiptHash":

            None

    }



    return response
# =====================================================
# RECEIPTS
# =====================================================

@router.post(
    "/v2/incidents/{run_id}/receipts"
)
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



    receipt_hash = stable_hash(
        body
    )



    state = INCIDENTS_DB[run_id]

    response = state["response"]



    # -----------------------------
    # Receipt idempotency
    # -----------------------------

    if state.get("lastReceiptHash"):


        if state["lastReceiptHash"] != receipt_hash:

            raise HTTPException(
                status_code=409,
                detail="IDEMPOTENCY_CONFLICT"
            )


        return response





    receipt_id = body.get(
        "receiptId",
        make_id("receipt")
    )



    # =================================================
    # TOOL RESULTS
    # =================================================

    if "outcomes" in body:


        for outcome in body["outcomes"]:


            tool_result = {


                "receiptId":

                    receipt_id,


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


                "result":

                    outcome.get(
                        "result"
                    ),


                "nonce":

                    outcome.get(
                        "nonce"
                    )

            }



            response["toolResults"].append(
                tool_result
            )



            response["receiptLog"].append(
                tool_result
            )



            # -------------------------
            # Update trace receipt data
            # -------------------------

            for rs in response["otlp"]["resourceSpans"]:

                for ss in rs["scopeSpans"]:

                    for span in ss["spans"]:


                        if span["name"].startswith(
                            "POST tool/"
                        ):


                            span["attributes"].append(

                                attr(
                                    "ga5.receipt.id",
                                    receipt_id
                                )

                            )


                            span["attributes"].append(

                                attr(
                                    "http.status_code",
                                    outcome.get(
                                        "status",
                                        200
                                    )
                                )

                            )



        # diagnostic completed

        response["dispatches"] = []



        # -------------------------
        # Effect proposal after tool
        # -------------------------

        effect_tools = state["body"].get(
            "policy",
            {}
        ).get(
            "effectTools",
            []
        )



        if effect_tools:


            effect_action = response["actionLog"][0]


            effect_dispatch = {


                "actionId":

                    effect_action["actionId"],


                "callId":

                    make_id(
                        "call"
                    ),


                "phase":

                    "effect",


                "toolName":

                    effect_tools[0],



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
                    ["evidence"],


                "attempt":

                    1,


                "traceparent":

                    effect_action["traceparent"]

            }



            response["dispatches"] = [

                effect_dispatch

            ]



            response["actionLog"].append(
                effect_dispatch
            )



            response["chosenEffect"] = effect_tools[0]



            response["status"] = "waiting"



        else:


            response["status"] = "completed"



        state["lastReceiptHash"] = receipt_hash


        return response





    # =================================================
    # APPROVAL RECEIPT
    # =================================================

    if "approvals" in body:


        for approval in body["approvals"]:


            approval_record = {


                "receiptId":

                    receipt_id,


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


            response["receiptLog"].append(
                approval_record
            )



        response["dispatches"] = []

        response["status"] = "completed"



        state["lastReceiptHash"] = receipt_hash


        return response





    # =================================================
    # DEFAULT COMPLETION
    # =================================================

    response["dispatches"] = []

    response["status"] = "completed"



    state["lastReceiptHash"] = receipt_hash



    return response





# =====================================================
# GET INCIDENT STATE
# =====================================================

@router.get(
    "/v2/incidents/{run_id}"
)
async def get_incident(
    run_id: str
):


    if run_id not in INCIDENTS_DB:

        raise HTTPException(
            status_code=404,
            detail="Incident run not found"
        )


    return INCIDENTS_DB[run_id]["response"]