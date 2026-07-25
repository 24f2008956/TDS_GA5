import json
import uuid
import hashlib
import re
import time

from typing import Dict, Any

from fastapi import APIRouter, HTTPException, Request


router = APIRouter()


# =====================================================
# Persistent storage
# =====================================================

INCIDENTS_DB: Dict[str, Dict[str, Any]] = {}

RECEIPTS_DB: Dict[str, str] = {}



# =====================================================
# Utility
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



def hex_id():

    return uuid.uuid4().hex[:16]



# =====================================================
# Evidence extraction
# =====================================================

def extract_evidence(transcript):

    ids=[]

    for line in transcript.splitlines():

        m = re.search(
            r"\[(ev_[A-Za-z0-9_-]+)\]",
            line
        )

        if m:
            ids.append(m.group(1))


    return list(dict.fromkeys(ids))[:4]



# =====================================================
# Root cause planner
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
    evidence=[]



    for cause in allowed:

        score=0

        for word in cause.lower().split():

            if len(word)>3 and word in transcript:

                score += 1



        if score:

            selected=cause
            break



    if selected is None and allowed:

        selected=allowed[0]



    ev = extract_evidence(
        incident.get(
            "transcript",
            ""
        )
    )


    evidence=ev[:4]


    while len(evidence)<2:

        evidence.append(
            "ev_unknown"
        )


    return {

        "rootCause":selected,

        "evidence":
            evidence[:4]

    }



# =====================================================
# Tool selection
# =====================================================

def choose_diagnostic_tools(
    catalog,
    policy,
    diagnosis
):

    effect=set(
        policy.get(
            "effectTools",
            []
        )
    )


    result=[]


    for tool in catalog:

        name=tool.get(
            "name"
        )


        if name not in effect:

            result.append(tool)



    return result[:3]



def make_arguments(
    tool,
    incident
):

    schema = tool.get(
        "inputSchema",
        {}
    )


    props = schema.get(
        "properties",
        {}
    )


    args={}


    for key in props:

        if key=="service":

            args[key]=incident.get(
                "service",
                ""
            )

        elif key=="window":

            args[key]="10m"

        elif key=="metric":

            args[key]="error_rate"



    return args

# =====================================================
# OTLP helpers
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



def create_otlp_trace(
    run_id,
    marker,
    dispatches
):

    trace_id = hashlib.sha256(
        (run_id + "trace").encode()
    ).hexdigest()[:32]


    spans=[]


    server_id = hex_id()
    agent_id = hex_id()
    model_id = hex_id()



    common=[

        attr(
            "ga5.run.id",
            run_id
        ),

        attr(
            "ga5.public.marker",
            marker
        )

    ]



    # SERVER

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



    # AGENT

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



    # MODEL

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



    execute_ids=[]


    for dispatch in dispatches:


        exec_id=hex_id()

        client_id=hex_id()


        execute_ids.append(
            exec_id
        )


        # INTERNAL execute_tool

        spans.append({

            "traceId":trace_id,

            "spanId":exec_id,

            "parentSpanId":agent_id,

            "name":
                "execute_tool "
                +
                dispatch["toolName"],

            "kind":1,

            "attributes":
                common
                +
                [

                    attr(
                        "ga5.action.id",
                        dispatch["actionId"]
                    ),

                    attr(
                        "gen_ai.tool.name",
                        dispatch["toolName"]
                    ),

                    attr(
                        "gen_ai.tool.call.id",
                        dispatch["callId"]
                    ),

                    attr(
                        "gen_ai.operation.name",
                        "execute_tool"
                    )

                ]

        })



        # CLIENT tool call

        spans.append({

            "traceId":trace_id,

            "spanId":client_id,

            "parentSpanId":exec_id,

            "name":
                "POST tool/"
                +
                dispatch["toolName"],

            "kind":3,

            "attributes":
                common
                +
                [

                    attr(
                        "ga5.action.id",
                        dispatch["actionId"]
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
                    )

                ]

        })



        dispatch["traceparent"]=(
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



    # join span only when parallel diagnostics exist

    if len(execute_ids)>0:


        spans.append({

            "traceId":trace_id,

            "spanId":hex_id(),

            "parentSpanId":agent_id,

            "name":
                "incident.join",

            "kind":1,

            "links":[

                {
                    "traceId":trace_id,
                    "spanId":x
                }

                for x in execute_ids

            ],

            "attributes":
                common

        })



    return {

        "resourceSpans":[

            {

                "scopeSpans":[

                    {

                        "spans":spans

                    }

                ]

            }

        ]

    }



# =====================================================
# POST /v2/incidents
# =====================================================

@router.post("/v2/incidents")
async def create_incident(request: Request):


    body = await request.json()



    if body.get(
        "profile"
    ) != "ga5-incident-agent/v2":

        raise HTTPException(
            400,
            "Invalid profile"
        )



    run_id = body.get(
        "runId"
    )


    if not run_id:

        raise HTTPException(
            400,
            "Missing runId"
        )



    request_hash = stable_hash(
        body
    )



    # replay protection

    if run_id in INCIDENTS_DB:


        old=INCIDENTS_DB[run_id]


        if old["hash"] != request_hash:

            raise HTTPException(
                409,
                "IDEMPOTENCY_CONFLICT"
            )


        return old["response"]




    incident=body.get(
        "incident",
        {}
    )


    policy=body.get(
        "policy",
        {}
    )


    catalog=body.get(
        "toolCatalog",
        []
    )



    diagnosis=diagnose(
        incident
    )



    tools=choose_diagnostic_tools(
        catalog,
        policy,
        diagnosis
    )



    dispatches=[]


    for tool in tools:


        action_id=make_id(
            "action"
        )


        call_id=make_id(
            "call"
        )


        dispatches.append({

            "actionId":
                action_id,

            "callId":
                call_id,

            "phase":
                "diagnostic",

            "toolName":
                tool["name"],

            "arguments":
                make_arguments(
                    tool,
                    incident
                ),

            "evidence":
                diagnosis["evidence"][:2],

            "attempt":
                1

        })



    otlp=create_otlp_trace(

        run_id,

        body.get(
            "publicMarker",
            ""
        ),

        dispatches

    )



    response={

        "runId":
            run_id,


        "status":
            "waiting",


        "diagnosis":
            diagnosis,


        "dispatches":
            dispatches,


        "approvals":
            [],


        "chosenEffect":
            None,


        "suppressed":
            [],


        "actionLog":
            dispatches.copy(),


        "receiptLog":
            [],


        "otlp":
            otlp

    }



    # Store WITHOUT sensitive fields

    INCIDENTS_DB[run_id]={

        "hash":
            request_hash,

        "response":
            response,

        "body":{

            "incident":
                incident,

            "policy":
                policy,

            "toolCatalog":
                catalog

        },

        "pending":
            dispatches

    }



    return response
# =====================================================
# POST RECEIPTS
# =====================================================

@router.post("/v2/incidents/{run_id}/receipts")
async def receive_receipt(
    run_id: str,
    request: Request
):

    if run_id not in INCIDENTS_DB:

        raise HTTPException(
            404,
            "Incident run not found"
        )



    body = await request.json()


    receipt_hash = stable_hash(
        body
    )


    state = INCIDENTS_DB[run_id]

    response = state["response"]



    # -----------------------------
    # Receipt replay protection
    # -----------------------------

    if state.get("lastReceiptHash"):


        if state["lastReceiptHash"] != receipt_hash:

            raise HTTPException(
                409,
                "IDEMPOTENCY_CONFLICT"
            )


        return response




    # -----------------------------
    # Diagnostic outcomes
    # -----------------------------

    if "outcomes" in body:


        for outcome in body["outcomes"]:


            receipt={

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



            # -------------------------
            # Retry only 503
            # -------------------------

            if outcome.get(
                "status"
            ) == 503:


                old = None


                for a in response["actionLog"]:

                    if (
                        a["actionId"]
                        ==
                        outcome.get("actionId")
                    ):
                        old=a
                        break



                if old:


                    retry = old.copy()


                    retry["callId"] = make_id(
                        "call"
                    )


                    retry["attempt"]=2


                    parts = old[
                        "traceparent"
                    ].split("-")



                    retry_span = hex_id()



                    retry["traceparent"]=(
                        parts[0]
                        +
                        "-"
                        +
                        parts[1]
                        +
                        "-"
                        +
                        retry_span
                        +
                        "-01"
                    )



                    response["dispatches"]=[
                        retry
                    ]


                    response["actionLog"].append(
                        retry
                    )


                    response["status"]="waiting"



                    state["lastReceiptHash"] = receipt_hash

                    return response




            # -------------------------
            # Timeout failure
            # -------------------------

            if (

                outcome.get("status")
                ==
                0

                and

                outcome.get("errorType")
                ==
                "timeout"

            ):


                response["status"]="failed"


                response["dispatches"]=[]


                response["suppressed"].append(
                    "effect_not_executed_timeout"
                )



                state["lastReceiptHash"] = receipt_hash


                return response





        # Diagnostics passed
        # Decide effect


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


            original = response["actionLog"][0]



            effect_dispatch={


                "actionId":
                    original["actionId"],


                "callId":
                    make_id(
                        "call"
                    ),


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
                    original[
                        "traceparent"
                    ]

            }



            response["dispatches"]=[

                effect_dispatch

            ]


            response["actionLog"].append(

                effect_dispatch

            )


            response["chosenEffect"]=effect


            response["status"]="waiting"


            state["lastReceiptHash"]=receipt_hash


            return response




        response["status"]="completed"


        response["dispatches"]=[]



    # -----------------------------
    # Approval receipts
    # -----------------------------

    if "approvals" in body:


        for approval in body["approvals"]:


            response["receiptLog"].append({

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

            })



        response["dispatches"]=[]

        response["status"]="completed"



    # -----------------------------
    # Save receipt state
    # -----------------------------

    state["lastReceiptHash"] = receipt_hash


    return response




# =====================================================
# GET stored state
# =====================================================

@router.get("/v2/incidents/{run_id}")
async def get_incident(
    run_id: str
):

    if run_id not in INCIDENTS_DB:

        raise HTTPException(
            404,
            "Incident run not found"
        )


    return INCIDENTS_DB[run_id]["response"]