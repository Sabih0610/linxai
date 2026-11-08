r"""Planning as an explicit state graph (original requirement 5, LangGraph workflow).

    normalize -> deterministic --(request)--------------------------------> END
                      \--(none)--> classify_fast --(plan)--> validate -> adapt -> END
                                         \--(none)--> model ---/

Every node is a pure state update; routing is a separate function, so the same
graph runs on LangGraph's StateGraph when the optional `langgraph` package is
installed and on the bounded built-in runner otherwise. The graph only produces
a typed request: validation, preview, confirmation and authorization remain in
the registry/jobs/broker path, and the model node cannot add authority.
"""
import operator
from typing import Annotated, Any, TypedDict

from .fast_path import classify_fast
from .plan_schema import validate_plan
from operations.plans import adapt_plan

MAX_STEPS = 8


class PlanningState(TypedDict, total=False):
    text: str
    context: Any
    request: Any
    plan: Any
    trace: Annotated[list, operator.add]


def nodes(planner):
    from .local_planner import typed_request

    def normalize(state):
        return {"text": planner.check_text(state["text"]).strip(), "trace": ["normalize"]}

    def deterministic(state):
        found = planner.deterministic(state["text"], state.get("context", ()))
        update = {"trace": ["deterministic"]}
        if found is not None:
            update["request"], update["plan"] = found
        return update

    def fast(state):
        return {"plan": classify_fast(state["text"]), "trace": ["classify_fast"]}

    def model(state):
        return {"plan": planner.model.generate(state["text"], state.get("context", ())), "trace": ["model"]}

    def validate(state):
        return {"plan": validate_plan(state["plan"]), "trace": ["validate"]}

    def adapt(state):
        return {"request": typed_request(adapt_plan(state["plan"], planner.registry)), "trace": ["adapt"]}

    return {"normalize": normalize, "deterministic": deterministic, "classify_fast": fast,
            "model": model, "validate": validate, "adapt": adapt}


END = "__end__"
EDGES = {"normalize": lambda s: "deterministic",
         "deterministic": lambda s: END if s.get("request") else "classify_fast",
         "classify_fast": lambda s: "validate" if s.get("plan") else "model",
         "model": lambda s: "validate",
         "validate": lambda s: "adapt",
         "adapt": lambda s: END}


def run_builtin(planner, state):
    table, node = nodes(planner), "normalize"
    state = {**state, "trace": []}
    for _ in range(MAX_STEPS):
        update = table[node](state)
        state = {**state, **update, "trace": state["trace"] + update.get("trace", [])}
        node = EDGES[node](state)
        if node == END:
            return state
    raise RuntimeError("Planning graph exceeded its step bound")


def build_langgraph(planner):
    from langgraph.graph import END as LG_END, StateGraph
    graph = StateGraph(PlanningState)
    for name, fn in nodes(planner).items():
        graph.add_node(name, fn)
    graph.set_entry_point("normalize")
    for name, route in EDGES.items():
        targets = {"deterministic", "classify_fast", "model", "validate", "adapt", END}
        graph.add_conditional_edges(name, route, {t: (LG_END if t == END else t) for t in targets})
    return graph.compile()


def engine():
    try:
        import langgraph  # noqa: F401
        return "langgraph"
    except ImportError:
        return "builtin"


def run_planning(planner, text, context=()):
    initial = {"text": text, "context": context}
    if engine() == "langgraph":
        state = build_langgraph(planner).invoke({**initial, "trace": []}, {"recursion_limit": MAX_STEPS + 2})
    else:
        state = run_builtin(planner, initial)
    plan = dict(state["plan"])
    plan["workflow"] = {"engine": engine(), "trace": list(state["trace"])}
    return state["request"], plan
