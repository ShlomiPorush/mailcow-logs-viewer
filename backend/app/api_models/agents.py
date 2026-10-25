"""What the agents' own calls return (agent_access/rest.py, agent_access/mcp.py).

GET /api/agent/access and GET /api/agent/endpoints are answered by the auth
middleware for a bearer token, before routing, so they have no route. Their
entries are added to the OpenAPI document by ``agent_paths`` (main.py).
"""
from typing import Any, Dict, List, Union

from pydantic import Field, TypeAdapter

from . import Fixed


class AgentError(Fixed):
    """An agent's call was refused or failed."""
    error: str = Field(description="A stable code, such as invalid_token, forbidden, not_found or too_many_requests")
    message: str = Field(description="What happened and what to do next")


class AgentArea(Fixed):
    area: str
    name: str
    may: str = Field(description="view, or view and act")


class AgentAccessResponse(Fixed):
    """What this connection may do."""
    connection: str = Field(description="The connection's name")
    ends: str = Field(description="When the access ends, UTC, ISO 8601 with Z")
    areas: List[AgentArea]
    not_allowed: List[str] = Field(description="The areas this connection may not use")
    app_version: str
    timezone: str = Field(description="The zone the app shows times in")
    update_skill: str = Field(None, description="Only when the agent's skill is older than the app's: how to update it")


class AgentParameter(Fixed):
    name: str
    # "in" is a Python keyword
    in_: str = Field(alias="in", description="query or path")
    required: bool
    type: str = Field(None)
    default: Any = Field(None)
    enum: List[Any] = Field(None)
    description: str = Field(None)


class AgentEndpoint(Fixed):
    method: str
    path: str
    kind: str = Field(description="read or act")
    area: str
    summary: str = Field(None)
    description: str = Field(None)
    parameters: List[AgentParameter] = Field(None)
    body: Union[str, Dict[str, Any]] = Field(None, description="The request body: its fields and their types, "
                                                               "or a sentence")
    returns: Union[str, Dict[str, Any]] = Field(None, description="What a successful call returns: its top-level "
                                                                  "fields and their types, or a type name")
    limit: str = Field(None, description="A limit beyond the area, such as only this server's own domains")


class AgentEndpointsResponse(Fixed):
    """The API calls this connection may make."""
    endpoints: List[AgentEndpoint]
    count: int


_AGENT_ERRORS = {401: "No valid bearer token", 400: "Unknown area", 405: "Use GET",
                 429: "Too many requests with a bad token"}


def _operation(model, summary: str, description: str, errors: Dict[int, str], schemas: Dict[str, Any],
               parameters: List[Dict[str, Any]]) -> Dict[str, Any]:
    def ref(m):
        schema = TypeAdapter(m).json_schema(ref_template="#/components/schemas/{model}", by_alias=True)
        schemas.update(schema.pop("$defs", {}))
        schemas[m.__name__] = schema
        return {"$ref": f"#/components/schemas/{m.__name__}"}

    responses = {"200": {"description": "Success", "content": {"application/json": {"schema": ref(model)}}}}
    for code, text in errors.items():
        responses[str(code)] = {"description": text, "content": {"application/json": {"schema": ref(AgentError)}}}
    return {"get": {"tags": ["Agents"], "summary": summary, "description": description,
                    "operationId": f"agent_{model.__name__}", "parameters": parameters,
                    "security": [{"AgentBearer": []}], "responses": responses}}


def agent_paths(document: Dict[str, Any]) -> None:
    """Add the two middleware-answered agent calls to a generated OpenAPI document."""
    components = document.setdefault("components", {})
    schemas = components.setdefault("schemas", {})
    components.setdefault("securitySchemes", {})["AgentBearer"] = {
        "type": "http", "scheme": "bearer",
        "description": "An agent's access token (Settings > Agents). Not a sign-in session."}
    paths = document.setdefault("paths", {})
    paths["/api/agent/access"] = _operation(
        AgentAccessResponse, "Agent: what this connection may do",
        "For an agent's bearer token only.", {401: _AGENT_ERRORS[401], 405: _AGENT_ERRORS[405],
                                              429: _AGENT_ERRORS[429]}, schemas, [])
    paths["/api/agent/endpoints"] = _operation(
        AgentEndpointsResponse, "Agent: the API calls this connection may make",
        "For an agent's bearer token only.", _AGENT_ERRORS, schemas,
        [{"name": "area", "in": "query", "required": False, "schema": {"type": "string"},
          "description": "Only the calls of this area"}])
