"""Controlled tool registry with enforced authority boundaries.

THE ARCHITECTURAL CLAIM
-----------------------
The specification requires that agents "must NEVER bypass deterministic
policy" and must never receive "unrestricted shell access" or "arbitrary
system privileges". Those are not properties that can be achieved by
*instructing* a language model; a prompt is a request, not a guarantee.

They are achieved here structurally:

* An agent is constructed with a **fixed allowlist** of tool names drawn
  from its role. A tool outside that allowlist cannot be invoked - the
  registry refuses before the tool function is reached, and the refusal is
  recorded as an authority violation on the audit trail.
* Each tool declares an :class:`ToolAuthority`. Agents hold an authority
  ceiling, and a tool above that ceiling is refused regardless of
  allowlisting.
* Tools are **pure functions over a read-only context**. There is no shell
  tool, no filesystem tool, no network tool, no eval. The actuation tool
  does not actuate: it returns a request that the response orchestrator
  evaluates against the policy engine.
* Arguments are validated against a declared schema before dispatch, so a
  malformed or injected argument is rejected rather than reaching code.

So the authority boundary is a property of the registry, testable
independently of any model's behaviour. ``tests/unit/test_agents.py``
asserts it by attempting violations.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from backend.app.domain.enums import AgentRole, ToolAuthority
from backend.app.domain.ids import IdFactory, canonical_hash
from backend.app.domain.models import ToolCallRecord

#: Authority ceiling per agent role, mirroring the specification's authority
#: table. An agent cannot be constructed with a higher ceiling.
#:
#: NOTE ON WHAT THIS EXCLUDES. Every role tops out at COMPUTE, so the three
#: privileged tools - request_human_approval (REQUEST_APPROVAL),
#: propose_safe_action (ACTUATE) and record_provenance (LEDGER_WRITE) - are
#: reachable by NO agent role. That is deliberate and is the central safety
#: property: approval requests, actuation and ledger writes are performed by
#: the ORCHESTRATOR after the deterministic policy engine has ruled, never by
#: an agent mid-reasoning.
#:
#: The orchestrator invokes those tools with an explicit elevated ceiling
#: (see ``ORCHESTRATOR_AUTHORITY``), which is auditable as a distinct actor
#: on the timeline. An agent that attempts one gets AuthorityViolation.
ROLE_AUTHORITY: dict[AgentRole, ToolAuthority] = {
    AgentRole.INVESTIGATION: ToolAuthority.READ_ONLY,
    AgentRole.THREAT_REASONING: ToolAuthority.COMPUTE,
    AgentRole.HEALTHCARE_CONTEXT: ToolAuthority.COMPUTE,
    AgentRole.RESPONSE_PLANNING: ToolAuthority.COMPUTE,
    AgentRole.RECOVERY_VERIFICATION: ToolAuthority.COMPUTE,
}

#: Ordering of authority levels, least to most privileged.
AUTHORITY_ORDER: tuple[ToolAuthority, ...] = (
    ToolAuthority.READ_ONLY,
    ToolAuthority.COMPUTE,
    ToolAuthority.REQUEST_APPROVAL,
    ToolAuthority.ACTUATE,
    ToolAuthority.LEDGER_WRITE,
)


#: Ceiling used by the orchestrator itself. Not available to any agent.
ORCHESTRATOR_AUTHORITY: ToolAuthority = ToolAuthority.LEDGER_WRITE


def authority_rank(authority: ToolAuthority) -> int:
    return AUTHORITY_ORDER.index(authority)


class ToolError(Exception):
    """A tool failed for an ordinary reason (bad arguments, missing data)."""


class AuthorityViolation(Exception):
    """An agent attempted a tool outside its authority. Never recoverable.

    Raised rather than returned, because an authority violation is a
    structural fault in the orchestration - not a condition the agent
    should be allowed to handle and retry around.
    """


@dataclass(frozen=True)
class ToolSpec:
    """Declaration of one controlled tool."""

    name: str
    authority: ToolAuthority
    description: str
    #: Argument name -> (python type, required)
    arguments: dict[str, tuple[type, bool]] = field(default_factory=dict)
    #: Roles permitted to use this tool at all.
    allowed_roles: frozenset[AgentRole] = field(default_factory=frozenset)
    #: Set when the tool reads mutable state and must not be cached.
    volatile: bool = True

    def validate_arguments(self, arguments: dict[str, Any]) -> None:
        unknown = sorted(set(arguments) - set(self.arguments))
        if unknown:
            raise ToolError(
                f"{self.name}: unknown arguments {unknown}. Accepted: {sorted(self.arguments)}"
            )
        for arg, (expected, required) in self.arguments.items():
            if arg not in arguments:
                if required:
                    raise ToolError(f"{self.name}: missing required argument {arg!r}")
                continue
            value = arguments[arg]
            if value is None and not required:
                continue
            if not isinstance(value, expected):
                raise ToolError(
                    f"{self.name}: argument {arg!r} must be {expected.__name__}, "
                    f"got {type(value).__name__}"
                )

    def json_schema(self) -> dict[str, Any]:
        """Schema handed to an LLM provider for structured tool-calling."""
        type_map = {
            str: "string",
            int: "integer",
            float: "number",
            bool: "boolean",
            list: "array",
            dict: "object",
        }
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    arg: {"type": type_map.get(t, "string")}
                    for arg, (t, _) in self.arguments.items()
                },
                "required": [a for a, (_, req) in self.arguments.items() if req],
            },
        }


ToolFunction = Callable[["ToolContext", dict[str, Any]], Any]


@dataclass
class ToolContext:
    """Read-only context a tool may access.

    Deliberately narrow. A tool receives this and its validated arguments,
    and nothing else - no module imports at call time, no globals, no
    service locator. Whatever is absent here is unreachable from a tool.
    """

    incident_id: str
    incident_package: Any  # IncidentContextPackage; Any avoids a cycle
    risk_engine: Any | None = None
    hospital_view: Any | None = None
    approval_sink: Any | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResult:
    """Outcome of a tool call, plus the audit record."""

    value: Any
    record: ToolCallRecord


class ToolRegistry:
    """Holds tool specs and implementations; enforces authority on dispatch."""

    def __init__(self, ids: IdFactory) -> None:
        self.ids = ids
        self._specs: dict[str, ToolSpec] = {}
        self._functions: dict[str, ToolFunction] = {}

    # -- registration ------------------------------------------------------
    def register(self, spec: ToolSpec, fn: ToolFunction) -> None:
        if spec.name in self._specs:
            raise ValueError(f"tool {spec.name!r} is already registered")
        self._specs[spec.name] = spec
        self._functions[spec.name] = fn

    def spec(self, name: str) -> ToolSpec:
        if name not in self._specs:
            raise ToolError(f"unknown tool {name!r}")
        return self._specs[name]

    def names(self) -> list[str]:
        return sorted(self._specs)

    def tools_for_role(self, role: AgentRole) -> list[ToolSpec]:
        ceiling = authority_rank(ROLE_AUTHORITY[role])
        return [
            s
            for s in sorted(self._specs.values(), key=lambda x: x.name)
            if role in s.allowed_roles and authority_rank(s.authority) <= ceiling
        ]

    def schemas_for_role(self, role: AgentRole) -> list[dict[str, Any]]:
        return [s.json_schema() for s in self.tools_for_role(role)]

    # -- dispatch ----------------------------------------------------------
    def call(
        self,
        name: str,
        arguments: dict[str, Any],
        context: ToolContext,
        role: AgentRole,
        allowlist: frozenset[str] | None = None,
        authority_override: ToolAuthority | None = None,
    ) -> ToolResult:
        """Invoke a tool, enforcing every boundary before dispatch.

        Order matters: existence, then allowlist, then role permission, then
        authority ceiling, then argument validation. Each failure before
        dispatch means the tool function is never reached.
        """
        started = time.perf_counter()
        call_id = self.ids.tool_call()

        def _record(
            succeeded: bool,
            error: str | None = None,
            digest: str | None = None,
            violation: bool = False,
        ) -> ToolCallRecord:
            return ToolCallRecord(
                tool_call_id=call_id,
                agent_role=role,
                tool_name=name,
                arguments=dict(arguments),
                succeeded=succeeded,
                error=error,
                duration_ms=(time.perf_counter() - started) * 1000.0,
                result_digest=digest,
                authority_violation=violation,
            )

        # 1. Does the tool exist at all?
        if name not in self._specs:
            raise AuthorityViolation(
                f"agent {role.value} attempted unknown tool {name!r}. "
                f"Available to this role: "
                f"{[s.name for s in self.tools_for_role(role)]}"
            )

        spec = self._specs[name]

        # 2. Is it on this agent's fixed allowlist?
        if allowlist is not None and name not in allowlist:
            raise AuthorityViolation(
                f"agent {role.value} attempted tool {name!r}, which is not on "
                f"its allowlist {sorted(allowlist)}. The allowlist is fixed at "
                "construction and cannot be extended at run time."
            )

        # 3. Is the role permitted this tool?
        if role not in spec.allowed_roles:
            raise AuthorityViolation(
                f"tool {name!r} is not available to the {role.value} agent. "
                f"Permitted roles: {sorted(r.value for r in spec.allowed_roles)}"
            )

        # 4. Is the tool within the caller's authority ceiling?
        #    ``authority_override`` is how the ORCHESTRATOR reaches the
        #    privileged tools. It is never passed from agent code: the
        #    agent loop calls this method without it, so an agent cannot
        #    supply its own ceiling.
        ceiling = authority_override or ROLE_AUTHORITY[role]
        if authority_rank(spec.authority) > authority_rank(ceiling):
            raise AuthorityViolation(
                f"tool {name!r} requires {spec.authority.value} authority but "
                f"the {role.value} agent is limited to {ceiling.value}. "
                "An agent cannot escalate its own authority; privileged tools "
                "are invoked by the orchestrator after the policy engine rules."
            )

        # 5. Are the arguments well-formed?
        try:
            spec.validate_arguments(arguments)
        except ToolError as exc:
            return ToolResult(value=None, record=_record(False, str(exc)))

        # 6. Dispatch.
        try:
            value = self._functions[name](context, arguments)
        except ToolError as exc:
            return ToolResult(value=None, record=_record(False, str(exc)))
        except AuthorityViolation:
            raise
        except Exception as exc:
            return ToolResult(
                value=None,
                record=_record(False, f"{type(exc).__name__}: {exc}"),
            )

        return ToolResult(
            value=value,
            record=_record(True, digest=canonical_hash(value)[:16]),
        )


__all__ = [
    "AUTHORITY_ORDER",
    "ORCHESTRATOR_AUTHORITY",
    "ROLE_AUTHORITY",
    "AuthorityViolation",
    "ToolContext",
    "ToolError",
    "ToolFunction",
    "ToolRegistry",
    "ToolResult",
    "ToolSpec",
    "authority_rank",
]
