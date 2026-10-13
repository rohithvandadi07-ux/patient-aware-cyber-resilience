"""Authentication/authorization -- post-Phase-15, closing a gap this
project had disclosed and carried forward since Phase 9.

`docs/security-checklist.md`'s own Section 6 named the prior state exactly:
"designed-for, not implemented ... adding a full auth layer here, un-asked,
would be exactly the kind of scope invention this project has avoided at
every other phase boundary." That caveat -- "un-asked" -- is the reason this
module didn't exist before now: it was never that auth was hard, it was that
nobody had asked for it yet.

## Design

API-key based, not a session/OAuth flow -- this is a backend API with no
browser-facing login page (the SOC dashboard, `frontend/`, is a separate
client), so a bearer-style API key is the simplest mechanism that actually
satisfies "Authentication/authorization where required" (architecture plan
Section 20) without inventing a user-account system this project has no
other use for.

Three roles, ranked:
  - `viewer`: read-only (every `GET` route).
  - `operator`: `viewer` + can trigger `/incidents/{id}/investigate`
    without auto-approving, and can propose/create things that don't
    themselves execute a response on a device.
  - `approver`: `operator` + can approve/execute a response
    (`POST /responses/executed` with a non-null `approval`) and can set
    `auto_approve=True` on `/incidents/{id}/investigate` -- the two actions
    that can actually change a simulated device's state without a human
    explicitly saying so in the moment. This mirrors the architecture plan's
    own human-approval-gate intent (Section 10/11): the same authority
    boundary already enforced deterministically inside `ResponseOrchestrator`
    (`requires_human_approval`) now also has an identity requirement on who
    may supply that approval over HTTP.

Fails closed, not open: `Settings.auth_enabled=True` with no `api_keys`
configured locks out every route but `/health` -- there is no "auth enabled
but anything goes" state.

Opt-in by default (`auth_enabled=False`), like every other `mock`/opt-in
flag this project has added (`repository_backend`, `fabric_client_mode`,
`llm_backend`): every pre-existing test, and the default dev/demo
experience, are completely unaffected unless a deployment turns this on and
configures real keys.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Header, HTTPException, Request

_ROLE_RANK = {"viewer": 0, "operator": 1, "approver": 2}
_ANONYMOUS_IDENTITY = "anonymous (auth disabled)"
_ANONYMOUS_ROLE = "approver"  # permissive default, matching this app's historical no-auth behavior


@dataclass(frozen=True)
class Principal:
    """Who is making this request, and what they're allowed to do.
    `identity` is a human-readable label (from `Settings.api_keys`'
    `key:role:identity` entry, or the anonymous placeholder) -- never the
    raw API key itself, so it's safe to log or return in an error message.
    """

    identity: str
    role: str

    def has_role(self, minimum: str) -> bool:
        return _ROLE_RANK[self.role] >= _ROLE_RANK[minimum]


class InsufficientRoleError(Exception):
    def __init__(self, principal: Principal, required: str) -> None:
        self.principal = principal
        self.required = required
        super().__init__(
            f"{principal.identity!r} has role {principal.role!r}, which does not meet the "
            f"required minimum role {required!r} for this action"
        )


def get_current_principal(
    request: Request, x_api_key: str | None = Header(default=None)
) -> Principal:
    """The one real authentication check. Used as a global dependency on
    every router except `/health` (see `app/core/app_factory.py`'s
    `_register_routers`) -- every request through those routers resolves a
    `Principal` here, whether or not `auth_enabled` is on.

    When `Settings.auth_enabled` is false (the default): returns a static,
    fully-permissive anonymous principal without inspecting `x_api_key` at
    all -- this app's historical no-auth behavior, now represented by a
    real `Principal` object instead of there being no concept of one.

    When true: requires `x_api_key` to be present and to match a configured
    entry in `Settings.api_keys`. Raises 401 if missing or unrecognized --
    never guesses a role for an unrecognized key, and never distinguishes
    "missing header" from "wrong key" in the response (both are 401 with
    the same generic detail), so this isn't a key-enumeration oracle.
    """
    settings = request.app.state.settings
    if not settings.auth_enabled:
        return Principal(identity=_ANONYMOUS_IDENTITY, role=_ANONYMOUS_ROLE)

    if x_api_key is None or x_api_key not in settings.api_keys:
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header")

    role, identity = settings.api_keys[x_api_key]
    if role not in _ROLE_RANK:
        # A misconfigured Settings.api_keys entry (should have been caught by
        # config.py's own validator at startup) -- fail closed rather than
        # silently granting an unranked role some default access.
        raise HTTPException(
            status_code=500, detail=f"API key resolves to unrecognized role {role!r}"
        )
    return Principal(identity=identity, role=role)


def require_role(principal: Principal, minimum: str) -> None:
    """Call from inside a route handler (not as its own `Depends`) when the
    required role depends on the request body, which a plain `Depends`
    cannot see before the body is parsed -- e.g. `/responses/executed`
    only needs `approver` when `body.approval is not None`;
    `/incidents/{id}/investigate` only needs it when `body.auto_approve`.
    Raises 403 (not 401 -- the principal *is* authenticated, they just lack
    the role this specific action needs) via `InsufficientRoleError`
    translated by the route, or directly as `HTTPException` here for
    convenience."""
    if not principal.has_role(minimum):
        raise HTTPException(
            status_code=403,
            detail=f"This action requires role '{minimum}' or higher; "
            f"{principal.identity!r} has role {principal.role!r}",
        )
