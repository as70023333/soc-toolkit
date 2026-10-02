"""Read-only collection from Microsoft Graph into a tenant snapshot.

Each section is collected independently. A missing permission or license fails only that
section: it is recorded under ``errors`` and the report says what was skipped and why.
"""

from __future__ import annotations

from typing import Any, Callable

from soc_toolkit.common.http import HttpError
from soc_toolkit.common.msapi import GraphApi
from soc_toolkit.common.timeutil import iso, utcnow
from soc_toolkit.entra_audit.constants import RISKY_RESOURCE_APPS

CHECKS = ("stale", "mfa", "consent", "roles")

SECTION_HELP = {
    "organization": "Organization.Read.All or Directory.Read.All",
    "users": "User.Read.All (sign-in activity also needs AuditLog.Read.All and Entra ID P1)",
    "registration": "AuditLog.Read.All and Entra ID P1/P2",
    "consents": "Application.Read.All and Directory.Read.All",
    "roles": "RoleManagement.Read.Directory",
}

USER_FIELDS = ("id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,"
               "onPremisesSyncEnabled,externalUserState,externalUserStateChangeDateTime")
SP_FIELDS = ("id,appId,displayName,appOwnerOrganizationId,publisherName,verifiedPublisher,"
             "servicePrincipalType,accountEnabled,createdDateTime")

Log = Callable[[str], None]


def _hint(section: str, exc: HttpError) -> str:
    if exc.status in (401, 403):
        return f"{exc} - grant {SECTION_HELP.get(section, 'the documented permission')}"
    return str(exc)


def _list_users(graph: GraphApi, snap: dict[str, Any], log: Log) -> None:
    attempts = (("signInActivity", "999"), ("signInActivity", "120"), ("", "999"))
    last_error: HttpError | None = None
    for extra, top in attempts:
        select = USER_FIELDS + ("," + extra if extra else "")
        try:
            snap["users"] = graph.get_all("/v1.0/users", {"$select": select, "$top": top})
            snap["sign_in_activity_available"] = bool(extra)
            if not extra and last_error is not None:
                snap["errors"]["sign_in_activity"] = (
                    f"sign-in activity unavailable ({last_error}); stale-account checks were skipped. "
                    "Grant AuditLog.Read.All; the tenant needs Entra ID P1.")
            log(f"users: {len(snap['users'])}")
            return
        except HttpError as exc:
            if exc.status not in (400, 403):
                raise
            last_error = exc
    raise last_error  # type: ignore[misc]


def _collect_registration(graph: GraphApi, snap: dict[str, Any], log: Log) -> None:
    snap["registration"] = graph.get_all("/v1.0/reports/authenticationMethods/userRegistrationDetails")
    log(f"MFA registration records: {len(snap['registration'])}")


def _collect_consents(graph: GraphApi, snap: dict[str, Any], log: Log) -> None:
    sps = graph.get_all("/v1.0/servicePrincipals", {"$select": SP_FIELDS, "$top": "999"})
    snap["service_principals"] = sps
    snap["oauth2_grants"] = graph.get_all("/v1.0/oauth2PermissionGrants")
    by_app = {sp.get("appId"): sp for sp in sps}
    assignments: list[dict] = []
    roles: dict[str, dict[str, str]] = {}
    for app_id in RISKY_RESOURCE_APPS:
        resource = by_app.get(app_id)
        if not resource:
            continue
        detail = graph.get_json(f"/v1.0/servicePrincipals/{resource['id']}",
                                {"$select": "id,appId,displayName,appRoles"}) or {}
        roles[resource["id"]] = {r["id"]: r.get("value") or r.get("displayName") or r["id"]
                                 for r in detail.get("appRoles", []) if r.get("id")}
        assignments.extend(graph.get_all(f"/v1.0/servicePrincipals/{resource['id']}/appRoleAssignedTo"))
    snap["app_role_assignments"] = assignments
    snap["resource_app_roles"] = roles
    log(f"service principals: {len(sps)}, delegated grants: {len(snap['oauth2_grants'])}, "
        f"application permission grants: {len(assignments)}")


def _collect_roles(graph: GraphApi, snap: dict[str, Any], log: Log) -> None:
    try:
        defs = graph.get_all("/v1.0/roleManagement/directory/roleDefinitions",
                             {"$select": "id,displayName,templateId,isBuiltIn,isPrivileged"})
    except HttpError as exc:
        if exc.status != 400:
            raise
        defs = graph.get_all("/v1.0/roleManagement/directory/roleDefinitions",
                             {"$select": "id,displayName,templateId,isBuiltIn"})
    snap["role_definitions"] = defs
    try:
        rows = graph.get_all("/v1.0/roleManagement/directory/roleAssignmentScheduleInstances")
        for row in rows:
            row["source"] = "pim"
        snap["pim_available"] = True
    except HttpError as exc:
        if exc.status not in (400, 403, 404):
            raise
        # No PIM (Entra ID P2) or no PIM permission: every active assignment is treated as permanent.
        rows = graph.get_all("/v1.0/roleManagement/directory/roleAssignments",
                             {"$select": "id,principalId,roleDefinitionId,directoryScopeId"})
        for row in rows:
            row["source"] = "direct"
        snap["pim_available"] = False
        snap["errors"]["pim"] = (f"PIM schedule data unavailable ({exc}); all active role assignments "
                                 "are reported as permanent. Grant RoleAssignmentSchedule.Read.Directory "
                                 "(needs Entra ID P2) for exact results.")
    snap["role_assignments"] = rows
    known = {u["id"] for u in snap.get("users", [])} | {sp["id"] for sp in snap.get("service_principals", [])}
    unknown = sorted({r["principalId"] for r in rows if r.get("principalId") and r["principalId"] not in known})
    principals: dict[str, dict] = {}
    for start in range(0, len(unknown), 1000):
        chunk = unknown[start:start + 1000]
        data = graph.post_json("/v1.0/directoryObjects/getByIds",
                               {"ids": chunk, "types": ["user", "group", "servicePrincipal"]}) or {}
        for obj in data.get("value", []):
            principals[obj["id"]] = obj
    snap["principals"] = principals
    log(f"role definitions: {len(defs)}, active role assignments: {len(rows)}")


def collect(graph: GraphApi, checks: tuple[str, ...] = CHECKS, log: Log = lambda _m: None) -> dict[str, Any]:
    snap: dict[str, Any] = {
        "captured_at": iso(utcnow()),
        "tenant": {},
        "users": [],
        "sign_in_activity_available": False,
        "registration": None,
        "service_principals": [],
        "oauth2_grants": [],
        "app_role_assignments": [],
        "resource_app_roles": {},
        "role_definitions": [],
        "role_assignments": [],
        "pim_available": False,
        "principals": {},
        "checks": list(checks),
        "errors": {},
    }

    def section(name: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except HttpError as exc:
            snap["errors"][name] = _hint(name, exc)
            log(f"{name}: skipped ({snap['errors'][name]})")

    def organization() -> None:
        orgs = graph.get_all("/v1.0/organization", {"$select": "id,displayName"})
        if orgs:
            snap["tenant"] = {"id": orgs[0].get("id", ""), "displayName": orgs[0].get("displayName", "")}

    section("organization", organization)
    section("users", lambda: _list_users(graph, snap, log))
    if "mfa" in checks:
        section("registration", lambda: _collect_registration(graph, snap, log))
    if "consent" in checks or "roles" in checks:
        section("consents", lambda: _collect_consents(graph, snap, log))
    if "roles" in checks or "stale" in checks or "mfa" in checks:
        section("roles", lambda: _collect_roles(graph, snap, log))
    return snap
