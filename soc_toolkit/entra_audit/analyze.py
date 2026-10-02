"""Turn a tenant snapshot into findings. Pure functions: no network, fully unit-tested."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from soc_toolkit.common.findings import Finding, lower_severity, raise_severity, sort_findings
from soc_toolkit.common.timeutil import days_between, parse_time
from soc_toolkit.entra_audit.constants import (
    DATA_PERMISSIONS, GLOBAL_ADMIN_TEMPLATE, MICROSOFT_TENANTS, PRIVILEGED_ROLE_TEMPLATES,
    TAKEOVER_PERMISSIONS, WEAK_METHODS, is_phishing_resistant,
)


@dataclass
class AuditConfig:
    stale_days: int = 90
    guest_stale_days: int = 90
    pending_invite_days: int = 30
    break_glass: set[str] = field(default_factory=set)
    exclude: set[str] = field(default_factory=set)
    max_global_admins: int = 5
    min_global_admins: int = 2
    now: datetime | None = None
    checks: tuple[str, ...] = ("stale", "mfa", "consent", "roles")

    def __post_init__(self) -> None:
        self.break_glass = {u.lower() for u in self.break_glass}
        self.exclude = {u.lower() for u in self.exclude}
        for name in ("stale_days", "guest_stale_days", "pending_invite_days"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be at least 1")


@dataclass
class AuditResult:
    findings: list[Finding]
    stats: dict[str, Any]
    notes: list[str]


def _name(user: dict) -> str:
    return user.get("userPrincipalName") or user.get("displayName") or user.get("id") or ""


def _upn(user: dict) -> str:
    return _name(user).lower()


def _last_sign_in(user: dict) -> datetime | None:
    activity = user.get("signInActivity") or {}
    if "lastSuccessfulSignInDateTime" in activity:
        return parse_time(activity.get("lastSuccessfulSignInDateTime"))
    times = [parse_time(activity.get(k)) for k in ("lastSignInDateTime", "lastNonInteractiveSignInDateTime")]
    times = [t for t in times if t]
    return max(times) if times else None


class _RoleIndex:
    """Which principals hold which privileged roles, and how."""

    def __init__(self, snap: dict[str, Any]) -> None:
        self.defs: dict[str, dict] = {}
        for d in snap.get("role_definitions", []):
            self.defs[d.get("id", "")] = d
            if d.get("templateId"):
                self.defs.setdefault(d["templateId"], d)
        self.assignments = [a for a in snap.get("role_assignments", [])
                            if a.get("memberType", "Direct") not in ("Group", "Inherited")]
        self.privileged_by_principal: dict[str, list[str]] = defaultdict(list)
        for a in self.assignments:
            if self.is_privileged(a.get("roleDefinitionId", "")):
                self.privileged_by_principal[a.get("principalId", "")].append(self.role_name(a["roleDefinitionId"]))

    def _template(self, role_id: str) -> str:
        d = self.defs.get(role_id) or {}
        return d.get("templateId") or role_id

    def role_name(self, role_id: str) -> str:
        d = self.defs.get(role_id) or {}
        return d.get("displayName") or PRIVILEGED_ROLE_TEMPLATES.get(self._template(role_id), role_id)

    def is_privileged(self, role_id: str) -> bool:
        d = self.defs.get(role_id) or {}
        return d.get("isPrivileged") is True or self._template(role_id) in PRIVILEGED_ROLE_TEMPLATES

    def is_global_admin(self, role_id: str) -> bool:
        return self._template(role_id) == GLOBAL_ADMIN_TEMPLATE


# --------------------------------------------------------------------------- stale accounts

def _check_stale(snap: dict, cfg: AuditConfig, now: datetime, roles: _RoleIndex) -> list[Finding]:
    findings: list[Finding] = []
    activity = snap.get("sign_in_activity_available", False)
    for user in snap.get("users", []):
        upn = _upn(user)
        if not user.get("accountEnabled") or upn in cfg.exclude or upn in cfg.break_glass:
            continue
        guest = (user.get("userType") or "").lower() == "guest"
        created = parse_time(user.get("createdDateTime"))
        privileged = roles.privileged_by_principal.get(user.get("id", ""), [])
        role_note = f" Holds privileged role(s): {', '.join(sorted(set(privileged)))}." if privileged else ""

        if guest and user.get("externalUserState") == "PendingAcceptance":
            invited = parse_time(user.get("externalUserStateChangeDateTime")) or created
            if invited and days_between(now, invited) >= cfg.pending_invite_days:
                findings.append(Finding(
                    "pending_guest_invite", "low", "Guest invitation never accepted", _name(user),
                    f"Invited {days_between(now, invited)} days ago and never redeemed.{role_note}",
                    "Delete the guest or resend the invitation if the collaboration is still needed.",
                    {"invited": user.get("externalUserStateChangeDateTime") or user.get("createdDateTime")}))
            continue
        if not activity:
            continue
        limit = cfg.guest_stale_days if guest else cfg.stale_days
        last = _last_sign_in(user)
        base = "medium"
        if last is None:
            if created and days_between(now, created) >= limit:
                severity = raise_severity(base) if privileged else base
                findings.append(Finding(
                    "never_signed_in", severity, "Enabled account has never signed in", _name(user),
                    f"Created {days_between(now, created)} days ago with no recorded sign-in.{role_note}",
                    "Confirm an owner exists; disable it, or convert it to a managed identity if it is a "
                    "service account.",
                    {"created": user.get("createdDateTime"), "guest": guest}))
        elif days_between(now, last) >= limit:
            severity = raise_severity(base) if privileged else base
            check = "stale_guest" if guest else "stale_account"
            title = "Stale guest account" if guest else "Stale enabled account"
            findings.append(Finding(
                check, severity, title, _name(user),
                f"Last successful sign-in {days_between(now, last)} days ago (threshold {limit}).{role_note}",
                "Disable the account, then delete it after your retention period. Consider access reviews "
                "for guests.",
                {"last_sign_in": last.isoformat(), "guest": guest}))
    return findings


# --------------------------------------------------------------------------- MFA

def _check_mfa(snap: dict, cfg: AuditConfig, roles: _RoleIndex) -> list[Finding]:
    registration = snap.get("registration")
    if registration is None:
        return []
    reg_by_id = {r.get("id"): r for r in registration}
    findings: list[Finding] = []
    for user in snap.get("users", []):
        upn = _upn(user)
        if not user.get("accountEnabled") or upn in cfg.exclude:
            continue
        if (user.get("userType") or "member").lower() != "member":
            continue  # guests authenticate in their home tenant
        reg = reg_by_id.get(user.get("id"))
        if reg is None:
            continue
        roles_held = roles.privileged_by_principal.get(user.get("id", ""), [])
        privileged = bool(roles_held) or bool(reg.get("isAdmin")) or upn in cfg.break_glass
        methods = set(reg.get("methodsRegistered") or [])
        evidence = {"methods": sorted(methods), "privileged": privileged}
        who = f" Privileged: {', '.join(sorted(set(roles_held))) or 'yes'}." if privileged else ""
        if not reg.get("isMfaRegistered"):
            findings.append(Finding(
                "no_mfa", "critical" if privileged else "high", "User has no MFA method registered", _name(user),
                f"No multifactor method is registered.{who}",
                "Require MFA registration with a Conditional Access policy and a registration campaign; "
                "until then the password alone protects this account.", evidence))
            continue
        if not methods - WEAK_METHODS:
            findings.append(Finding(
                "weak_mfa_only", "high" if privileged else "medium", "Only phishable MFA methods registered",
                _name(user), f"Registered methods: {', '.join(sorted(methods))}.{who}",
                "Move the user to Microsoft Authenticator or a passkey and disable SMS/voice for them.",
                evidence))
        if privileged and not any(is_phishing_resistant(m) for m in methods):
            findings.append(Finding(
                "admin_not_phishing_resistant", "high", "Privileged user without phishing-resistant MFA", _name(user),
                f"Registered methods: {', '.join(sorted(methods)) or 'none'}.{who}",
                "Register a FIDO2 key or passkey and enforce the 'Phishing-resistant MFA' authentication "
                "strength for admin roles.", evidence))
    return findings


# --------------------------------------------------------------------------- consents

def _classify(perms: set[str]) -> tuple[list[str], list[str]]:
    takeover = sorted(p for p in perms if p in TAKEOVER_PERMISSIONS)
    data = sorted(p for p in perms if p in DATA_PERMISSIONS)
    return takeover, data


def _check_consents(snap: dict, cfg: AuditConfig) -> list[Finding]:
    tenant_id = (snap.get("tenant") or {}).get("id", "")
    sps = {sp.get("id"): sp for sp in snap.get("service_principals", [])}
    role_names: dict[str, dict[str, str]] = snap.get("resource_app_roles", {})

    def ownership(sp: dict) -> tuple[bool, bool, bool]:
        owner = sp.get("appOwnerOrganizationId") or ""
        microsoft = owner in MICROSOFT_TENANTS
        third_party = bool(owner) and owner != tenant_id and not microsoft
        unverified = not ((sp.get("verifiedPublisher") or {}).get("verifiedPublisherId"))
        return microsoft, third_party, unverified

    app_perms: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for a in snap.get("app_role_assignments", []):
        if (a.get("principalType") or "ServicePrincipal") != "ServicePrincipal":
            continue
        resource = a.get("resourceId", "")
        name = role_names.get(resource, {}).get(a.get("appRoleId", ""), a.get("appRoleId", "unknown"))
        resource_name = (sps.get(resource) or {}).get("displayName") or a.get("resourceDisplayName") or resource
        app_perms[a.get("principalId", "")][resource_name].add(name)

    delegated: dict[tuple[str, str], dict[str, Any]] = {}
    for g in snap.get("oauth2_grants", []):
        kind = "admin" if g.get("consentType") == "AllPrincipals" else "user"
        entry = delegated.setdefault((g.get("clientId", ""), kind), {"scopes": defaultdict(set), "users": set()})
        resource_name = (sps.get(g.get("resourceId")) or {}).get("displayName") or g.get("resourceId", "")
        for scope in (g.get("scope") or "").split():
            entry["scopes"][resource_name].add(scope)
        if kind == "user" and g.get("principalId"):
            entry["users"].add(g["principalId"])

    findings: list[Finding] = []

    def describe(sp: dict, client_id: str, third_party: bool, unverified: bool) -> tuple[str, str]:
        name = sp.get("displayName") or client_id
        target = f"{name} ({sp.get('appId', client_id)})"
        publisher = sp.get("publisherName") or (sp.get("verifiedPublisher") or {}).get("displayName") or "unknown"
        origin = (f"Third-party app from tenant {sp.get('appOwnerOrganizationId')}, publisher {publisher}"
                  f"{' (unverified)' if unverified else ' (verified)'}." if third_party
                  else "App registered in your tenant.")
        return target, origin

    def explain(perms: list[str]) -> str:
        return "; ".join(f"{p}: {TAKEOVER_PERMISSIONS.get(p) or DATA_PERMISSIONS.get(p)}" for p in perms)

    for client_id, by_resource in app_perms.items():
        sp = sps.get(client_id)
        if not sp:
            continue
        microsoft, third_party, unverified = ownership(sp)
        if microsoft:
            continue
        all_perms = {p for perms in by_resource.values() for p in perms}
        takeover, data = _classify(all_perms)
        if not takeover and not data:
            continue
        if takeover:
            severity = "critical" if third_party else "high"
        else:
            severity = "high" if third_party else "medium"
        if third_party and unverified:
            severity = raise_severity(severity)
        target, origin = describe(sp, client_id, third_party, unverified)
        granted = "; ".join(f"{res}: {', '.join(sorted(p))}" for res, p in sorted(by_resource.items()))
        findings.append(Finding(
            "risky_app_permission", severity, "App holds high-risk application permissions", target,
            f"{origin} Application permissions (work without a signed-in user): {granted}. "
            f"Risk: {explain(takeover + data)}.",
            "Confirm the business owner and need. Remove permissions it does not use, scope Exchange "
            "access with RBAC for Applications, and monitor its sign-ins and credentials.",
            {"permissions": sorted(all_perms), "third_party": third_party, "unverified": unverified,
             "type": "application"}))

    for (client_id, kind), entry in delegated.items():
        sp = sps.get(client_id)
        if not sp:
            continue
        microsoft, third_party, unverified = ownership(sp)
        if microsoft:
            continue
        all_scopes = {s for scopes in entry["scopes"].values() for s in scopes}
        takeover, data = _classify(all_scopes)
        if not takeover and not data:
            continue
        if kind == "admin":
            severity = ("high" if takeover else "medium") if third_party else ("medium" if takeover else "low")
            title = "Tenant-wide consent to high-risk delegated permissions"
            who = "Granted for all users by an administrator."
        else:
            severity = ("high" if unverified else "medium") if third_party else "low"
            title = "Users consented to high-risk delegated permissions"
            who = f"Consented individually by {len(entry['users'])} user(s)."
        target, origin = describe(sp, client_id, third_party, unverified)
        granted = "; ".join(f"{res}: {', '.join(sorted(s))}" for res, s in sorted(entry["scopes"].items()))
        findings.append(Finding(
            "risky_delegated_consent", severity, title, target,
            f"{origin} {who} Scopes: {granted}. Risk: {explain(takeover + data)}.",
            "Review the app; revoke the grants if it is not approved. Restrict user consent to verified "
            "publishers and low-risk permissions, and turn on the admin consent workflow.",
            {"permissions": sorted(all_scopes), "consent": kind, "users": len(entry["users"]),
             "third_party": third_party, "unverified": unverified, "type": "delegated"}))
    return findings


# --------------------------------------------------------------------------- privileged roles

def _check_roles(snap: dict, cfg: AuditConfig, roles: _RoleIndex) -> list[Finding]:
    if not snap.get("role_assignments"):
        return []
    users = {u.get("id"): u for u in snap.get("users", [])}
    sps = {sp.get("id"): sp for sp in snap.get("service_principals", [])}
    others: dict[str, dict] = snap.get("principals", {})
    pim = snap.get("pim_available", False)
    findings: list[Finding] = []
    global_admins: set[str] = set()
    break_glass_seen: set[str] = set()

    for a in roles.assignments:
        role_id = a.get("roleDefinitionId", "")
        if not roles.is_privileged(role_id):
            continue
        pid = a.get("principalId", "")
        role = roles.role_name(role_id)
        scope = a.get("directoryScopeId") or "/"
        tenant_wide = scope == "/"
        permanent = a.get("source") == "direct" or (
            (a.get("assignmentType") or "Assigned") == "Assigned" and not a.get("endDateTime"))
        how = "permanent (standing)" if permanent else (
            "time-bound PIM activation" if a.get("assignmentType") == "Activated" else "time-bound assignment")
        where = "tenant-wide" if tenant_wide else f"scoped to {scope}"
        evidence = {"role": role, "scope": scope, "permanent": permanent, "assignment": how}

        def adjust(sev: str) -> str:
            return sev if tenant_wide else lower_severity(sev)

        if pid in users:
            user = users[pid]
            upn = _upn(user)
            if roles.is_global_admin(role_id) and user.get("accountEnabled"):
                global_admins.add(pid)
            if upn in cfg.break_glass:
                if upn not in break_glass_seen:
                    break_glass_seen.add(upn)
                    findings.append(Finding(
                        "break_glass_account", "info", "Break-glass account holds a privileged role", _name(user),
                        f"{role}, {how}, {where}. Expected for an emergency-access account.",
                        "Keep it cloud-only with a FIDO2 key, exclude it from Conditional Access deliberately, "
                        "and alert on every sign-in.", evidence))
                continue
            if (user.get("userType") or "").lower() == "guest":
                findings.append(Finding(
                    "guest_privileged_role", adjust("critical"), "Guest account holds a privileged role", _name(user),
                    f"{role}, {how}, {where}. The account's security is controlled by another tenant.",
                    "Remove the role. Give the person a member account in your tenant if they need admin rights.",
                    evidence))
                continue
            if not user.get("accountEnabled"):
                findings.append(Finding(
                    "disabled_user_with_role", "low", "Disabled account still holds a privileged role", _name(user),
                    f"{role}, {how}, {where}.",
                    "Remove the role so re-enabling the account does not silently restore admin access.",
                    evidence))
                continue
            if user.get("onPremisesSyncEnabled"):
                findings.append(Finding(
                    "synced_privileged_account", adjust("high"), "Admin account is synchronized from on-prem AD",
                    _name(user), f"{role}, {how}, {where}. Compromising on-prem AD compromises this cloud admin.",
                    "Use a separate cloud-only account for Entra admin roles.", evidence))
            if permanent:
                severity = "critical" if roles.is_global_admin(role_id) else "high"
                note = "" if pim else " (PIM data was unavailable, so every active assignment is treated as standing)"
                findings.append(Finding(
                    "standing_privileged_role", adjust(severity), "Permanent privileged role assignment", _name(user),
                    f"{role}, {how}, {where}{note}.",
                    "Convert to a PIM eligible assignment with MFA, justification and a short activation window.",
                    evidence))
        elif pid in sps:
            sp = sps[pid]
            findings.append(Finding(
                "service_principal_privileged_role", adjust("high"), "Service principal holds a privileged role",
                f"{sp.get('displayName') or pid} ({sp.get('appId', pid)})",
                f"{role}, {how}, {where}. Anyone with the app's credentials has these rights.",
                "Prefer narrowly scoped application permissions or an administrative unit; protect and rotate "
                "the app's credentials and alert on credential changes.", evidence))
        else:
            obj = others.get(pid, {})
            otype = (obj.get("@odata.type") or "").rsplit(".", 1)[-1] or "principal"
            name = obj.get("displayName") or pid
            if otype == "group":
                findings.append(Finding(
                    "group_privileged_role", adjust("medium"), "Role assigned through a group", name,
                    f"{role}, {how}, {where}. Every member of the role-assignable group holds the role.",
                    "Review group owners and members, and use PIM for Groups so membership is time-bound.",
                    evidence))
            else:
                findings.append(Finding(
                    "unresolved_privileged_principal", "medium", "Privileged role held by an unresolved principal",
                    name, f"{role}, {how}, {where}. The principal could not be looked up ({otype}).",
                    "Check the assignment in the Entra admin center; remove it if the object no longer exists.",
                    evidence))

    count = len(global_admins)
    if count > cfg.max_global_admins:
        findings.append(Finding(
            "too_many_global_admins", "medium", "Too many Global Administrators", "Global Administrator",
            f"{count} enabled accounts hold Global Administrator (recommended: {cfg.min_global_admins}-"
            f"{cfg.max_global_admins}, including break-glass accounts).",
            "Move day-to-day admins to least-privileged roles.", {"count": count}))
    elif count < cfg.min_global_admins:
        findings.append(Finding(
            "too_few_global_admins", "medium", "Too few Global Administrators", "Global Administrator",
            f"Only {count} enabled account(s) hold Global Administrator; losing one could lock you out.",
            "Keep two cloud-only break-glass accounts.", {"count": count}))
    return findings


# --------------------------------------------------------------------------- entry point

def analyze(snap: dict[str, Any], cfg: AuditConfig) -> AuditResult:
    now = cfg.now or parse_time(snap.get("captured_at"))
    if now is None:
        raise ValueError("snapshot has no captured_at and no 'now' was given")
    roles = _RoleIndex(snap)
    findings: list[Finding] = []
    if "stale" in cfg.checks:
        findings += _check_stale(snap, cfg, now, roles)
    if "mfa" in cfg.checks:
        findings += _check_mfa(snap, cfg, roles)
    if "consent" in cfg.checks:
        findings += _check_consents(snap, cfg)
    if "roles" in cfg.checks:
        findings += _check_roles(snap, cfg, roles)

    users = snap.get("users", [])
    enabled_members = [u for u in users if u.get("accountEnabled") and (u.get("userType") or "Member") == "Member"]
    reg = {r.get("id"): r for r in (snap.get("registration") or [])}
    mfa_known = [u for u in enabled_members if u.get("id") in reg]
    mfa_ok = [u for u in mfa_known if reg[u["id"]].get("isMfaRegistered")]
    privileged_assignments = [a for a in roles.assignments if roles.is_privileged(a.get("roleDefinitionId", ""))]
    stats = {
        "users_total": len(users),
        "users_enabled": sum(1 for u in users if u.get("accountEnabled")),
        "guests": sum(1 for u in users if (u.get("userType") or "").lower() == "guest"),
        "mfa_registered_pct": round(100 * len(mfa_ok) / len(mfa_known), 1) if mfa_known else None,
        "service_principals": len(snap.get("service_principals", [])),
        "privileged_assignments": len(privileged_assignments),
        "pim_available": snap.get("pim_available", False),
        "sign_in_activity_available": snap.get("sign_in_activity_available", False),
    }
    notes = [f"{name}: {message}" for name, message in sorted((snap.get("errors") or {}).items())]
    if "stale" in cfg.checks and not snap.get("sign_in_activity_available") and "sign_in_activity" not in (
            snap.get("errors") or {}):
        notes.append("sign_in_activity: not collected; stale-account checks were skipped.")
    return AuditResult(sort_findings(findings), stats, notes)
