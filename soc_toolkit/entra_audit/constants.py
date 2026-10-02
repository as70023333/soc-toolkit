"""Reference data for the Entra ID audit."""

from __future__ import annotations

# Built-in Entra roles that can change security posture or take over the tenant, by role
# template ID (stable across tenants). Used when the API does not return isPrivileged.
PRIVILEGED_ROLE_TEMPLATES: dict[str, str] = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator",
    "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
    "7698a772-787b-4ac8-901f-60d6b08affd2": "Cloud Device Administrator",
    "8329153b-31d0-4727-b945-745eb3bc5f31": "Domain Name Administrator",
    "be2f45a1-457d-42af-a067-6ec1fa63bc45": "External Identity Provider Administrator",
    "0526716b-113d-4c15-b2c8-68e3c22b9f80": "Authentication Policy Administrator",
    "fdd7a751-b60b-444a-984c-02652fe8fa1c": "Groups Administrator",
    "17315797-102d-40b4-93e0-432062caca18": "Compliance Administrator",
    "9360feb5-f418-4baa-8175-e2a00bac4301": "Directory Writers",
    "69091246-20e8-4a56-aa4d-066075b2a7a8": "Teams Administrator",
    "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8": "Partner Tier2 Support",
}
GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"

# Apps owned by these tenants are Microsoft first-party services; their grants are not consents
# your users or admins made, so they are skipped.
MICROSOFT_TENANTS = frozenset({
    "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
    "72f988bf-86f1-41af-91ab-2d7cd011db47",
})

GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
EXCHANGE_APP_ID = "00000002-0000-0ff1-ce00-000000000000"
SHAREPOINT_APP_ID = "00000003-0000-0ff1-ce00-000000000000"
RISKY_RESOURCE_APPS = (GRAPH_APP_ID, EXCHANGE_APP_ID, SHAREPOINT_APP_ID)

# Permissions that let an app take over the tenant (grant itself roles, add credentials, change
# sign-in policy or authentication methods). Names match both app roles and delegated scopes.
TAKEOVER_PERMISSIONS: dict[str, str] = {
    "RoleManagement.ReadWrite.Directory": "can assign any directory role, including Global Administrator",
    "AppRoleAssignment.ReadWrite.All": "can grant itself any application permission",
    "Application.ReadWrite.All": "can add credentials to any app and act as it",
    "Directory.ReadWrite.All": "can modify most directory objects",
    "Directory.AccessAsUser.All": "acts as the signed-in user across the whole directory",
    "UserAuthenticationMethod.ReadWrite.All": "can register MFA methods for any user",
    "Policy.ReadWrite.ConditionalAccess": "can disable Conditional Access policies",
    "Policy.ReadWrite.AuthenticationMethod": "can change which MFA methods are allowed",
    "Domain.ReadWrite.All": "can add a federated domain (Golden SAML style backdoor)",
    "User.ReadWrite.All": "can change any user, including resetting profile data",
    "Group.ReadWrite.All": "can add members to any group, including role-assignable ones",
    "GroupMember.ReadWrite.All": "can add members to any group",
    "Exchange.ManageAsApp": "can run Exchange Online admin cmdlets",
}

# Permissions that expose bulk mail, files or chat data.
DATA_PERMISSIONS: dict[str, str] = {
    "Mail.Read": "reads mail",
    "Mail.ReadWrite": "reads and changes mail",
    "Mail.Send": "sends mail as users",
    "MailboxSettings.ReadWrite": "can create forwarding rules",
    "full_access_as_app": "full access to every mailbox (EWS)",
    "full_access_as_user": "full mailbox access as the user (EWS)",
    "EWS.AccessAsUser.All": "full mailbox access as the user (EWS)",
    "Files.Read.All": "reads all files the identity can reach",
    "Files.ReadWrite.All": "reads and changes all files",
    "Sites.Read.All": "reads all SharePoint sites",
    "Sites.ReadWrite.All": "reads and changes all SharePoint sites",
    "Sites.Manage.All": "manages SharePoint sites and lists",
    "Sites.FullControl.All": "full control of all SharePoint sites",
    "Chat.Read.All": "reads all Teams chats",
    "Chat.ReadWrite.All": "reads and changes all Teams chats",
    "ChannelMessage.Read.All": "reads all Teams channel messages",
    "Notes.Read.All": "reads all OneNote notebooks",
    "Notes.ReadWrite.All": "reads and changes all OneNote notebooks",
    "Contacts.ReadWrite": "reads and changes contacts",
    "User.Export.All": "exports user data",
}

# MFA methods (methodsRegistered values) that are phishable and weak on their own.
WEAK_METHODS = frozenset({"mobilePhone", "alternateMobilePhone", "officePhone", "email", "securityQuestion"})

# Phishing-resistant methods. Values starting with "passKey" are matched as a prefix as well.
PHISHING_RESISTANT_METHODS = frozenset({
    "fido2SecurityKey", "windowsHelloForBusiness", "x509Certificate", "x509CertificateSingleFactor",
    "x509CertificateMultiFactor", "platformCredential", "macOsSecureEnclaveKey",
})


def is_phishing_resistant(method: str) -> bool:
    return method in PHISHING_RESISTANT_METHODS or method.startswith("passKey")
