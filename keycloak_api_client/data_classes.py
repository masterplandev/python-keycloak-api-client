from uuid import UUID

import attr


@attr.s(auto_attribs=True)
class KeycloakFederatedIdentity:
    provider_name: str
    user_id: str
    user_name: str


@attr.s(auto_attribs=True)
class BaseKeycloakUser:
    username: str
    first_name: str
    last_name: str
    email: str
    enabled: bool
    email_verified: bool


@attr.s(auto_attribs=True)
class WriteKeycloakUser(BaseKeycloakUser):
    attributes: dict[str, str] | None
    keycloak_id: UUID | None = None
    raw_password: str | None = None
    hashed_password: str | None = None
    federated_identities: list[KeycloakFederatedIdentity] | None = None


@attr.s(auto_attribs=True)
class ReadKeycloakUser(BaseKeycloakUser):
    keycloak_id: UUID
    raw_data: dict[str, str]


@attr.s(auto_attribs=True)
class KeycloakTokens:
    access_token: str
    refresh_token: str


@attr.s(auto_attribs=True)
class KeycloakClient:
    keycloak_id: UUID
    client_id: str
    enabled: bool
    service_account_enabled: bool
