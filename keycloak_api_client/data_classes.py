from typing import List, Optional
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
    attributes: Optional[dict]
    keycloak_id: Optional[UUID] = None
    raw_password: Optional[str] = None
    hashed_password: Optional[str] = None
    federated_identities: Optional[List[KeycloakFederatedIdentity]] = None


@attr.s(auto_attribs=True)
class ReadKeycloakUser(BaseKeycloakUser):
    keycloak_id: UUID
    raw_data: dict


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
