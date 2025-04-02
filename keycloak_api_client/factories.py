from typing import Any
from uuid import UUID

from attrs.converters import to_bool

from keycloak_api_client.data_classes import ReadKeycloakUser, KeycloakClient


def read_keycloak_user_factory(user_endpoint_data: dict[str, Any]) -> ReadKeycloakUser:
    def _get_casted_value_if_present(val: Any | None, cast: type) -> Any | None:
        if val:
            return cast(val)

    return ReadKeycloakUser(
        keycloak_id=UUID(user_endpoint_data.get("id")),
        username=str(user_endpoint_data.get("username")),
        first_name=_get_casted_value_if_present(
            user_endpoint_data.get("firstName"), str
        ),
        last_name=_get_casted_value_if_present(user_endpoint_data.get("lastName"), str),
        email=str(user_endpoint_data.get("email")),
        enabled=to_bool(str(user_endpoint_data.get("enabled"))),
        email_verified=to_bool(str(user_endpoint_data.get("emailVerified"))),
        raw_data=user_endpoint_data,
    )


def keycloak_client_factory(client_endpoint_data: dict[str, str]) -> KeycloakClient:
    return KeycloakClient(
        keycloak_id=UUID(client_endpoint_data.get("id")),
        client_id=str(client_endpoint_data.get("clientId")),
        enabled=to_bool(str(client_endpoint_data.get("enabled"))),
        service_account_enabled=to_bool(
            str(client_endpoint_data.get("serviceAccountsEnabled"))
        ),
    )
