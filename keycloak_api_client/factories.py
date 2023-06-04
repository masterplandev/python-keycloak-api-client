from uuid import UUID

from keycloak_api_client.data_classes import ReadKeycloakUser, KeycloakClient


def read_keycloak_user_factory(user_endpoint_data: dict) -> ReadKeycloakUser:
    return ReadKeycloakUser(
        keycloak_id=UUID(user_endpoint_data.get('id')),
        username=user_endpoint_data.get('username'),
        first_name=user_endpoint_data.get('firstName'),
        last_name=user_endpoint_data.get('lastName'),
        email=user_endpoint_data.get('email'),
        enabled=user_endpoint_data.get('enabled'),
        email_verified=user_endpoint_data.get('emailVerified'),
        raw_data=user_endpoint_data
    )


def keycloak_client_factory(client_endpoint_data: dict) -> KeycloakClient:
    return KeycloakClient(
        keycloak_id=UUID(client_endpoint_data.get('id')),
        client_id=client_endpoint_data.get('clientId'),
        enabled=client_endpoint_data.get('enabled'),
        service_account_enabled=(
            client_endpoint_data.get('serviceAccountsEnabled')
        )
    )
