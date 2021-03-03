from uuid import UUID

from keycloak_api_client.data_classes import ReadKeycloakUser


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
