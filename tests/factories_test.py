from uuid import UUID

from keycloak_api_client.factories import (
    keycloak_client_factory,
    read_keycloak_user_factory,
)


def test_create_user_from_keycloak_data():
    data1 = {
        "id": "3f169eaa-8405-46e0-b106-e4f1823331e1",
        "createdTimestamp": 1590563321150,
        "username": "any@test.com",
        "enabled": True,
        "totp": False,
        "emailVerified": True,
        "firstName": "name",
        "lastName": "surname",
        "email": "any@test.com",
        "attributes": {
            "legacy_user_id": ["281eecba-da9f-4806-835d-59eb06856f32"],
            "company_id": ["f4be2d0f-af90-07b0-44b9-05629d2cb8de"],
            "phone": ["111222333"],
            "date_of_birth": ["2000-11-13"],
            "title": ["mr"],
            "job_title": ["job_title"],
        },
        "disableableCredentialTypes": [],
        "requiredActions": [],
        "notBefore": 0,
        "access": {
            "manageGroupMembership": True,
            "view": True,
            "mapRoles": True,
            "impersonate": True,
            "manage": True,
        },
    }

    keycloak_user1 = read_keycloak_user_factory(user_endpoint_data=data1)

    assert keycloak_user1.keycloak_id == UUID("3f169eaa-8405-46e0-b106-e4f1823331e1")
    assert keycloak_user1.username == "any@test.com"
    assert keycloak_user1.first_name == "name"
    assert keycloak_user1.last_name == "surname"
    assert keycloak_user1.email == "any@test.com"
    assert keycloak_user1.enabled
    assert keycloak_user1.email_verified
    assert keycloak_user1.raw_data == data1

    data2 = {
        "id": "3f169eaa-8405-46e0-b106-e4f1823331e1",
        "createdTimestamp": 1590563321150,
        "username": "any@test.com",
        "enabled": True,
        "totp": False,
        "emailVerified": True,
        "firstName": None,
        "lastName": None,
        "email": "any@test.com",
        "attributes": {
            "legacy_user_id": ["281eecba-da9f-4806-835d-59eb06856f32"],
            "company_id": ["f4be2d0f-af90-07b0-44b9-05629d2cb8de"],
            "phone": ["111222333"],
            "date_of_birth": ["2000-11-13"],
            "title": ["mr"],
            "job_title": ["job_title"],
        },
        "disableableCredentialTypes": [],
        "requiredActions": [],
        "notBefore": 0,
        "access": {
            "manageGroupMembership": True,
            "view": True,
            "mapRoles": True,
            "impersonate": True,
            "manage": True,
        },
    }

    keycloak_user2 = read_keycloak_user_factory(user_endpoint_data=data2)

    assert keycloak_user2.keycloak_id == UUID("3f169eaa-8405-46e0-b106-e4f1823331e1")
    assert keycloak_user2.username == "any@test.com"
    assert not keycloak_user2.first_name
    assert not keycloak_user2.last_name
    assert keycloak_user2.email == "any@test.com"
    assert keycloak_user2.enabled
    assert keycloak_user2.email_verified
    assert keycloak_user2.raw_data == data2


def test_keycloak_client_factory():
    data = {
        "access": {"configure": True, "manage": True, "view": True},
        "alwaysDisplayInConsole": False,
        "attributes": {
            "backchannel.logout.revoke.offline.tokens": "false",
            "backchannel.logout.session.required": "true",
        },
        "authenticationFlowBindingOverrides": {},
        "bearerOnly": False,
        "clientAuthenticatorType": "client-secret",
        "clientId": "existing_client_id",
        "consentRequired": False,
        "defaultClientScopes": ["web-origins", "acr", "roles", "profile", "email"],
        "directAccessGrantsEnabled": True,
        "enabled": True,
        "frontchannelLogout": False,
        "fullScopeAllowed": True,
        "id": "15d9cce8-2e11-4f37-adde-cb686d037a60",
        "implicitFlowEnabled": False,
        "nodeReRegistrationTimeout": -1,
        "notBefore": 0,
        "optionalClientScopes": [
            "address",
            "phone",
            "offline_access",
            "microprofile-jwt",
        ],
        "protocol": "openid-connect",
        "publicClient": True,
        "redirectUris": [],
        "serviceAccountsEnabled": False,
        "standardFlowEnabled": True,
        "surrogateAuthRequired": False,
        "webOrigins": [],
    }

    keycloak_client = keycloak_client_factory(client_endpoint_data=data)

    assert keycloak_client.keycloak_id == UUID("15d9cce8-2e11-4f37-adde-cb686d037a60")
    assert keycloak_client.client_id == "existing_client_id"
    assert keycloak_client.enabled is True
    assert keycloak_client.service_account_enabled is False
