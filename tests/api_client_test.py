from typing import List, Optional
from uuid import UUID

import pytest

from keycloak_api_client import KeycloakApiClient
from keycloak_api_client.data_classes import (
    KeycloakClient,
    KeycloakFederatedIdentity,
    KeycloakTokens,
    ReadKeycloakUser,
    WriteKeycloakUser
)
from keycloak_api_client.exceptions import KeycloakApiClientException
from keycloak_api_client.factories import read_keycloak_user_factory

raw_user_1_data = {
    "id": "7428411e-38c3-47da-9b2e-181502b7148f",
    "createdTimestamp": 1614767329366,
    "username": "testname1",
    "enabled": True,
    "totp": False,
    "emailVerified": True,
    "firstName": "firstname",
    "lastName": "lastname",
    "email": "testname1@test.com",
    "attributes": {"some_attrib": ["val1"]},
    "disableableCredentialTypes": [],
    "requiredActions": [],
    "notBefore": 0,
    "access": {
        "manageGroupMembership": True,
        "view": True, "mapRoles": True,
        "impersonate": True, "manage": True
    }
}


raw_user_2_data = {
    "id": "11a8cc8e-b6c9-4f1c-9814-a861b8ade6cf",
    "createdTimestamp": 1614767377821,
    "username": "testname2",
    "enabled": True,
    "totp": False,
    "emailVerified": True,
    "firstName": "firstname1",
    "lastName": "firstname2",
    "email": "test2@test.com",
    "attributes": {"other_attrib": ["val2"]},
    "disableableCredentialTypes": [],
    "requiredActions": [],
    "notBefore": 0,
    "access": {
        "manageGroupMembership": True, "view": True,
        "mapRoles": True, "impersonate": True, "manage": True
    }
}

raw_existing_client_data = {
    'access': {'configure': True, 'manage': True, 'view': True},
    'alwaysDisplayInConsole': False,
    'attributes': {'backchannel.logout.revoke.offline.tokens': 'false',
                   'backchannel.logout.session.required': 'true'},
    'authenticationFlowBindingOverrides': {},
    'bearerOnly': False,
    'clientAuthenticatorType': 'client-secret',
    'clientId': 'existing_client_id',
    'consentRequired': False,
    'defaultClientScopes': ['web-origins', 'acr', 'roles', 'profile', 'email'],
    'directAccessGrantsEnabled': True,
    'enabled': True,
    'frontchannelLogout': False,
    'fullScopeAllowed': True,
    'id': '15d9cce8-2e11-4f37-adde-cb686d037a60',
    'implicitFlowEnabled': False,
    'nodeReRegistrationTimeout': -1,
    'notBefore': 0,
    'optionalClientScopes': ['address',
                             'phone',
                             'offline_access',
                             'microprofile-jwt'],
    'protocol': 'openid-connect',
    'publicClient': True,
    'redirectUris': [],
    'serviceAccountsEnabled': False,
    'standardFlowEnabled': True,
    'surrogateAuthRequired': False,
    'webOrigins': []
}


def _keycloak_api_client_factory():
    return KeycloakApiClient(
        keycloak_url='http://localhost:8080',
        realm='my-realm',
        admin_username='admin-user',
        admin_password='admin-pass',
        admin_client_id='admin-client-id',
        admin_client_secret='18069767-90f4-4364-a519-28f908727d7e',
        token_exchange_target_client_id='frontend',
    )


def _get_keycloak_user_fixture(
    suffix: str,
    federated_identities: Optional[List[KeycloakFederatedIdentity]] = None,
    keycloak_id: Optional[UUID] = None,
    hashed_password: Optional[str] = None
) -> WriteKeycloakUser:
    return WriteKeycloakUser(
        username=f'_username{suffix}',
        first_name=f'_first_name{suffix}',
        last_name=f'_last_name{suffix}',
        email=f'_test-user{suffix}@test.com',
        raw_password='pass',
        hashed_password=hashed_password,
        enabled=False,
        email_verified=False,
        federated_identities=federated_identities,
        keycloak_id=keycloak_id,
        attributes={
            'some_attrib': f'val{suffix}'
        }
    )


@pytest.mark.vcr()
def test_search_for_existing_user():
    assert _keycloak_api_client_factory().search_users(
        query='testname'
    ) == [
        ReadKeycloakUser(
            keycloak_id=UUID('7428411e-38c3-47da-9b2e-181502b7148f'),
            username='testname1',
            first_name='firstname',
            last_name='lastname',
            email='testname1@test.com',
            enabled=True,
            email_verified=True,
            raw_data=raw_user_1_data
        ),
        ReadKeycloakUser(
            keycloak_id=UUID('11a8cc8e-b6c9-4f1c-9814-a861b8ade6cf'),
            username='testname2',
            first_name='firstname1',
            last_name='firstname2',
            email='test2@test.com',
            enabled=True,
            email_verified=True,
            raw_data=raw_user_2_data
        ),
    ]


@pytest.mark.vcr()
def test_search_for_existing_user_with_limit_and_offset():
    assert _keycloak_api_client_factory().search_users(
        query='testname', limit=1, offset=1
    ) == [
        ReadKeycloakUser(
            keycloak_id=UUID('11a8cc8e-b6c9-4f1c-9814-a861b8ade6cf'),
            username='testname2',
            first_name='firstname1',
            last_name='firstname2',
            email='test2@test.com',
            enabled=True,
            email_verified=True,
            raw_data=raw_user_2_data
        ),
    ]


@pytest.mark.vcr()
def test_get_existing_user():
    assert _keycloak_api_client_factory().get_keycloak_user_by_email(
        email='testname1@test.com'
    ) == ReadKeycloakUser(
        keycloak_id=UUID('7428411e-38c3-47da-9b2e-181502b7148f'),
        username='testname1',
        first_name='firstname',
        last_name='lastname',
        email='testname1@test.com',
        enabled=True,
        email_verified=True,
        raw_data=raw_user_1_data
    )


@pytest.mark.vcr()
def test_get_not_existing_user_when_partially_matching_emails_returned():
    assert _keycloak_api_client_factory().get_keycloak_user_by_email(
        email='some-prefix-testname1@test.com'
    ) is None


@pytest.mark.vcr()
def test_get_existing_user_by_keycloak_id():
    assert _keycloak_api_client_factory().get_keycloak_user_by_id(
        keycloak_id=UUID('11a8cc8e-b6c9-4f1c-9814-a861b8ade6cf')
    ) == ReadKeycloakUser(
        keycloak_id=UUID('11a8cc8e-b6c9-4f1c-9814-a861b8ade6cf'),
        username='testname2',
        first_name='firstname1',
        last_name='firstname2',
        email='test2@test.com',
        enabled=True,
        email_verified=True,
        raw_data=raw_user_2_data
    )


@pytest.mark.vcr()
def test_get_not_existing_user():
    assert _keycloak_api_client_factory().get_keycloak_user_by_email(
        email='not-existing@test.com'
    ) is None


@pytest.mark.vcr()
def test_get_not_existing_user_by_id():
    assert _keycloak_api_client_factory().get_keycloak_user_by_id(
        keycloak_id=UUID('3c2e80d3-3805-4325-9de6-7a8ec5b571d4')
    ) is None


@pytest.mark.vcr()
def test_register_then_update_then_get_user():
    keycloak_api_client = _keycloak_api_client_factory()
    keycloak_id = UUID('bacca16b-8fe8-4dc3-bf5e-3599adcb545e')

    assert keycloak_id == keycloak_api_client.register_user(
        _get_keycloak_user_fixture(suffix='1')
    )

    assert keycloak_api_client.get_keycloak_user_by_email(
        '_test-user1@test.com'
    ) == read_keycloak_user_factory({
        "id": str(keycloak_id),
        "createdTimestamp": 1614770258309,
        "username": "_username1",
        "enabled": False,
        "totp": False,
        "emailVerified": False,
        "firstName": "_first_name1",
        "lastName": "_last_name1",
        "email": "_test-user1@test.com",
        "attributes": {
            "some_attrib": ["val1"]
        },
        "disableableCredentialTypes": [],
        "requiredActions": [],
        "notBefore": 0,
        "access": {
            "manageGroupMembership": True,
            "view": True,
            "mapRoles": True,
            "impersonate": True,
            "manage": True
        }
    })

    keycloak_api_client.update_user(
        _get_keycloak_user_fixture(
            suffix='2',
            federated_identities=[
                KeycloakFederatedIdentity(
                    provider_name='linkedin',
                    user_id='linkedin-id',
                    user_name='linkedin-name',
                )
            ],
            keycloak_id=keycloak_id
        )
    )

    assert keycloak_api_client.get_keycloak_user_by_email(
        '_test-user2@test.com'
    ) == read_keycloak_user_factory({
        'id': str(keycloak_id),
        'createdTimestamp': 1614770258309,
        'username': '_username2',
        'enabled': False,
        'totp': False,
        'emailVerified': False,
        'firstName': '_first_name2',
        'lastName': '_last_name2',
        'email': '_test-user2@test.com',
        'attributes': {
            'some_attrib': ['val2'],
        },
        "disableableCredentialTypes": [],
        "requiredActions": [],
        "notBefore": 0,
        "access": {
            "manageGroupMembership": True,
            "view": True,
            "mapRoles": True,
            "impersonate": True,
            "manage": True
        }
    })

    assert [
        dict(
            identityProvider='linkedin',
            userId='linkedin-id',
            userName='linkedin-name',
        )
    ] == keycloak_api_client._get_user_identities(
        keycloak_id=keycloak_id
    )


@pytest.mark.vcr()
def test_get_user_tokens():
    keycloak_api_client = _keycloak_api_client_factory()
    keycloak_id = keycloak_api_client.register_user(
        _get_keycloak_user_fixture(suffix='1')
    )
    assert keycloak_api_client.get_user_tokens(
        keycloak_id=keycloak_id,
        starting_client_id=keycloak_api_client.admin_client_id,
        target_client_id=keycloak_api_client.token_exchange_target_client_id,
        starting_client_secret=keycloak_api_client.admin_client_secret
    ) == KeycloakTokens(
        access_token='eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJpS0ZBa1YyY2xDWTdodlhGVTNrZmN2RzY2UHpKQWplYjFtU2hEOEVzVFRBIn0.eyJleHAiOjE2MTQ3NzE5NTAsImlhdCI6MTYxNDc3MTY1MCwianRpIjoiMTFiMDk0ZjgtYTg2MC00OGNlLTk5MWMtN2QxMGZkMzhkOWZkIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL215LXJlYWxtIiwiYXVkIjpbImFjY291bnQiLCJmcm9udGVuZCJdLCJzdWIiOiIzNDZkZjMxYS0zMmExLTRkOWItYjYxMy1jNmQwYjRmZDFiYjAiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJmcm9udGVuZCIsInNlc3Npb25fc3RhdGUiOiI0ZGY4Mjk4Yy1mZWJlLTQ5ZmUtODY0Zi0wZDk1NDc0MzUxMzMiLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJfZmlyc3RfbmFtZTEgX2xhc3RfbmFtZTEiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJfdXNlcm5hbWUxIiwiZ2l2ZW5fbmFtZSI6Il9maXJzdF9uYW1lMSIsImZhbWlseV9uYW1lIjoiX2xhc3RfbmFtZTEiLCJlbWFpbCI6Il90ZXN0LXVzZXIxQHRlc3QuY29tIn0.CriZLjpfHF4OXPA4n2o5iu0unaC0xWy0FdeeG_KJD6MZ75EaFS3yo-jSDgwO1U91y7lZtHyOtWzntJ2j_MgvyhUWEivaL1mWeUdPOlZAFcsIUKzu_K_1Ht7AmSAOIkoDafsgmqCMs546dNnul3bT13rXgVsmPN0ndXBromo--liTDcPw1lGUqKRA9Ph-SrPV0we_BBTmXF-SuOTlOh1bK7m6WkL93Z6c3a6qEnuxeqPMiQGRh_qkeJ-FY6hNn-3ZL2HNgiJJT_VxlX--E1gKz3F2kx2p3UzjmPNzbURasG6VaXKXK0i2dQ8vIl1HGSbXkVG-X1YJZM_BxPM9CYkaWw',  # noqa
        refresh_token='eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJmYjJjZDVjNC05NTk4LTQxMjQtODQzZC04OWJjZWJlNjdjOWEifQ.eyJleHAiOjE2MTQ3NzM0NTAsImlhdCI6MTYxNDc3MTY1MCwianRpIjoiYzdlMDNlMDQtYzhjNC00ZGQ3LTkwN2YtMWJkMTZhNGI0NDUyIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL215LXJlYWxtIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL215LXJlYWxtIiwic3ViIjoiMzQ2ZGYzMWEtMzJhMS00ZDliLWI2MTMtYzZkMGI0ZmQxYmIwIiwidHlwIjoiUmVmcmVzaCIsImF6cCI6ImZyb250ZW5kIiwic2Vzc2lvbl9zdGF0ZSI6IjRkZjgyOThjLWZlYmUtNDlmZS04NjRmLTBkOTU0NzQzNTEzMyIsInNjb3BlIjoicHJvZmlsZSBlbWFpbCJ9.eYeCbgYZfUj8Y-605hdsU2sp6M9gqTXRMp-YtZrtHmw'  # noqa
    )
    keycloak_api_client = _keycloak_api_client_factory()
    assert keycloak_api_client.get_user_tokens(
        keycloak_id=keycloak_id,
        starting_client_id=keycloak_api_client.token_exchange_target_client_id,
        target_client_id=keycloak_api_client.token_exchange_target_client_id
    ) == KeycloakTokens(
        access_token='eybbbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJpS0ZBa1YyY2xDWTdodlhGVTNrZmN2RzY2UHpKQWplYjFtU2hEOEVzVFRBIn0.eyJleHAiOjE2MTQ3NzE5NTAsImlhdCI6MTYxNDc3MTY1MCwianRpIjoiMTFiMDk0ZjgtYTg2MC00OGNlLTk5MWMtN2QxMGZkMzhkOWZkIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL215LXJlYWxtIiwiYXVkIjpbImFjY291bnQiLCJmcm9udGVuZCJdLCJzdWIiOiIzNDZkZjMxYS0zMmExLTRkOWItYjYxMy1jNmQwYjRmZDFiYjAiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJmcm9udGVuZCIsInNlc3Npb25fc3RhdGUiOiI0ZGY4Mjk4Yy1mZWJlLTQ5ZmUtODY0Zi0wZDk1NDc0MzUxMzMiLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJfZmlyc3RfbmFtZTEgX2xhc3RfbmFtZTEiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJfdXNlcm5hbWUxIiwiZ2l2ZW5fbmFtZSI6Il9maXJzdF9uYW1lMSIsImZhbWlseV9uYW1lIjoiX2xhc3RfbmFtZTEiLCJlbWFpbCI6Il90ZXN0LXVzZXIxQHRlc3QuY29tIn0.CriZLjpfHF4OXPA4n2o5iu0unaC0xWy0FdeeG_KJD6MZ75EaFS3yo-jSDgwO1U91y7lZtHyOtWzntJ2j_MgvyhUWEivaL1mWeUdPOlZAFcsIUKzu_K_1Ht7AmSAOIkoDafsgmqCMs546dNnul3bT13rXgVsmPN0ndXBromo--liTDcPw1lGUqKRA9Ph-SrPV0we_BBTmXF-SuOTlOh1bK7m6WkL93Z6c3a6qEnuxeqPMiQGRh_qkeJ-FY6hNn-3ZL2HNgiJJT_VxlX--E1gKz3F2kx2p3UzjmPNzbURasG6VaXKXK0i2dQ8vIl1HGSbXkVG-X1YJZM_BxPM9CYkaWw',  # noqa
        refresh_token='eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJmYjJjZDVjNC05NTk4LTQxMjQtODQzZC04OWJjZWJlNjdjOWEifQ.eyJleHAiOjE2MTQ3NzM0NTAsImlhdCI6MTYxNDc3MTY1MCwianRpIjoiYzdlMDNlMDQtYzhjNC00ZGQ3LTkwN2YtMWJkMTZhNGI0NDUyIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL215LXJlYWxtIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL215LXJlYWxtIiwic3ViIjoiMzQ2ZGYzMWEtMzJhMS00ZDliLWI2MTMtYzZkMGI0ZmQxYmIwIiwidHlwIjoiUmVmcmVzaCIsImF6cCI6ImZyb250ZW5kIiwic2Vzc2lvbl9zdGF0ZSI6IjRkZjgyOThjLWZlYmUtNDlmZS04NjRmLTBkOTU0NzQzNTEzMyIsInNjb3BlIjoicHJvZmlsZSBlbWFpbCJ9.eYeCbgYZfUj8Y-605hdsU2sp6M9gqTXRMp-YtZrtHmw'  # noqa
    )


@pytest.mark.vcr()
def test_count_users():
    assert _keycloak_api_client_factory().count_users() == 3
    assert _keycloak_api_client_factory().count_users(query='test') == 2


@pytest.mark.vcr()
def test_password_reset():
    assert _keycloak_api_client_factory().reset_password(
        keycloak_id=raw_user_1_data["id"],
        new_password="test",
        temporary=False
    ) is None
    keycloak_user = _keycloak_api_client_factory().search_users(
        query=raw_user_1_data["username"])[0]
    assert "UPDATE_PASSWORD" not in keycloak_user.raw_data["requiredActions"]
    assert _keycloak_api_client_factory().reset_password(
        keycloak_id=raw_user_1_data["id"],
        new_password="test",
        temporary=True
    ) is None
    keycloak_user = _keycloak_api_client_factory().search_users(
        query=raw_user_1_data["username"])[0]
    assert "UPDATE_PASSWORD" in keycloak_user.raw_data["requiredActions"]
    with pytest.raises(KeycloakApiClientException):
        _keycloak_api_client_factory().reset_password(
            keycloak_id=raw_user_1_data["id"],
            new_password="test",
            temporary=True
        )


@pytest.mark.vcr()
def test_send_verification_email():
    assert _keycloak_api_client_factory().send_verification_email(
        keycloak_id=raw_user_1_data['id']
    ) is None

    with pytest.raises(KeycloakApiClientException) as ex:
        _keycloak_api_client_factory().send_verification_email(
            keycloak_id=UUID('eae0c454-ebca-41df-8279-f0d282c31a44')
        )
    assert str(ex.value) == (
        'Error while sending a verification email for user with ID '
        'eae0c454-ebca-41df-8279-f0d282c31a44 '
        '(msg: {\'error\': \'User not found\'})'
    )


@pytest.mark.vcr()
def test_create_client_and_create_mapper():
    client_id = "test_client_id"
    client_secret = "test_secret"
    id_of_client = UUID("00000000-0000-0000-0000-000000000000")
    wrong_id_of_client = UUID("00000000-0000-0000-0000-000000000001")
    _keycloak_api_client_factory()._get_authorization_header(
    )
    assert _keycloak_api_client_factory().create_client(
        client_id=client_id,
        client_secret=client_secret,
        id=str(id_of_client)
    ) is None

    with pytest.raises(KeycloakApiClientException) as ex:
        _keycloak_api_client_factory().create_client(
            client_id=client_id,
            client_secret=client_secret,
            id=str(id_of_client)
        )

    assert str(ex.value) == (
        "Error while creating new client "
        "with data={'clientId': 'test_client_id', "
        "'secret': 'test_secret', 'id': "
        "'00000000-0000-0000-0000-000000000000'}"
    )

    protocol = "openid-connect"
    config = {
        "access.token.claim": "true",
        "access.tokenResponse.claim": "false",
        "claim.name": "test_mapper",
        "claim.value": "any_value",
        "id.token.claim": "false",
        "userinfo.token.claim": "false"
    }
    name = "Test mapper"
    protocol_mapper = "oidc-hardcoded-claim-mapper"

    assert _keycloak_api_client_factory().create_mapper_for_client(
        name=name,
        protocol=protocol,
        config=config,
        protocol_mapper=protocol_mapper,
        id_of_client=id_of_client
    ) is None

    with pytest.raises(KeycloakApiClientException) as ex:
        _keycloak_api_client_factory().create_mapper_for_client(
            name=name,
            protocol=protocol,
            config=config,
            protocol_mapper=protocol_mapper,
            id_of_client=wrong_id_of_client
        )

    assert str(ex.value) == (
        "Error while creating client mapper with "
        "data={'protocol': 'openid-connect', "
        "'config': {'access.token.claim': 'true', "
        "'access.tokenResponse.claim': "
        "'false', 'claim.name': 'test_mapper', "
        "'claim.value': 'any_value', "
        "'id.token.claim': 'false', "
        "'userinfo.token.claim': 'false'}, "
        "'name': 'Test "
        "mapper', 'protocolMapper': "
        "'oidc-hardcoded-claim-mapper'}"
    )


@pytest.mark.vcr()
def test_search_clients_by_client_id():
    existing_client_id = "existing_client_id"
    non_existing_client_id = "not_existing_client_id"
    keycloak_api_client = _keycloak_api_client_factory()
    assert keycloak_api_client.search_clients_by_client_id(
        client_id=existing_client_id
    ) == [
        KeycloakClient(
            keycloak_id=UUID(raw_existing_client_data["id"]),
            client_id=raw_existing_client_data["clientId"],
            enabled=raw_existing_client_data["enabled"],
            service_account_enabled=(
                raw_existing_client_data["serviceAccountsEnabled"]
            )
        )
    ]
    assert keycloak_api_client.search_clients_by_client_id(
        client_id=non_existing_client_id
    ) == []


@pytest.mark.vcr()
def test_delete_client():
    keycloak_api_client = _keycloak_api_client_factory()

    with pytest.raises(KeycloakApiClientException) as ex:
        keycloak_api_client.delete_client(
            id_of_client=UUID("00000000-0000-0000-0000-000000000000")
        )

    assert str(ex.value) == (
        "Error while deleting client with "
        "ID=00000000-0000-0000-0000-000000000000) "
        "response code=404"
    )

    keycloak_api_client.delete_client(
        id_of_client=raw_existing_client_data['id']
    )
