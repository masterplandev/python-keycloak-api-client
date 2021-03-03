from uuid import UUID

from keycloak_api_client.factories import read_keycloak_user_factory


def test_create_user_from_keycloak_data():
    data = {
        'id': '3f169eaa-8405-46e0-b106-e4f1823331e1',
        'createdTimestamp': 1590563321150,
        'username': 'any@test.com',
        'enabled': True,
        'totp': False,
        'emailVerified': True,
        'firstName': 'name',
        'lastName': 'surname',
        'email': 'any@test.com',
        'attributes': {
            'legacy_user_id': ['281eecba-da9f-4806-835d-59eb06856f32'],
            'company_id': ['f4be2d0f-af90-07b0-44b9-05629d2cb8de'],
            'phone': ['111222333'],
            'date_of_birth': ['2000-11-13'],
            'title': ['mr'],
            'job_title': ['job_title']
        },
        'disableableCredentialTypes': [],
        'requiredActions': [],
        'notBefore': 0,
        'access': {
            'manageGroupMembership': True,
            'view': True,
            'mapRoles': True,
            'impersonate': True,
            'manage': True
        }
    }

    keycloak_user = read_keycloak_user_factory(user_endpoint_data=data)

    assert keycloak_user.keycloak_id == \
           UUID('3f169eaa-8405-46e0-b106-e4f1823331e1')
    assert keycloak_user.username == 'any@test.com'
    assert keycloak_user.first_name == 'name'
    assert keycloak_user.last_name == 'surname'
    assert keycloak_user.email == 'any@test.com'
    assert keycloak_user.enabled
    assert keycloak_user.email_verified
    assert keycloak_user.raw_data == data
