import json
from http import HTTPStatus
from typing import List, Optional
from urllib import parse
from uuid import UUID

import requests

from keycloak_api_client.data_classes import (
    KeycloakFederatedIdentity,
    KeycloakTokens,
    WriteKeycloakUser,
    ReadKeycloakUser
)
from keycloak_api_client.exceptions import KeycloakApiClientException
from keycloak_api_client.factories import read_keycloak_user_factory


class KeycloakApiClient:

    admin_user_access_token = None

    def __init__(
        self,
        keycloak_url: str,
        realm: str,
        admin_username: str,
        admin_password: str,
        admin_client_id: str,
        admin_client_secret: str,
        token_exchange_target_client_id: str,
    ):
        self.keycloak_url = keycloak_url
        self.realm = realm
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.admin_client_id = admin_client_id
        self.admin_client_secret = admin_client_secret
        self.token_exchange_target_client_id = token_exchange_target_client_id

    def _get_token_url(self) -> str:
        return f'{self.keycloak_url}/auth/realms/{self.realm}'\
               '/protocol/openid-connect/token'

    def _get_users_url(self) -> str:
        return f'{self.keycloak_url}/auth/admin/realms/{self.realm}/users'

    def _get_identities_url(self, user_id: UUID) -> str:
        return f'{self._get_users_url()}/{user_id}/federated-identity'

    def _get_users_count_url(self) -> str:
        return f'{self._get_users_url()}/count'

    def _get_user_password_reset_url(self, user_id: UUID) -> str:
        return f'{self._get_users_url()}/{user_id}/reset-password'

    def _get_authorization_header(self) -> str:
        return f'Bearer {self._get_api_admin_oidc_token()}'

    def _get_api_admin_oidc_token(self) -> str:
        if self.admin_user_access_token:
            return self.admin_user_access_token

        response = requests.post(
            self._get_token_url(),
            data={
                'grant_type': 'password',
                'username': self.admin_username,
                'password': self.admin_password,
                'client_id': self.admin_client_id,
                'client_secret': self.admin_client_secret
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

        if not response.ok:
            raise KeycloakApiClientException(
                'Error while obtaining api-admin access_token '
                f'(msg: {response.json()})'
            )

        self.admin_user_access_token = response.json()['access_token']

        return self.admin_user_access_token

    def _get_user_identities(self, keycloak_id: UUID) -> List[dict]:
        response = requests.get(
            self._get_identities_url(user_id=keycloak_id),
            headers={'Authorization': self._get_authorization_header()}
        )

        if not response.ok:
            raise KeycloakApiClientException(
                'Error while retrieving identities of user '
                f'{keycloak_id} (msg: {response.json()})'
            )

        return response.json()

    def _update_user_identities(
        self,
        keycloak_id: UUID,
        federated_identities: List[KeycloakFederatedIdentity]
    ):
        keycloak_identities = {
            i['identityProvider']: i
            for i in self._get_user_identities(keycloak_id)
        }
        for identity in federated_identities:
            if identity.provider_name in keycloak_identities:
                response = requests.post(
                    f'{self._get_identities_url(user_id=keycloak_id)}/'
                    f'{identity.provider_name}',
                    data=json.dumps({
                        'identityProvider': identity.provider_name,
                        'userId': identity.user_id,
                        'userName': identity.user_name,
                    }),
                    headers={
                        'Content-Type': 'application/json',
                        'Authorization': self._get_authorization_header(),
                    }
                )

                if not response.ok:
                    raise KeycloakApiClientException(
                        'Error while creating identity for user '
                        f'{keycloak_id} (msg: {response.json()})'
                    )

    def _get_user_endpoint_schema_data(
        self,
        write_keycloak_user: WriteKeycloakUser
    ) -> dict:
        data = {
            'username': write_keycloak_user.username,
            'firstName': write_keycloak_user.first_name,
            'lastName': write_keycloak_user.last_name,
            'email': write_keycloak_user.email,
            'enabled': write_keycloak_user.enabled,
            'emailVerified': write_keycloak_user.email_verified,
            'attributes': write_keycloak_user.attributes,
        }

        if write_keycloak_user.raw_password:
            data['credentials'] = [{
                'type': 'password',
                'value': write_keycloak_user.raw_password,
                'temporary': False
            }]
        elif write_keycloak_user.hashed_password:
            data['credentials'] = [{
                'hashedSaltedValue': write_keycloak_user.hashed_password,
                'algorithm': 'bcrypt',
                'hashIterations': 12,
                'type': 'password',
                'temporary': False
            }]

        return data

    def get_keycloak_user_by_id(
        self,
        keycloak_id: Optional[UUID] = None
    ) -> Optional[ReadKeycloakUser]:
        response = requests.get(
            f'{self._get_users_url()}/{keycloak_id}',
            headers={'Authorization': self._get_authorization_header()}
        )

        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        if not response.ok:
            raise KeycloakApiClientException(
                f'Error while retrieving user with id {keycloak_id} '
                f'(msg: {response.json()})'
            )

        if not response.json():
            return None

        return read_keycloak_user_factory(user_endpoint_data=response.json())

    def get_keycloak_user_by_email(
        self,
        email: Optional[str] = None,
    ) -> Optional[ReadKeycloakUser]:
        response = requests.get(
            f'{self._get_users_url()}?email={parse.quote(email)}',
            headers={'Authorization': self._get_authorization_header()}
        )

        if not response.ok:
            raise KeycloakApiClientException(
                f'Error while retrieving user with email {email} '
                f'(msg: {response.json()})'
            )

        if len(response.json()) == 0:
            return None

        try:
            return read_keycloak_user_factory(
                user_endpoint_data=next(
                    user for user in response.json()
                    if user['email'] == email
                )
            )
        except StopIteration:
            return None

    def register_user(self, write_keycloak_user: WriteKeycloakUser) -> UUID:
        response = requests.post(
            self._get_users_url(),
            data=json.dumps(
                self._get_user_endpoint_schema_data(
                    write_keycloak_user=write_keycloak_user
                )
            ),
            headers={
                'Content-Type': 'application/json',
                'Authorization': self._get_authorization_header(),
            }
        )

        if not response.ok:
            raise KeycloakApiClientException(
                f'Error while creating user (msg: {response.json()})'
            )

        keycloak_id = response.headers['Location'].split('/')[-1]

        if write_keycloak_user.federated_identities:
            self._update_user_identities(
                keycloak_id=UUID(keycloak_id),
                federated_identities=write_keycloak_user.federated_identities
            )

        return UUID(keycloak_id)

    def update_user(self, write_keycloak_user: WriteKeycloakUser):
        response = requests.put(
            f'{self._get_users_url()}/{write_keycloak_user.keycloak_id}',
            data=json.dumps(
                self._get_user_endpoint_schema_data(
                    write_keycloak_user=write_keycloak_user
                )
            ),
            headers={
                'Content-Type': 'application/json',
                'Authorization': self._get_authorization_header(),
            }
        )

        if not response.ok:
            raise KeycloakApiClientException(
                f'Error while updating user (msg: {response.json()})'
            )

        if write_keycloak_user.federated_identities:
            self._update_user_identities(
                keycloak_id=write_keycloak_user.keycloak_id,
                federated_identities=write_keycloak_user.federated_identities
            )

    def get_user_tokens(self, keycloak_id: UUID) -> KeycloakTokens:
        response = requests.post(
            self._get_token_url(),
            data={
                'audience': self.token_exchange_target_client_id,
                'grant_type': 'urn:ietf:params:oauth:grant-type'
                              ':token-exchange',
                'requested_subject': str(keycloak_id),
                'subject_token': self._get_api_admin_oidc_token(),
                'client_id': self.token_exchange_target_client_id,
                'client_secret': self.admin_client_secret,
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

        if not response.ok:
            raise KeycloakApiClientException(
                'Error while obtaining user tokens '
                f'{keycloak_id} (msg: {response.json()})'
            )

        data = response.json()

        return KeycloakTokens(
            access_token=data['access_token'],
            refresh_token=data['refresh_token']
        )

    def search_users(
        self, query: str, limit: int = 100, offset: int = 0
    ) -> List[ReadKeycloakUser]:
        response = requests.get(
            self._get_users_url(),
            params={'search': query, 'max': limit, 'first': offset},
            headers={'Authorization': self._get_authorization_header()}
        )

        if not response.ok:
            raise KeycloakApiClientException(
                f'Error while retrieving users with query {query} '
                f'(msg: {response.json()})'
            )

        return [
            read_keycloak_user_factory(user_endpoint_data=user_data)
            for user_data in response.json()
        ]

    def count_users(
        self,
        query: Optional[str] = None
    ) -> List[ReadKeycloakUser]:
        params = {"search": query} if query else None
        response = requests.get(
            self._get_users_count_url(),
            params=params,
            headers={"Authorization": self._get_authorization_header()}
        )
        if not response.ok:
            raise KeycloakApiClientException(
                f"Error while retrieving users count "
                f"{'with query' + query if query else None}"
                f"(msg: {response.json()})"
            )
        return response.json()

    def reset_password(
        self,
        keycloak_id: UUID,
        new_password: str,
        temporary: bool = False
    ) -> None:
        data = {
            "type": "password",
            "temporary": temporary,
            "value": new_password
        }
        response = requests.put(
            url=self._get_user_password_reset_url(user_id=keycloak_id),
            json=data,
            headers={"Authorization": self._get_authorization_header()}
        )
        if not response.ok:
            raise KeycloakApiClientException(
                f"Error while resetting password for "
                f"user with ID {keycloak_id}"
                f"(msg: {response.json()})"
            )
