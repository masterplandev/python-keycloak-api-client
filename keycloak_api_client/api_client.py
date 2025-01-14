from datetime import datetime, timedelta
import json
from http import HTTPStatus
from urllib import parse
from uuid import UUID

import requests

from keycloak_api_client.data_classes import (
    KeycloakClient,
    KeycloakFederatedIdentity,
    KeycloakTokens,
    WriteKeycloakUser,
    ReadKeycloakUser,
)
from keycloak_api_client.exceptions import KeycloakApiClientException
from keycloak_api_client.factories import (
    keycloak_client_factory,
    read_keycloak_user_factory,
)


class KeycloakApiClient:
    _keycloak_url: str
    _realm: str
    _admin_username: str
    _admin_password: str
    _admin_client_id: str
    _admin_client_secret: str
    _relative_path: str | None
    _admin_user_token_expiration_time: int

    _admin_user_access_token: str | None = None
    _admin_user_token_acquire_time: datetime | None = None

    def __init__(
        self,
        keycloak_url: str,
        realm: str,
        admin_username: str,
        admin_password: str,
        admin_client_id: str,
        admin_client_secret: str,
        relative_path: str | None,
        admin_user_token_expiration_time: int = 60,
    ):
        self._keycloak_url = keycloak_url
        self._realm = realm
        self._admin_username = admin_username
        self._admin_password = admin_password
        self._admin_client_id = admin_client_id
        self._admin_client_secret = admin_client_secret
        self._relative_path = relative_path
        self._admin_user_token_expiration_time = admin_user_token_expiration_time

    def _get_base_url(self) -> str:
        if self._relative_path:
            return f"{self._keycloak_url}{self._relative_path}"
        return f"{self._keycloak_url}"

    def _get_token_url(self) -> str:
        return (
            f"{self._get_base_url()}/realms/{self._realm}/protocol/openid-connect/token"
        )

    def _get_users_url(self) -> str:
        return f"{self._get_base_url()}/admin/realms/{self._realm}/users"

    def _get_user_url(self, user_id: UUID) -> str:
        return f"{self._get_users_url()}/{user_id}"

    def _get_identities_url(self, user_id: UUID) -> str:
        return f"{self._get_users_url()}/{user_id}/federated-identity"

    def _get_users_count_url(self) -> str:
        return f"{self._get_users_url()}/count"

    def _get_user_password_reset_url(self, user_id: UUID) -> str:
        return f"{self._get_users_url()}/{user_id}/reset-password"

    def _get_send_verify_email_url(self, user_id: UUID) -> str:
        return f"{self._get_users_url()}/{user_id}/send-verify-email"

    def _get_clients_url(self) -> str:
        return f"{self._get_base_url()}/admin/realms/{self._realm}/clients"

    def _get_client_url(self, id_of_client: UUID) -> str:
        return f"{self._get_clients_url()}/{id_of_client}"

    def _get_client_mappers_url(self, id_of_client: UUID) -> str:
        return f"{self._get_clients_url()}/{id_of_client}/protocol-mappers/models"

    def _get_authorization_header(self) -> str:
        return "Bearer " + self._get_api_admin_oidc_token(
            client_id=self._admin_client_id, client_secret=self._admin_client_secret
        )

    def _clear_admin_user_access_token(self) -> None:
        self._admin_user_access_token = None

    def _is_admin_user_token_expired(self) -> bool:
        expiration_time = self._admin_user_token_acquire_time + timedelta(
            seconds=self._admin_user_token_expiration_time
        )
        return datetime.now() >= expiration_time

    def _get_api_admin_oidc_token(
        self, client_id: str, client_secret: str | None = None
    ) -> str:
        if self._admin_user_access_token and not self._is_admin_user_token_expired():
            return self._admin_user_access_token

        data = {
            "grant_type": "password",
            "username": self._admin_username,
            "password": self._admin_password,
            "client_id": client_id,
        }

        if client_secret:
            data["client_secret"] = client_secret

        response = requests.post(
            self._get_token_url(),
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if not response.ok:
            raise KeycloakApiClientException(
                f"Error while obtaining api-admin access_token (msg: {response.json()})"
            )

        self._admin_user_access_token = response.json()["access_token"]
        self._admin_user_token_acquire_time = datetime.now()
        return self._admin_user_access_token

    def _get_user_identities(self, keycloak_id: UUID) -> list[dict[str, str]]:
        response = requests.get(
            self._get_identities_url(user_id=keycloak_id),
            headers={"Authorization": self._get_authorization_header()},
        )

        if not response.ok:
            raise KeycloakApiClientException(
                "Error while retrieving identities of user "
                f"{keycloak_id} (msg: {response.json()})"
            )

        return response.json()

    def _update_user_identities(
        self, keycloak_id: UUID, federated_identities: list[KeycloakFederatedIdentity]
    ):
        keycloak_identities = {
            i["identityProvider"]: i for i in self._get_user_identities(keycloak_id)
        }
        for identity in federated_identities:
            if identity.provider_name in keycloak_identities:
                response = requests.post(
                    f"{self._get_identities_url(user_id=keycloak_id)}/"
                    f"{identity.provider_name}",
                    data=json.dumps(
                        {
                            "identityProvider": identity.provider_name,
                            "userId": identity.user_id,
                            "userName": identity.user_name,
                        }
                    ),
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": self._get_authorization_header(),
                    },
                )

                if not response.ok:
                    raise KeycloakApiClientException(
                        "Error while creating identity for user "
                        f"{keycloak_id} (msg: {response.json()})"
                    )

    def _get_user_endpoint_schema_data(
        self, write_keycloak_user: WriteKeycloakUser
    ) -> dict[str, str]:
        data = {
            "username": write_keycloak_user.username,
            "firstName": write_keycloak_user.first_name,
            "lastName": write_keycloak_user.last_name,
            "email": write_keycloak_user.email,
            "enabled": write_keycloak_user.enabled,
            "emailVerified": write_keycloak_user.email_verified,
            "attributes": write_keycloak_user.attributes,
        }

        if write_keycloak_user.raw_password:
            data["credentials"] = [
                {
                    "type": "password",
                    "value": write_keycloak_user.raw_password,
                    "temporary": False,
                }
            ]
        elif write_keycloak_user.hashed_password:
            data["credentials"] = [
                {
                    "hashedSaltedValue": write_keycloak_user.hashed_password,
                    "algorithm": "bcrypt",
                    "hashIterations": 12,
                    "type": "password",
                    "temporary": False,
                }
            ]

        return data

    def get_keycloak_user_by_id(
        self, keycloak_id: UUID | None = None
    ) -> ReadKeycloakUser | None:
        response = requests.get(
            f"{self._get_users_url()}/{keycloak_id}",
            headers={"Authorization": self._get_authorization_header()},
        )

        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        if not response.ok:
            raise KeycloakApiClientException(
                f"Error while retrieving user with id {keycloak_id} "
                f"(msg: {response.json()})"
            )

        if not response.json():
            return None

        return read_keycloak_user_factory(user_endpoint_data=response.json())

    def get_keycloak_user_by_email(
        self,
        email: str | None = None,
    ) -> ReadKeycloakUser | None:
        response = requests.get(
            f"{self._get_users_url()}?email={parse.quote(email)}",
            headers={"Authorization": self._get_authorization_header()},
        )

        if not response.ok:
            raise KeycloakApiClientException(
                f"Error while retrieving user with email {email} "
                f"(msg: {response.json()})"
            )

        if len(response.json()) == 0:
            return None

        try:
            return read_keycloak_user_factory(
                user_endpoint_data=next(
                    user for user in response.json() if user["email"] == email
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
                "Content-Type": "application/json",
                "Authorization": self._get_authorization_header(),
            },
        )

        if not response.ok:
            raise KeycloakApiClientException(
                f"Error while creating user (msg: {response.json()})"
            )

        keycloak_id = response.headers["Location"].split("/")[-1]

        if write_keycloak_user.federated_identities:
            self._update_user_identities(
                keycloak_id=UUID(keycloak_id),
                federated_identities=write_keycloak_user.federated_identities,
            )

        return UUID(keycloak_id)

    def update_user(self, write_keycloak_user: WriteKeycloakUser):
        response = requests.put(
            f"{self._get_users_url()}/{write_keycloak_user.keycloak_id}",
            data=json.dumps(
                self._get_user_endpoint_schema_data(
                    write_keycloak_user=write_keycloak_user
                )
            ),
            headers={
                "Content-Type": "application/json",
                "Authorization": self._get_authorization_header(),
            },
        )

        if not response.ok:
            raise KeycloakApiClientException(
                f"Error while updating user (msg: {response.json()})"
            )

        if write_keycloak_user.federated_identities:
            self._update_user_identities(
                keycloak_id=write_keycloak_user.keycloak_id,
                federated_identities=write_keycloak_user.federated_identities,
            )

    def get_user_tokens(
        self,
        keycloak_id: UUID,
        starting_client_id: str,
        target_client_id: str,
        starting_client_secret: str | None = None,
    ) -> KeycloakTokens:
        self._clear_admin_user_access_token()

        data = {
            "audience": target_client_id,
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "requested_subject": str(keycloak_id),
            "subject_token": self._get_api_admin_oidc_token(
                client_id=starting_client_id, client_secret=starting_client_secret
            ),
            "client_id": starting_client_id,
        }

        if starting_client_secret:
            data["client_secret"] = starting_client_secret

        response = requests.post(
            self._get_token_url(),
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if not response.ok:
            raise KeycloakApiClientException(
                "Error while obtaining user tokens "
                f"{keycloak_id} (msg: {response.json()})"
            )

        data = response.json()

        return KeycloakTokens(
            access_token=data["access_token"], refresh_token=data["refresh_token"]
        )

    def search_users(
        self, query: str, limit: int = 100, offset: int = 0
    ) -> list[ReadKeycloakUser]:
        response = requests.get(
            self._get_users_url(),
            params={"search": query, "max": limit, "first": offset},
            headers={"Authorization": self._get_authorization_header()},
        )

        if not response.ok:
            raise KeycloakApiClientException(
                f"Error while retrieving users with query {query} "
                f"(msg: {response.json()})"
            )

        return [
            read_keycloak_user_factory(user_endpoint_data=user_data)
            for user_data in response.json()
        ]

    def count_users(self, query: str | None = None) -> list[ReadKeycloakUser]:
        params = {"search": query} if query else None
        response = requests.get(
            self._get_users_count_url(),
            params=params,
            headers={"Authorization": self._get_authorization_header()},
        )
        if not response.ok:
            raise KeycloakApiClientException(
                f"Error while retrieving users count "
                f"{'with query' + query if query else None}"
                f"(msg: {response.json()})"
            )
        return response.json()

    def reset_password(
        self, keycloak_id: UUID, new_password: str, temporary: bool = False
    ) -> None:
        data = {"type": "password", "temporary": temporary, "value": new_password}
        response = requests.put(
            url=self._get_user_password_reset_url(user_id=keycloak_id),
            json=data,
            headers={"Authorization": self._get_authorization_header()},
        )
        if not response.ok:
            raise KeycloakApiClientException(
                f"Error while resetting password for "
                f"user with ID {keycloak_id}"
                f"(msg: {response.json()})"
            )

    def send_verification_email(
        self,
        keycloak_id: UUID,
        client_id: str | None = None,
        redirect_uri: str | None = None,
    ) -> None:
        """
        Send an email-verification email to the user. An email contains a link
        the user can click to verify their email address.
        """

        params = {
            "client_id": client_id if client_id else None,
            "redirect_uri": redirect_uri if redirect_uri else None,
        }

        response = requests.put(
            self._get_send_verify_email_url(user_id=keycloak_id),
            headers={"Authorization": self._get_authorization_header()},
            params=params if params else None,
        )

        if not response.ok:
            raise KeycloakApiClientException(
                f"Error while sending a verification email for "
                f"user with ID {keycloak_id} (msg: {response.json()})"
            )

    def create_client(self, client_id: str, client_secret: str, **kwargs) -> None:
        """
        Creates new client with passed client_id and client_secret.
        Pass additional data to attach it to request payload.
        """

        data = {"clientId": client_id, "secret": client_secret, **kwargs}

        response = requests.post(
            self._get_clients_url(),
            data=json.dumps(data),
            headers={
                "Authorization": self._get_authorization_header(),
                "Content-Type": "application/json",
            },
        )
        if not response.ok:
            raise KeycloakApiClientException(
                f"Error while creating new client with data={data}"
            )

    def create_mapper_for_client(
        self,
        name: str,
        id_of_client: UUID,
        protocol: str,
        protocol_mapper: str,
        config: dict[str, str],
    ) -> None:
        """
        Creates new mapper for client.
        """
        data = {
            "protocol": protocol,
            "config": config,
            "name": name,
            "protocolMapper": protocol_mapper,
        }

        response = requests.post(
            self._get_client_mappers_url(id_of_client=id_of_client),
            data=json.dumps(data),
            headers={
                "Authorization": self._get_authorization_header(),
                "Content-Type": "application/json",
            },
        )
        if not response.ok:
            raise KeycloakApiClientException(
                f"Error while creating client mapper with data={data}"
            )

    def search_clients_by_client_id(self, client_id: str) -> list[KeycloakClient]:
        response = requests.get(
            self._get_clients_url(),
            params={"clientId": client_id, "search": True},
            headers={"Authorization": self._get_authorization_header()},
        )
        if not response.ok:
            raise KeycloakApiClientException(
                "Error while retrieving client data by clientId "
                f"(clientId: {client_id})"
            )
        return [keycloak_client_factory(client) for client in response.json()]

    def delete_client(self, id_of_client: UUID) -> None:
        response = requests.delete(
            self._get_client_url(id_of_client=id_of_client),
            headers={"Authorization": self._get_authorization_header()},
        )
        if not response.ok:
            raise KeycloakApiClientException(
                "Error while deleting client "
                f"with ID={id_of_client}) "
                f"response code={response.status_code}"
            )

    def delete_user(self, user_id: UUID) -> None:
        response = requests.delete(
            url=self._get_user_url(user_id=user_id),
            headers={"Authorization": self._get_authorization_header()},
        )
        if not response.ok:
            raise KeycloakApiClientException(
                "Error while deleting user "
                f"with ID={user_id}) "
                f"response code={response.status_code}"
            )
