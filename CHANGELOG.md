# Changelog

## v0.13.2

- Make `first_name` and `last_name` optional in `BaseKeycloakUser` as they can be `None`
- Fix issue: `first_name` and `last_name` of `BaseKeycloakUser` are no longer casted to string if they are `None`

## v0.13.1

- Add a check for the expiration of the admin user token

## v0.13.0

- Added CI badges
- Add general readme info

## v0.12.0

- Provided option for [relative path](https://www.keycloak.org/server/all-config?q=relative-path) configuration
- Adjusted scope of client private properties
- Provided extra consistency when casting responses to objects
- Deleted unused `token_exchange_target_client_id` attribute

## v0.11.0

- Dropped support for older Python versions (`3.7`, `3.8` and `3.9`)
- Adjusted typing for modern Python

## v0.10.1

- Fix failing tests due to `vcr` not being able to decode binary responses for Python>=3.9
- Delete some ALB related cookie leftovers
- Replace `flake` with `ruff`

## v0.10.0

- Dropped support for Python `3.6`
- Provided support for Python `<=3.12`

## v0.9.0

- Added `delete_user` method.

## v0.8.1

- Clear `admin_user_access_token` before using token-exchange feature.

## v0.8.0

- Allow to define starting `client_id` / `client_secret` when using token-exchange feature

## v0.7.1

- Change `client_id` value in `get_user_tokens`

## v0.7.0

- Added methods `search_clients_by_client_id` and `delete_client`
- Added `KeycloakClient` dataclass

## v0.6.0

- Added methods `create_client` and `create_mapper_for_client`

## v0.5.0

- Added method `send_verification_email`

## v0.4.0

- Added method `reset_password`

## v0.3.0

- Added method `count_users`

## v0.2.2

- Added `limit` and `offset` params in `KeycloakApiClient.search_users()` to control paging

## v0.2.1

- Fixed `StopIteration` when downloading user by email in case email partially matches found users but not exact match exact email

## v0.2.0

- Method `get_keycloak_user` was replaced by `get_keycloak_user_by_id` and `get_keycloak_user_by_email`

## v0.1.1

- Fixed typo

## v0.1.0

- Initial release
