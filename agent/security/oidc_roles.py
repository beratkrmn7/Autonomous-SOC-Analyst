from collections.abc import Mapping
from typing import Any


MAX_EXTERNAL_ROLES = 100
MAX_EXTERNAL_ROLE_LENGTH = 128


class OidcRoleMapper:
    """Maps only explicitly trusted external role values to internal roles."""

    def __init__(
        self,
        roles_claim: str,
        role_mapping: tuple[tuple[str, str], ...],
    ):
        self.roles_claim = roles_claim
        self.role_mapping = dict(role_mapping)

    def map_claims(self, claims: Mapping[str, Any]) -> tuple[str, ...]:
        external_roles_value = claims.get(self.roles_claim, [])
        if isinstance(external_roles_value, str):
            external_roles = [external_roles_value]
        elif isinstance(external_roles_value, list) and all(
            isinstance(role, str) for role in external_roles_value
        ):
            external_roles = external_roles_value
        else:
            raise ValueError("jwt_roles_invalid")

        if len(external_roles) > MAX_EXTERNAL_ROLES or any(
            not role or len(role) > MAX_EXTERNAL_ROLE_LENGTH
            for role in external_roles
        ):
            raise ValueError("jwt_roles_invalid")

        mapped_roles: list[str] = []
        for external_role in external_roles:
            internal_role = self.role_mapping.get(external_role)
            if internal_role is not None and internal_role not in mapped_roles:
                mapped_roles.append(internal_role)
        return tuple(mapped_roles)
