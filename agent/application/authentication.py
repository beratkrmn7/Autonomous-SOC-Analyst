import datetime
import hashlib
import hmac
import logging
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import cast

from sqlalchemy import or_
from sqlalchemy.exc import SQLAlchemyError

from agent.persistence.orm_models import ApiCredential, AuditEvent
from agent.persistence.unit_of_work import UnitOfWork
from agent.security.authorization import Role

logger = logging.getLogger(__name__)

AUTHENTICATION_ERROR = {
    "code": "authentication_required",
    "message": "Valid authentication credentials are required.",
}
DEFAULT_SERVICE_ROLE = Role.SERVICE.value


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    subject_type: str
    subject_id: str
    display_name: str
    authentication_method: str
    roles: tuple[str, ...]
    credential_id: str | None


@dataclass(frozen=True)
class CredentialView:
    credential_id: str
    name: str
    key_prefix: str
    status: str
    role: str
    created_at: datetime.datetime
    expires_at: datetime.datetime | None
    last_used_at: datetime.datetime | None
    revoked_at: datetime.datetime | None
    description: str | None
    version: int


@dataclass(frozen=True)
class GeneratedCredential:
    credential: CredentialView
    api_key: str


class AuthenticationRequiredError(Exception):
    def __init__(self) -> None:
        super().__init__(AUTHENTICATION_ERROR["code"])


class CredentialNotFoundError(Exception):
    pass


def local_development_principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        subject_type="local_development",
        subject_id="local-development",
        display_name="Local development (authentication disabled)",
        authentication_method="disabled",
        roles=(Role.ADMIN.value,),
        credential_id=None,
    )


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _utc(value: datetime.datetime) -> datetime.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value.astimezone(datetime.timezone.utc)


def _credential_view(credential: ApiCredential) -> CredentialView:
    return CredentialView(
        credential_id=str(credential.credential_id),
        name=str(credential.name),
        key_prefix=str(credential.key_prefix),
        status=str(credential.status),
        role=str(credential.role),
        created_at=cast(datetime.datetime, credential.created_at),
        expires_at=cast(datetime.datetime | None, credential.expires_at),
        last_used_at=cast(datetime.datetime | None, credential.last_used_at),
        revoked_at=cast(datetime.datetime | None, credential.revoked_at),
        description=cast(str | None, credential.description),
        version=int(credential.version),
    )


def _extract_prefix(api_key: str) -> str | None:
    parts = api_key.split("_", 2)
    if len(parts) != 3 or parts[0] != "soc":
        return None
    prefix, secret = parts[1], parts[2]
    if not (8 <= len(prefix) <= 32 and prefix.isalnum()):
        return None
    if len(secret) < 32 or any(character.isspace() for character in secret):
        return None
    return prefix


class ApiKeyAuthenticationService:
    """Creates and validates high-entropy API credentials without storing secrets."""

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    @staticmethod
    def _add_audit_event(
        session,
        *,
        credential_id: str,
        event_type: str,
        actor_type: str,
        actor_id: str,
        timestamp: datetime.datetime,
        details: dict[str, str],
    ) -> None:
        existing = session.query(AuditEvent.id).filter(
            AuditEvent.event_type == event_type,
            AuditEvent.entity_type == "api_credential",
            AuditEvent.entity_id == credential_id,
        ).first()
        if existing:
            return
        session.add(AuditEvent(
            audit_event_id=f"ae_{uuid.uuid4().hex}",
            timestamp=timestamp,
            event_type=event_type,
            entity_type="api_credential",
            entity_id=credential_id,
            action=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            actor=actor_type,
            details=details,
        ))

    def generate_credential(
        self,
        *,
        name: str,
        description: str | None = None,
        expires_at: datetime.datetime | None = None,
        role: Role | str = Role.SERVICE,
        created_by_type: str = "admin_cli",
        created_by_id: str = "local_administrator",
    ) -> GeneratedCredential:
        name = name.strip()
        if not name or len(name) > 120:
            raise ValueError("credential_name_invalid")
        if description is not None and len(description) > 500:
            raise ValueError("credential_description_invalid")
        if expires_at is not None:
            expires_at = _utc(expires_at)
        try:
            persisted_role = Role(role).value
        except ValueError:
            raise ValueError("credential_role_invalid") from None

        now = datetime.datetime.now(datetime.timezone.utc)
        credential_id = f"cred_{uuid.uuid4().hex}"
        with self.uow:
            assert self.uow.session is not None
            for _ in range(5):
                key_prefix = secrets.token_hex(6)
                if not self.uow.api_credentials.get_by_prefix(key_prefix):
                    break
            else:
                raise RuntimeError("credential_generation_failed")

            api_key = f"soc_{key_prefix}_{secrets.token_urlsafe(32)}"
            credential = ApiCredential(
                credential_id=credential_id,
                name=name,
                key_prefix=key_prefix,
                key_hash=hash_api_key(api_key),
                status="active",
                role=persisted_role,
                created_at=now,
                expires_at=expires_at,
                last_used_at=None,
                revoked_at=None,
                created_by_type=created_by_type,
                created_by_id=created_by_id,
                description=description,
                version=1,
            )
            self.uow.api_credentials.add(credential)
            self._add_audit_event(
                self.uow.session,
                credential_id=credential_id,
                event_type="api_credential_created",
                actor_type=created_by_type,
                actor_id=created_by_id,
                timestamp=now,
                details={
                    "name": name,
                    "key_prefix": key_prefix,
                    "role": persisted_role,
                },
            )
            view = _credential_view(credential)
        return GeneratedCredential(credential=view, api_key=api_key)

    def authenticate(self, api_key: str) -> AuthenticatedPrincipal:
        key_prefix = _extract_prefix(api_key)
        presented_hash = hash_api_key(api_key)
        now = datetime.datetime.now(datetime.timezone.utc)
        principal: AuthenticatedPrincipal | None = None
        failure_category = "authentication_failed"

        try:
            with self.uow:
                assert self.uow.session is not None
                candidates = (
                    self.uow.api_credentials.get_by_prefix(key_prefix)
                    if key_prefix is not None
                    else []
                )
                matched: ApiCredential | None = None
                comparison_hashes: list[ApiCredential | None] = (
                    list(candidates) if candidates else [None]
                )
                for candidate in comparison_hashes:
                    stored_hash = (
                        str(candidate.key_hash) if candidate is not None else "0" * 64
                    )
                    if hmac.compare_digest(stored_hash, presented_hash):
                        matched = candidate

                if matched is None:
                    failure_category = "authentication_failed"
                elif str(matched.status) == "revoked":
                    failure_category = "credential_revoked"
                elif str(matched.status) == "expired":
                    failure_category = "credential_expired"
                elif str(matched.status) != "active":
                    failure_category = "authentication_failed"
                elif str(matched.role) not in {role.value for role in Role}:
                    failure_category = "authentication_failed"
                elif matched.expires_at is not None and _utc(
                    cast(datetime.datetime, matched.expires_at)
                ) <= now:
                    updated = self.uow.session.query(ApiCredential).filter(
                        ApiCredential.credential_id == matched.credential_id,
                        ApiCredential.status == "active",
                        ApiCredential.version == matched.version,
                    ).update({
                        "status": "expired",
                        "version": ApiCredential.version + 1,
                    }, synchronize_session=False)
                    failure_category = (
                        "credential_expired" if updated else "authentication_failed"
                    )
                else:
                    updated = self.uow.session.query(ApiCredential).filter(
                        ApiCredential.credential_id == matched.credential_id,
                        ApiCredential.status == "active",
                        or_(
                            ApiCredential.expires_at.is_(None),
                            ApiCredential.expires_at > now,
                        ),
                    ).update({
                        "last_used_at": now,
                        "version": ApiCredential.version + 1,
                    }, synchronize_session=False)
                    if updated:
                        principal = AuthenticatedPrincipal(
                            subject_type="api_client",
                            subject_id=str(matched.credential_id),
                            display_name=str(matched.name),
                            authentication_method="api_key",
                            roles=(Role(str(matched.role)).value,),
                            credential_id=str(matched.credential_id),
                        )
                    else:
                        failure_category = "authentication_failed"
        except SQLAlchemyError:
            logger.warning("authentication_failed")
            raise AuthenticationRequiredError() from None

        if principal is None:
            logger.warning(failure_category)
            raise AuthenticationRequiredError()
        return principal

    def revoke_credential(
        self,
        credential_id: str,
        *,
        actor_type: str = "admin_cli",
        actor_id: str = "local_administrator",
    ) -> CredentialView:
        for attempt in range(3):
            try:
                return self._revoke_credential_once(
                    credential_id,
                    actor_type=actor_type,
                    actor_id=actor_id,
                )
            except SQLAlchemyError:
                if attempt == 2:
                    raise RuntimeError("credential_operation_failed") from None
                time.sleep(0.01 * (attempt + 1))
        raise RuntimeError("credential_operation_failed")

    def _revoke_credential_once(
        self,
        credential_id: str,
        *,
        actor_type: str,
        actor_id: str,
    ) -> CredentialView:
        now = datetime.datetime.now(datetime.timezone.utc)
        with self.uow:
            assert self.uow.session is not None
            for _ in range(3):
                credential = self.uow.api_credentials.get(credential_id)
                if credential is None:
                    raise CredentialNotFoundError(credential_id)
                if str(credential.status) == "revoked":
                    return _credential_view(credential)

                updated = self.uow.session.query(ApiCredential).filter(
                    ApiCredential.credential_id == credential_id,
                    ApiCredential.status != "revoked",
                    ApiCredential.version == credential.version,
                ).update({
                    "status": "revoked",
                    "revoked_at": now,
                    "version": ApiCredential.version + 1,
                }, synchronize_session=False)
                if updated:
                    break
                self.uow.session.rollback()
                self.uow.session.expire_all()
            else:
                raise RuntimeError("credential_version_conflict")

            self._add_audit_event(
                self.uow.session,
                credential_id=credential_id,
                event_type="api_credential_revoked",
                actor_type=actor_type,
                actor_id=actor_id,
                timestamp=now,
                details={"credential_id": credential_id},
            )
            self.uow.session.expire_all()
            revoked = self.uow.api_credentials.get(credential_id)
            assert revoked is not None
            return _credential_view(revoked)

    def list_credentials(self) -> list[CredentialView]:
        with self.uow:
            return [
                _credential_view(credential)
                for credential in self.uow.api_credentials.list_for_administration()
            ]
