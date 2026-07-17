import logging
from collections.abc import Callable
from functools import lru_cache
from typing import cast

from fastapi import Depends, Header, Request

from agent.application.authentication import (
    AuthenticatedPrincipal,
    AuthenticationRequiredError,
    ApiKeyAuthenticationService,
    local_development_principal,
)
from agent.application.oidc_authentication import OidcJwtAuthenticationService
from agent.persistence.unit_of_work import UnitOfWork
from agent.persistence.database import create_engine_factory, create_session_factory
from agent.config import Settings, get_settings
from agent.opensearch.client import OpenSearchClientFactory
from agent.opensearch.manager import OpenSearchHealthService
from agent.api.rate_limiting import (
    remember_rate_limit_decision,
    route_identifier,
)
from agent.api.security import trusted_client_address
from agent.security.abuse_protection import (
    RateLimitCategory,
    RateLimitManager,
)
from agent.security.authorization import (
    AuthorizationDeniedError,
    Permission,
    has_permission,
)
from agent.security.oidc import (
    HttpxOidcHttpClient,
    OidcConfiguration,
    OidcMetadataProvider,
    OidcSigningKeyResolver,
)

logger = logging.getLogger(__name__)

# Global engine/session factory for FastAPI
settings = get_settings()
engine = create_engine_factory(settings)
session_factory = create_session_factory(engine)

def get_uow() -> UnitOfWork:
    return UnitOfWork(session_factory)

def get_staging_store():
    from agent.application.staging import LocalFileStagingStore
    return LocalFileStagingStore(
        staging_dir=settings.staging_dir,
        max_size_bytes=settings.max_upload_bytes,
    )

def get_dispatcher():
    from agent.queue.dispatchers import DatabasePollingDispatcher, CeleryAnalysisJobDispatcher
    if settings.task_queue_backend == "celery":
        return CeleryAnalysisJobDispatcher()
    return DatabasePollingDispatcher()


def get_rate_limit_manager(request: Request) -> RateLimitManager:
    return request.app.state.rate_limit_manager


def get_opensearch_health_service(
    opensearch_settings: Settings = Depends(get_settings),
) -> OpenSearchHealthService:
    factory = OpenSearchClientFactory(opensearch_settings)
    return OpenSearchHealthService(opensearch_settings, factory.create)


@lru_cache(maxsize=8)
def _get_cached_oidc_authentication_service(
    configuration: OidcConfiguration,
) -> OidcJwtAuthenticationService:
    http_client = HttpxOidcHttpClient()
    metadata_provider = OidcMetadataProvider(configuration, http_client)
    signing_key_resolver = OidcSigningKeyResolver(
        configuration,
        metadata_provider,
        http_client,
    )
    return OidcJwtAuthenticationService(configuration, signing_key_resolver)


def get_optional_oidc_authentication_service(
    auth_settings: Settings = Depends(get_settings),
) -> OidcJwtAuthenticationService | None:
    if auth_settings.auth_mode not in ("oidc", "hybrid"):
        return None
    configuration = OidcConfiguration.from_settings(auth_settings)
    return _get_cached_oidc_authentication_service(configuration)


def _is_jwt_shaped(credential: str) -> bool:
    parts = credential.split(".")
    return len(parts) == 3 and all(parts)


def get_authenticated_principal(
    request: Request = cast(Request, None),
    authorization: str | None = Header(default=None, alias="Authorization"),
    auth_settings: Settings = Depends(get_settings),
    uow: UnitOfWork = Depends(get_uow, use_cache=False),
    oidc_service: OidcJwtAuthenticationService | None = Depends(
        get_optional_oidc_authentication_service
    ),
    rate_limit_manager: RateLimitManager = Depends(get_rate_limit_manager),
) -> AuthenticatedPrincipal:
    if auth_settings.auth_mode == "disabled":
        return local_development_principal()

    try:
        if authorization is None:
            raise AuthenticationRequiredError()
        scheme, separator, credential = authorization.partition(" ")
        if (
            scheme.lower() != "bearer"
            or separator != " "
            or not credential
            or any(character.isspace() for character in credential)
        ):
            raise AuthenticationRequiredError()

        if auth_settings.auth_mode == "api_key":
            return ApiKeyAuthenticationService(uow).authenticate(credential)
        if auth_settings.auth_mode == "oidc":
            if oidc_service is None:
                raise AuthenticationRequiredError()
            return oidc_service.authenticate(credential)
        if auth_settings.auth_mode == "hybrid":
            if credential.startswith("soc_"):
                return ApiKeyAuthenticationService(uow).authenticate(
                    credential
                )
            if oidc_service is not None and _is_jwt_shaped(credential):
                return oidc_service.authenticate(credential)
        raise AuthenticationRequiredError()
    except AuthenticationRequiredError:
        decision = rate_limit_manager.enforce_anonymous(
            RateLimitCategory.AUTHENTICATION_FAILURE,
            client_address=trusted_client_address(
                request.scope,
                auth_settings,
            ),
            request_id=getattr(request.state, "request_id", None),
            route=route_identifier(request.scope),
        )
        remember_rate_limit_decision(request.scope, decision)
        raise


def require_permission(
    permission: Permission,
    *,
    rate_limit_category: RateLimitCategory | None = None,
) -> Callable[..., AuthenticatedPrincipal]:
    def permission_dependency(
        request: Request,
        principal: AuthenticatedPrincipal = Depends(get_authenticated_principal),
        rate_limit_manager: RateLimitManager = Depends(get_rate_limit_manager),
    ) -> AuthenticatedPrincipal:
        if rate_limit_category is not None:
            decision = rate_limit_manager.enforce_principal(
                rate_limit_category,
                principal=principal,
                request_id=getattr(request.state, "request_id", None),
                route=route_identifier(request.scope),
            )
            remember_rate_limit_decision(request.scope, decision)
        if has_permission(principal.roles, permission):
            return principal

        logger.warning(
            "authorization_denied",
            extra={
                "subject_id": principal.subject_id,
                "permission": permission.value,
                "request_id": getattr(request.state, "request_id", None),
            },
        )
        raise AuthorizationDeniedError()

    setattr(permission_dependency, "required_permission", permission)
    return permission_dependency
