from collections.abc import Iterable, Mapping
from enum import Enum
from types import MappingProxyType


class Role(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    SERVICE = "service"
    ADMIN = "admin"


class Permission(str, Enum):
    JOB_SUBMIT = "job.submit"
    JOB_READ = "job.read"
    JOB_CANCEL = "job.cancel"
    INCIDENT_READ = "incident.read"
    INCIDENT_STATUS_UPDATE = "incident.status.update"
    INCIDENT_AUDIT_READ = "incident.audit.read"
    REPORT_READ = "report.read"
    WORKER_READ = "worker.read"
    AUDIT_READ = "audit.read"


FORBIDDEN_ERROR = {
    "code": "forbidden",
    "message": "You do not have permission to perform this action.",
}


class AuthorizationDeniedError(Exception):
    def __init__(self) -> None:
        super().__init__(FORBIDDEN_ERROR["code"])


_VIEWER_PERMISSIONS = frozenset({
    Permission.JOB_READ,
    Permission.INCIDENT_READ,
    Permission.REPORT_READ,
})

ROLE_PERMISSIONS: Mapping[Role, frozenset[Permission]] = MappingProxyType({
    Role.VIEWER: _VIEWER_PERMISSIONS,
    Role.SERVICE: frozenset({
        Permission.JOB_SUBMIT,
        Permission.JOB_READ,
        Permission.INCIDENT_READ,
        Permission.REPORT_READ,
    }),
    Role.ANALYST: frozenset({
        Permission.JOB_SUBMIT,
        Permission.JOB_READ,
        Permission.JOB_CANCEL,
        Permission.INCIDENT_READ,
        Permission.INCIDENT_STATUS_UPDATE,
        Permission.INCIDENT_AUDIT_READ,
        Permission.REPORT_READ,
    }),
    Role.ADMIN: frozenset(Permission),
})


def permissions_for_roles(roles: Iterable[str]) -> frozenset[Permission]:
    permissions: set[Permission] = set()
    for role_name in roles:
        try:
            role = Role(role_name)
        except ValueError:
            continue
        permissions.update(ROLE_PERMISSIONS[role])
    return frozenset(permissions)


def has_permission(roles: Iterable[str], permission: Permission) -> bool:
    return permission in permissions_for_roles(roles)
