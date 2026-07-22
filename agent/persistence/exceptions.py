class PersistenceError(Exception):
    pass

class RecordNotFoundError(PersistenceError):
    def __init__(self, model_name: str, id_val: str):
        super().__init__(f"{model_name} {id_val} not found", {"model_name": model_name, "id": id_val})

class InvalidEntityError(PersistenceError):
    pass


class CanonicalEventIdentityConflictError(PersistenceError):
    """An existing event ID points at incompatible immutable source facts."""

    def __init__(self, fields: list[str]):
        # Field names are a closed internal set. Never include event values,
        # raw records, excerpts, or parser metadata in this error.
        super().__init__(
            "canonical_event_identity_conflict:"
            + ",".join(sorted(set(fields)))
        )


class DetectionSignalIdentityConflictError(PersistenceError):
    """An existing signal ID belongs to a different rule contract."""

    def __init__(self, fields: list[str]):
        super().__init__(
            "detection_signal_identity_conflict:"
            + ",".join(sorted(set(fields)))
        )
