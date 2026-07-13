class ApplicationError(Exception):
    pass

class IncidentNotFoundError(ApplicationError):
    def __init__(self, incident_id: str):
        super().__init__(f"Incident {incident_id} not found", {"incident_id": incident_id})

class InvalidTransitionError(ApplicationError):
    def __init__(self, incident_id: str, old_status: str, new_status: str):
        super().__init__(
            f"Invalid transition from {old_status} to {new_status} for incident {incident_id}",
            {"incident_id": incident_id, "old_status": old_status, "new_status": new_status}
        )

class DuplicateAnalysisError(ApplicationError):
    def __init__(self, status: str):
        super().__init__(f"Analysis already in progress (status: {status})")
        self.status = status
