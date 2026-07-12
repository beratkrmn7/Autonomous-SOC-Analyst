from agent.errors import BaseError

class PersistenceError(BaseError):
    pass

class RecordNotFoundError(PersistenceError):
    def __init__(self, model_name: str, id_val: str):
        super().__init__(f"{model_name} {id_val} not found", {"model_name": model_name, "id": id_val})

class InvalidEntityError(PersistenceError):
    pass
