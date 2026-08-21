class InvariantViolation(Exception):
    """The caller HAD permission; the operation would leave the system invalid.

    Maps to 409 Conflict, deliberately distinct from a 403.
    """

    def __init__(self, name: str, message: str) -> None:
        self.name = name
        super().__init__(message)
