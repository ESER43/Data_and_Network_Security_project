class PatchGuardError(Exception):
    """A user-facing configuration or execution error."""


class BuildError(PatchGuardError):
    """A target did not build in one of the required modes."""

    def __init__(self, message, record=None):
        super().__init__(message)
        self.record = record
