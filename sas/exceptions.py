class SecurityError(Exception):
    """Raised when a SAS control refuses to proceed."""


class IncidentAction:
    ALLOW = "allow"
    THROTTLE = "throttle"
    BLOCK = "block"
    ROLLBACK = "rollback"
    ALERT = "alert"
