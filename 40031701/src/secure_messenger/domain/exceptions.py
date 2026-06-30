class DomainError(Exception):
    """Base class for expected business errors."""


class ValidationError(DomainError):
    """Raised when a request violates a business rule."""


class AuthenticationError(DomainError):
    """Raised when credentials are invalid."""


class NotFoundError(DomainError):
    """Raised when a requested resource does not exist."""

